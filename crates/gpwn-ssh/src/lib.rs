//! Live Realtek ONU backend using one persistent libssh2 PTY shell.
//!
//! [`LiveBackend`] implements `gpwn_core::OnuBackend` for ONUs in test
//! deployments the operator owns or is explicitly authorized to test.
//! The legacy device interface does not provide modern host-key negotiation;
//! callers must verify the reported fingerprint out of band. Run
//! `cargo run -p gpwn-ssh --example connect` with `GPWN_PASSWORD` set for a
//! read-only snapshot example.

use async_trait::async_trait;
use base64::Engine;
use gpwn_core::{
    AddFlowRequest, BackendKind, ConnectionInfo, DeleteFlowRequest, DirectionScope, DownstreamFlow,
    Error, FlowCounters, LineStatus, MibQuery, MibSelector, MibTableDescriptor, MibTableSnapshot,
    MutationReport, OnuBackend, OnuSnapshot, OperationStep, Result, UpstreamFlow,
    allocate_flow_ids, omci_class_id_for_table, parse_alarm_status, parse_downstream_flows,
    parse_flow_counters, parse_omci_mib_catalog, parse_omci_mib_snapshot, parse_onu_state,
    parse_upstream_flows,
};
use ssh2::{Channel, HashType, MethodType, Session};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

const DIAG_PROMPT: &str = "RTK.0>";
const SHELL_PROMPT: &str = "#";
const MORE_PROMPT: &str = "--More--";
const SHELL_OUTPUT_LIMIT: usize = 2 * 1024 * 1024;

/// Ordered Realtek diagnostic commands used by listen-all setup.
pub const LISTEN_ALL_COMMANDS: [&str; 12] = [
    "gpon set tx-laser force-off",
    "classf set downstream-unmatch-act permit",
    "classf del entry 255",
    "switch set rx-check-crc port all state disable",
    "gpon set ds-eth drop-crc-error disable",
    "vlan set ingress-filter port 0 state disable",
    "vlan set accept-frame-type port 0 all",
    "vlan set ingress-filter port 2 state disable",
    "vlan set accept-frame-type port 2 all",
    "switch set max-pkt-len index 0 length 2000",
    "switch set max-pkt-len ge port all index 0",
    "vlan set tag-mode port 0 keep-format",
];

/// Connection parameters for a live Realtek diagnostic session.
#[derive(Clone)]
pub struct ConnectionConfig {
    /// Hostname or IP address of the ONU.
    pub host: String,
    /// SSH TCP port.
    pub port: u16,
    /// SSH username.
    pub username: String,
    /// SSH password.
    pub password: String,
    /// Connection and device-command timeout.
    pub timeout: Duration,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            host: "192.168.69.1".into(),
            port: 22,
            username: "admin".into(),
            password: String::new(),
            timeout: Duration::from_secs(10),
        }
    }
}

/// Persistent live implementation of the GPWN backend contract.
pub struct LiveBackend {
    config: ConnectionConfig,
    session: Arc<Mutex<Option<DiagSession>>>,
    info: Option<ConnectionInfo>,
}

impl LiveBackend {
    /// Construct a disconnected backend with the supplied parameters.
    pub fn new(config: ConnectionConfig) -> Self {
        Self {
            config,
            session: Arc::new(Mutex::new(None)),
            info: None,
        }
    }

    async fn with_session<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut DiagSession) -> Result<T> + Send + 'static,
    {
        let session = Arc::clone(&self.session);
        tokio::task::spawn_blocking(move || {
            let mut guard = lock_session(&session)?;
            let diag = guard.as_mut().ok_or(Error::NotConnected)?;
            operation(diag)
        })
        .await
        .map_err(|error| Error::Backend(format!("blocking SSH worker stopped: {error}")))?
    }
}

#[async_trait]
impl OnuBackend for LiveBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::LiveSsh
    }

    fn connection_info(&self) -> Option<&ConnectionInfo> {
        self.info.as_ref()
    }

    async fn connect(&mut self) -> Result<ConnectionInfo> {
        if self.info.is_some() {
            return Ok(self.info.clone().expect("checked above"));
        }
        let config = self.config.clone();
        let session_slot = Arc::clone(&self.session);
        let (diag, fingerprint) =
            tokio::task::spawn_blocking(move || DiagSession::connect(&config))
                .await
                .map_err(|error| Error::Backend(format!("SSH connector stopped: {error}")))??;
        {
            let mut guard = lock_session(&session_slot)?;
            *guard = Some(diag);
        }
        let info = ConnectionInfo {
            kind: BackendKind::LiveSsh,
            endpoint: format!("{}:{}", self.config.host, self.config.port),
            username: Some(self.config.username.clone()),
            host_fingerprint: fingerprint,
            host_key_verified: false,
            connected_at: SystemTime::now(),
        };
        self.info = Some(info.clone());
        Ok(info)
    }

    async fn disconnect(&mut self) -> Result<()> {
        let slot = Arc::clone(&self.session);
        tokio::task::spawn_blocking(move || {
            let mut guard = lock_session(&slot)?;
            if let Some(mut session) = guard.take() {
                session.close();
            }
            Ok(())
        })
        .await
        .map_err(|error| Error::Backend(format!("SSH disconnector stopped: {error}")))??;
        self.info = None;
        Ok(())
    }

    async fn fetch_snapshot(&mut self) -> Result<OnuSnapshot> {
        self.with_session(|diag| {
            let state_output = diag.run_diag("gpon get onu-state")?;
            let alarm_output = diag.run_diag("gpon get alarm-status")?;
            let downstream_output = diag.run_diag("gpon show ds-flow")?;
            let upstream_output = diag.run_diag("gpon show us-flow")?;
            let (onu_state, state_description) = parse_onu_state(&state_output)?;
            let (los, lof, lom) = parse_alarm_status(&alarm_output);
            Ok(OnuSnapshot {
                line: LineStatus {
                    onu_state,
                    state_description,
                    los,
                    lof,
                    lom,
                    rx_power_dbm: None,
                    tx_power_dbm: None,
                },
                downstream: parse_downstream_flows(&downstream_output)?,
                upstream: parse_upstream_flows(&upstream_output)?,
                fetched_at: SystemTime::now(),
            })
        })
        .await
    }

    async fn read_flow_counters(&mut self, flow_id: u8) -> Result<FlowCounters> {
        if flow_id > gpwn_core::FLOW_ID_MAX {
            return Err(Error::Validation(format!(
                "flow ID {flow_id} is outside 0..={}",
                gpwn_core::FLOW_ID_MAX
            )));
        }
        self.with_session(move |diag| {
            let output = diag.run_diag(&format!("gpon show counter flow {flow_id}"))?;
            Ok(parse_flow_counters(flow_id, &output))
        })
        .await
    }

    async fn list_omci_mib_tables(&mut self) -> Result<Vec<MibTableDescriptor>> {
        self.with_session(|diag| {
            parse_omci_mib_catalog(&diag.run_shell_readonly("omcicli get tables")?)
        })
        .await
    }

    async fn fetch_omci_mib(&mut self, query: MibQuery) -> Result<MibTableSnapshot> {
        query.validate()?;
        let query = match query.selector {
            MibSelector::TableName(ref name) => {
                let class_id = omci_class_id_for_table(name).ok_or_else(|| {
                    Error::Validation(format!(
                        "OMCI class ID for table {name:?} is unknown; use direct numeric lookup"
                    ))
                })?;
                MibQuery {
                    selector: MibSelector::ClassId(class_id),
                    entity_id: query.entity_id,
                }
            }
            MibSelector::ClassId(_) => query,
        };
        let selector = query.selector.command_value();
        self.with_session(move |diag| {
            let output = diag.run_shell_readonly(&format!("omcicli mib get {selector}"))?;
            parse_omci_mib_snapshot(&output, query)
        })
        .await
    }

    async fn replace_downstream_flows(
        &mut self,
        flows: Vec<DownstreamFlow>,
    ) -> Result<MutationReport> {
        validate_exact_downstream_table(&flows)?;
        self.with_session(move |diag| replace_downstream_flows(diag, flows))
            .await
    }

    async fn add_flows(&mut self, request: AddFlowRequest) -> Result<MutationReport> {
        request.validate()?;
        self.with_session(move |diag| add_flows(diag, request))
            .await
    }

    async fn delete_flows(&mut self, request: DeleteFlowRequest) -> Result<MutationReport> {
        self.with_session(move |diag| delete_flows(diag, request))
            .await
    }

    async fn apply_listen_all_setup(&mut self) -> Result<MutationReport> {
        self.with_session(|diag| {
            let mut report = MutationReport::default();
            for command in LISTEN_ALL_COMMANDS {
                if !run_reported(diag, &mut report, "listen-all setup", command)? {
                    break;
                }
            }
            Ok(report)
        })
        .await
    }
}

fn lock_session(
    session: &Arc<Mutex<Option<DiagSession>>>,
) -> Result<MutexGuard<'_, Option<DiagSession>>> {
    session
        .lock()
        .map_err(|_| Error::Backend("SSH session lock was poisoned".into()))
}

struct DiagSession {
    session: Session,
    channel: Channel,
}

impl DiagSession {
    fn connect(config: &ConnectionConfig) -> Result<(Self, Option<String>)> {
        let address = resolve(&config.host, config.port)?;
        let tcp = TcpStream::connect_timeout(&address, config.timeout)
            .map_err(|error| Error::Connection(error.to_string()))?;
        tcp.set_read_timeout(Some(config.timeout))
            .map_err(|error| Error::Connection(error.to_string()))?;
        tcp.set_write_timeout(Some(config.timeout))
            .map_err(|error| Error::Connection(error.to_string()))?;

        let mut session = Session::new().map_err(|error| Error::Connection(error.to_string()))?;
        session.set_timeout(config.timeout.as_millis().min(u32::MAX as u128) as u32);
        session
            .method_pref(MethodType::Kex, "diffie-hellman-group1-sha1")
            .map_err(|error| Error::Connection(format!("legacy KEX unavailable: {error}")))?;
        session
            .method_pref(MethodType::HostKey, "ssh-rsa")
            .map_err(|error| Error::Connection(format!("legacy host key unavailable: {error}")))?;
        session
            .method_pref(MethodType::CryptCs, "3des-cbc")
            .map_err(|error| Error::Connection(format!("legacy cipher unavailable: {error}")))?;
        session
            .method_pref(MethodType::CryptSc, "3des-cbc")
            .map_err(|error| Error::Connection(format!("legacy cipher unavailable: {error}")))?;
        session.set_tcp_stream(tcp);
        session
            .handshake()
            .map_err(|error| Error::Connection(format!("SSH handshake: {error}")))?;
        let fingerprint = session.host_key_hash(HashType::Sha256).map(|bytes| {
            format!(
                "SHA256:{}",
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
            )
        });
        session
            .userauth_password(&config.username, &config.password)
            .map_err(|error| Error::Connection(format!("password authentication: {error}")))?;
        if !session.authenticated() {
            return Err(Error::Connection("authentication was rejected".into()));
        }
        let mut channel = session
            .channel_session()
            .map_err(|error| Error::Connection(format!("open shell channel: {error}")))?;
        channel
            .request_pty("vt100", None, Some((200, 1000, 0, 0)))
            .map_err(|error| Error::Connection(format!("request PTY: {error}")))?;
        channel
            .shell()
            .map_err(|error| Error::Connection(format!("start remote shell: {error}")))?;
        read_until(&mut channel, SHELL_PROMPT, None)?;
        send_line(&mut channel, "diag")?;
        read_until(&mut channel, DIAG_PROMPT, Some(MORE_PROMPT))?;
        Ok((Self { session, channel }, fingerprint))
    }

    fn run_diag(&mut self, command: &str) -> Result<String> {
        send_line(&mut self.channel, command)?;
        let output = read_until(&mut self.channel, DIAG_PROMPT, Some(MORE_PROMPT))?;
        Ok(clean_output(&output, command))
    }

    fn run_shell_readonly(&mut self, command: &str) -> Result<String> {
        // This firmware supports only one active shell context. Reuse the
        // persistent PTY instead of opening a second channel alongside diag.
        send_line(&mut self.channel, "exit")?;
        read_until_limited(&mut self.channel, SHELL_PROMPT, SHELL_OUTPUT_LIMIT)?;

        let command_result = send_line(&mut self.channel, command)
            .and_then(|()| read_until_limited(&mut self.channel, SHELL_PROMPT, SHELL_OUTPUT_LIMIT));

        // Always try to return the persistent channel to diag so a failed MIB
        // read does not break subsequent monitoring and mutation commands.
        let restore_result = send_line(&mut self.channel, "diag").and_then(|()| {
            read_until(&mut self.channel, DIAG_PROMPT, Some(MORE_PROMPT)).map(|_| ())
        });

        match (command_result, restore_result) {
            (Ok(output), Ok(())) => Ok(clean_output(&output, command)),
            (Err(command_error), Ok(())) => Err(command_error),
            (Ok(_), Err(restore_error)) => Err(restore_error),
            (Err(command_error), Err(restore_error)) => Err(Error::Backend(format!(
                "{command_error}; additionally failed to restore the diag shell: {restore_error}"
            ))),
        }
    }

    fn close(&mut self) {
        let _ = send_line(&mut self.channel, "exit");
        let _ = read_until(&mut self.channel, SHELL_PROMPT, None);
        let _ = send_line(&mut self.channel, "exit");
        let _ = self.channel.send_eof();
        let _ = self.channel.close();
        let _ = self.channel.wait_close();
        let _ = self
            .session
            .disconnect(None, "gpwn-toolkit disconnect", None);
    }
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()
        .map_err(|error| Error::Connection(format!("resolve {host}: {error}")))?
        .next()
        .ok_or_else(|| Error::Connection(format!("no address found for {host}")))
}

fn send_line(channel: &mut Channel, line: &str) -> Result<()> {
    channel
        .write_all(format!("{line}\n").as_bytes())
        .map_err(|error| Error::Connection(format!("write to SSH shell: {error}")))?;
    channel
        .flush()
        .map_err(|error| Error::Connection(format!("flush SSH shell: {error}")))
}

fn read_until(channel: &mut Channel, prompt: &str, pager: Option<&str>) -> Result<String> {
    let mut collected = String::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = channel.read(&mut buffer).map_err(|error| {
            if error.kind() == std::io::ErrorKind::TimedOut {
                Error::Timeout(format!("waiting for {prompt:?}"))
            } else {
                Error::Connection(format!("read SSH shell: {error}"))
            }
        })?;
        if read == 0 {
            return Err(Error::Connection(format!(
                "SSH shell closed while waiting for {prompt:?}"
            )));
        }
        collected.push_str(&String::from_utf8_lossy(&buffer[..read]));
        if let Some(pager) = pager
            && collected.contains(pager)
            && !collected.contains(prompt)
        {
            send_line(channel, "")?;
            collected = collected.replace(pager, "");
        }
        if collected.contains(prompt) {
            return Ok(collected);
        }
    }
}

fn read_until_limited(channel: &mut Channel, prompt: &str, limit: usize) -> Result<String> {
    let mut collected = String::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = channel.read(&mut buffer).map_err(|error| {
            if error.kind() == std::io::ErrorKind::TimedOut {
                Error::Timeout(format!("waiting for {prompt:?}"))
            } else {
                Error::Connection(format!("read SSH shell: {error}"))
            }
        })?;
        if read == 0 {
            return Err(Error::Connection(format!(
                "SSH shell closed while waiting for {prompt:?}"
            )));
        }
        if collected.len() + read > limit {
            return Err(Error::Backend(format!(
                "remote command output exceeded {} MiB",
                limit / 1024 / 1024
            )));
        }
        collected.push_str(&String::from_utf8_lossy(&buffer[..read]));
        if collected.contains(prompt) {
            return Ok(collected);
        }
    }
}

fn clean_output(output: &str, command: &str) -> String {
    let normalized = output.replace('\r', "").replace(MORE_PROMPT, "");
    normalized
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed != command
                && trimmed != DIAG_PROMPT
                && trimmed != SHELL_PROMPT
                && !trimmed.ends_with(command)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn output_failure(output: &str) -> Option<String> {
    let lower = output.to_ascii_lowercase();
    ["error", "failed", "invalid", "unknown command", "not found"]
        .into_iter()
        .find(|marker| lower.contains(marker))
        .map(|_| output.trim().to_owned())
}

fn run_reported(
    diag: &mut DiagSession,
    report: &mut MutationReport,
    description: &str,
    command: &str,
) -> Result<bool> {
    let output = diag.run_diag(command)?;
    let failure = output_failure(&output);
    report.steps.push(OperationStep {
        description: description.into(),
        command: Some(command.into()),
        success: failure.is_none(),
        message: failure.clone().unwrap_or_else(|| "completed".into()),
    });
    Ok(failure.is_none())
}

fn current_flows(diag: &mut DiagSession) -> Result<(Vec<DownstreamFlow>, Vec<UpstreamFlow>)> {
    let downstream = parse_downstream_flows(&diag.run_diag("gpon show ds-flow")?)?;
    let upstream = parse_upstream_flows(&diag.run_diag("gpon show us-flow")?)?;
    Ok((downstream, upstream))
}

fn validate_exact_downstream_table(flows: &[DownstreamFlow]) -> Result<()> {
    let mut ids = std::collections::BTreeSet::new();
    for flow in flows {
        if flow.flow_id > gpwn_core::FLOW_ID_MAX || flow.gem_port > gpwn_core::GEM_PORT_MAX {
            return Err(Error::Validation(format!(
                "invalid downstream flow {} / GEM {}",
                flow.flow_id, flow.gem_port
            )));
        }
        if !ids.insert(flow.flow_id) {
            return Err(Error::Validation(format!(
                "duplicate downstream flow ID {}",
                flow.flow_id
            )));
        }
    }
    Ok(())
}

fn replace_downstream_flows(
    diag: &mut DiagSession,
    mut flows: Vec<DownstreamFlow>,
) -> Result<MutationReport> {
    let (current, _) = current_flows(diag)?;
    let mut report = MutationReport::default();
    for flow in current {
        let command = format!("gpon del ds-flow flow-id {}", flow.flow_id);
        if !run_reported(diag, &mut report, "delete downstream flow", &command)? {
            return Ok(report);
        }
    }
    flows.sort_by_key(|flow| flow.flow_id);
    for flow in flows {
        let mut command = format!(
            "gpon add ds-flow flow-id {} gem-port {} {}",
            flow.flow_id,
            flow.gem_port,
            flow.flow_type.command_name()
        );
        if flow.multicast {
            command.push_str(" multicast");
        }
        if flow.aes {
            command.push_str(" aes");
        }
        if !run_reported(diag, &mut report, "add downstream flow", &command)? {
            return Ok(report);
        }
    }
    Ok(report)
}

fn add_flows(diag: &mut DiagSession, request: AddFlowRequest) -> Result<MutationReport> {
    let (downstream, upstream) = current_flows(diag)?;
    let ids = allocate_flow_ids(
        request.scope,
        request.flow_ids,
        request.gem_ports.len(),
        &downstream,
        &upstream,
    )?;
    let mut report = MutationReport::default();
    for (flow_id, gem_port) in ids.into_iter().zip(request.gem_ports) {
        if matches!(
            request.scope,
            DirectionScope::Downstream | DirectionScope::Both
        ) {
            let mut command = format!(
                "gpon add ds-flow flow-id {flow_id} gem-port {gem_port} {}",
                request.flow_type.command_name()
            );
            if request.multicast {
                command.push_str(" multicast");
            }
            if request.aes {
                command.push_str(" aes");
            }
            if !run_reported(diag, &mut report, "add downstream flow", &command)? {
                break;
            }
        }
        if matches!(
            request.scope,
            DirectionScope::Upstream | DirectionScope::Both
        ) {
            let command = format!(
                "gpon add us-flow flow-id {flow_id} gem-port {gem_port} {}",
                request.flow_type.command_name()
            );
            if !run_reported(diag, &mut report, "add upstream flow", &command)? {
                break;
            }
        }
    }
    Ok(report)
}

fn delete_flows(diag: &mut DiagSession, request: DeleteFlowRequest) -> Result<MutationReport> {
    let (downstream, upstream) = current_flows(diag)?;
    let requested: Option<BTreeSetU8> = request
        .flow_ids
        .map(|ids| ids.into_iter().collect::<BTreeSetU8>());
    let contains = |id: u8| requested.as_ref().is_none_or(|ids| ids.contains(&id));
    let mut report = MutationReport::default();
    if matches!(
        request.scope,
        DirectionScope::Downstream | DirectionScope::Both
    ) {
        for flow in downstream.into_iter().filter(|flow| contains(flow.flow_id)) {
            let command = format!("gpon del ds-flow flow-id {}", flow.flow_id);
            if !run_reported(diag, &mut report, "delete downstream flow", &command)? {
                return Ok(report);
            }
        }
    }
    if matches!(
        request.scope,
        DirectionScope::Upstream | DirectionScope::Both
    ) {
        for flow in upstream.into_iter().filter(|flow| contains(flow.flow_id)) {
            let command = format!("gpon del us-flow flow-id {}", flow.flow_id);
            if !run_reported(diag, &mut report, "delete upstream flow", &command)? {
                return Ok(report);
            }
        }
    }
    if report.steps.is_empty() {
        report.steps.push(OperationStep {
            description: "delete flows".into(),
            command: None,
            success: true,
            message: "no matching flows".into(),
        });
    }
    Ok(report)
}

type BTreeSetU8 = std::collections::BTreeSet<u8>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_sequence_matches_python_tool() {
        assert_eq!(LISTEN_ALL_COMMANDS.len(), 12);
        assert_eq!(LISTEN_ALL_COMMANDS[0], "gpon set tx-laser force-off");
        assert_eq!(
            LISTEN_ALL_COMMANDS[11],
            "vlan set tag-mode port 0 keep-format"
        );
    }

    #[test]
    fn cleans_echo_prompt_and_crlf() {
        let output = "gpon get onu-state\r\nONU state: Operation State(O5)\r\nRTK.0>";
        assert_eq!(
            clean_output(output, "gpon get onu-state"),
            "ONU state: Operation State(O5)"
        );
    }

    #[test]
    fn cleans_busybox_shell_prompt() {
        let output = "omcicli mib get 84\r\nVlanTagFilterData\r\n# ";
        assert_eq!(
            clean_output(output, "omcicli mib get 84"),
            "VlanTagFilterData"
        );
    }

    #[test]
    fn identifies_command_failures() {
        assert!(output_failure("").is_none());
        assert!(output_failure("invalid input").is_some());
    }
}
