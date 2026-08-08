//! Transport-independent GPON ONU management contracts and Realtek parsers.
//!
//! Applications depend on [`OnuBackend`] rather than a concrete transport.
//! Parsing helpers accept captured command output and perform no I/O. Run
//! `cargo run -p gpwn-core --example parse_realtek` for a complete example.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// Lowest flow-table identifier supported by the Realtek interface.
pub const FLOW_ID_MIN: u8 = 0;
/// Highest flow-table identifier supported by the Realtek interface.
pub const FLOW_ID_MAX: u8 = 127;
/// Lowest valid GPON Encapsulation Method port identifier.
pub const GEM_PORT_MIN: u16 = 0;
/// Highest valid GPON Encapsulation Method port identifier.
pub const GEM_PORT_MAX: u16 = 4095;

/// Error shared by GPWN backends and transport-independent workflows.
#[derive(Debug, Error, Clone)]
pub enum Error {
    /// An operation requires an active backend connection.
    #[error("not connected")]
    NotConnected,
    /// Establishing or maintaining the connection failed.
    #[error("connection failed: {0}")]
    Connection(String),
    /// An operation exceeded its allotted time.
    #[error("operation timed out: {0}")]
    Timeout(String),
    /// Caller-supplied data violated an API constraint.
    #[error("invalid input: {0}")]
    Validation(String),
    /// Device output could not be parsed in the expected context.
    #[error("could not parse {context}: {details}")]
    Parse {
        /// Short name of the output or record being parsed.
        context: &'static str,
        /// Human-readable description of the malformed input.
        details: String,
    },
    /// A command reached the device but returned an unsuccessful result.
    #[error("device command failed: {command}: {message}")]
    Command {
        /// Command sent to the device.
        command: String,
        /// Error text reported by the device or transport.
        message: String,
    },
    /// Backend-specific failure that has no more precise shared category.
    #[error("backend error: {0}")]
    Backend(String),
}

/// Result type returned by GPWN core and backend operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Transport that produced an ONU connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendKind {
    /// A live ONU reached through SSH.
    LiveSsh,
    /// An in-process deterministic mock backend.
    Mock,
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LiveSsh => "LIVE",
            Self::Mock => "MOCK",
        })
    }
}

/// Metadata for the currently connected backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// Transport implementation serving the connection.
    pub kind: BackendKind,
    /// Backend-specific endpoint, such as a host and port.
    pub endpoint: String,
    /// Authenticated username, when applicable.
    pub username: Option<String>,
    /// Presented SSH host-key fingerprint, when applicable.
    pub host_fingerprint: Option<String>,
    /// Whether the backend verified the presented host key.
    pub host_key_verified: bool,
    /// Time at which the connection was established.
    pub connected_at: SystemTime,
}

/// GPON activation state reported by the ONU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OnuState {
    /// Initial state: the ONU is powered on but has not begun activation.
    O1,
    /// Standby state while downstream synchronization is acquired.
    O2,
    /// Serial-number exchange state.
    O3,
    /// Ranging state.
    O4,
    /// Operational state.
    O5,
    /// POPUP state used while recovering synchronization.
    O6,
    /// Emergency-stop state.
    O7,
    /// State text was absent or not recognized.
    Unknown,
}

impl fmt::Display for OnuState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::O1 => "O1",
            Self::O2 => "O2",
            Self::O3 => "O3",
            Self::O4 => "O4",
            Self::O5 => "O5",
            Self::O6 => "O6",
            Self::O7 => "O7",
            Self::Unknown => "?",
        })
    }
}

/// State of an optical alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlarmCondition {
    /// Alarm is not asserted.
    Clear,
    /// Alarm is asserted.
    Active,
    /// Device output did not reveal the alarm state.
    Unknown,
}

impl fmt::Display for AlarmCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Clear => "clear",
            Self::Active => "ACTIVE",
            Self::Unknown => "?",
        })
    }
}

/// Optical state and alarms collected during a snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LineStatus {
    /// Current GPON activation state.
    pub onu_state: OnuState,
    /// Device-provided text accompanying the activation state.
    pub state_description: String,
    /// Loss-of-signal alarm.
    pub los: AlarmCondition,
    /// Loss-of-frame alarm.
    pub lof: AlarmCondition,
    /// Loss-of-message alarm.
    pub lom: AlarmCondition,
    /// Received optical power in dBm, when reported.
    pub rx_power_dbm: Option<f32>,
    /// Transmitted optical power in dBm, when reported.
    pub tx_power_dbm: Option<f32>,
}

/// Payload carried by a configured flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowType {
    /// Subscriber Ethernet payload.
    Ethernet,
    /// ONU Management and Control Interface payload.
    Omci,
}

impl FlowType {
    /// Return the token accepted by the Realtek diagnostic command.
    pub fn command_name(self) -> &'static str {
        match self {
            Self::Ethernet => "ether",
            Self::Omci => "omci",
        }
    }
}

impl fmt::Display for FlowType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ethernet => "ETH",
            Self::Omci => "OMCI",
        })
    }
}

/// One configured downstream GEM-to-flow mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownstreamFlow {
    /// Realtek downstream flow-table index.
    pub flow_id: u8,
    /// GEM port mapped to this flow.
    pub gem_port: u16,
    /// Payload carried by the mapping.
    pub flow_type: FlowType,
    /// Whether the flow accepts multicast traffic.
    pub multicast: bool,
    /// Whether downstream AES decryption is enabled.
    pub aes: bool,
}

/// One configured upstream GEM-to-flow mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamFlow {
    /// Realtek upstream flow-table index.
    pub flow_id: u8,
    /// GEM port mapped to this flow.
    pub gem_port: u16,
    /// Payload carried by the mapping.
    pub flow_type: FlowType,
    /// Alloc-ID/T-CONT assigned to the flow, when reported.
    pub tcont: Option<u16>,
    /// Upstream channel assigned to the flow, when reported.
    pub channel: Option<u16>,
    /// Whether the mapping is designated for OMCI traffic.
    pub omci: bool,
}

/// Interval counters returned by `gpon show counter flow`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowCounters {
    /// Flow-table index associated with the counters.
    pub flow_id: u8,
    /// Downstream GEM frames received.
    pub ds_gem_packets: u64,
    /// Downstream GEM payload bytes received.
    pub ds_gem_bytes: u64,
    /// Downstream Ethernet frames reconstructed from GEM traffic.
    pub ds_rx_eth_packets: u64,
    /// Downstream Ethernet frames forwarded by the flow.
    pub ds_fwd_eth_packets: u64,
    /// Upstream GEM frames transmitted.
    pub us_gem_packets: u64,
    /// Upstream GEM payload bytes transmitted.
    pub us_gem_bytes: u64,
    /// Upstream Ethernet frames accepted by the flow.
    pub us_eth_packets: u64,
}

/// A Realtek OMCI table registration entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MibTableDescriptor {
    /// Realtek's runtime table index, not the OMCI class ID.
    pub internal_id: u16,
    /// Runtime table label accepted by supported `omcicli` builds.
    pub name: String,
}

/// Resolve Realtek's table labels to standardized OMCI managed-entity class IDs.
///
/// `omcicli get tables` exposes only a runtime registration index and a label.
/// That index is not the class ID, while `omcicli mib get` requires the class
/// ID. Vendor-specific labels are deliberately left unresolved rather than
/// risking a query for the wrong managed entity.
pub fn omci_class_id_for_table(name: &str) -> Option<u16> {
    Some(match name.to_ascii_lowercase().as_str() {
        "anig" => 263,
        "cardholder" => 5,
        "circuitpack" => 6,
        "ethpmdata2" => 89,
        "ethpmdata3" => 90,
        "ethuni" => 11,
        "extvlantagopercfgdata" => 171,
        "fecpmhd" => 312,
        "galethprof" => 272,
        "gemiwtp" => 266,
        "gemportctp" => 268,
        "trafficdescriptor" => 280,
        "generalpurposebuffer" => 308,
        "iphostcfgdata" => 134,
        "largestring" => 157,
        "macbriservprof" => 45,
        "macbriportcfgdata" => 47,
        "macbriportbritbldata" => 48,
        "macbridgeportfiltertable" => 49,
        "macbridgeportpmmonitorhistorydata" => 52,
        "map8021pservprof" => 130,
        "mcastoperprof" => 309,
        "mcastsubconfinfo" => 310,
        "mcastsubmonitor" => 311,
        "multigemiwtp" => 281,
        "oltg" => 131,
        "ontdata" => 2,
        "ontg" => 256,
        "ont2g" => 257,
        "priq" => 277,
        "swimage" => 7,
        "scheduler" => 278,
        "tcont" => 262,
        "thresholddata1" => 273,
        "thresholddata2" => 274,
        "unig" => 264,
        "veip" => 329,
        "vlantagfilterdata" => 84,
        "vlantagopcfgdata" => 78,
        _ => return None,
    })
}

/// OMCI managed-entity selector accepted by a MIB query.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MibSelector {
    /// Select a table by its Realtek runtime label.
    TableName(String),
    /// Select a table by its standardized OMCI class ID.
    ClassId(u16),
}

impl MibSelector {
    /// Validates that a table-name selector is safe for the device command.
    pub fn validate(&self) -> Result<()> {
        if let Self::TableName(name) = self
            && (name.is_empty()
                || !name
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_'))
        {
            return Err(Error::Validation(
                "MIB table names may contain only ASCII letters, digits, and underscores".into(),
            ));
        }
        Ok(())
    }

    /// Formats the selector as the value accepted by `omcicli mib get`.
    pub fn command_value(&self) -> String {
        match self {
            Self::TableName(name) => name.clone(),
            Self::ClassId(class_id) => class_id.to_string(),
        }
    }
}

/// Request for an OMCI managed-entity table and optional entity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MibQuery {
    /// Table or managed-entity class to request.
    pub selector: MibSelector,
    /// Filtering is performed locally because entity-specific `omcicli` syntax
    /// is unreliable across Realtek firmware builds.
    pub entity_id: Option<u16>,
}

impl MibQuery {
    /// Validates the query's selector.
    pub fn validate(&self) -> Result<()> {
        self.selector.validate()
    }
}

/// One parsed OMCI attribute name and value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MibAttribute {
    /// Attribute label emitted by `omcicli`.
    pub name: String,
    /// Parsed value, including continuation lines where present.
    pub value: String,
}

/// One managed-entity instance returned by an OMCI query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MibEntity {
    /// OMCI managed-entity instance identifier.
    pub entity_id: u16,
    /// Parsed attributes in device-output order.
    pub attributes: Vec<MibAttribute>,
    /// Original lines belonging to this entity block.
    pub raw_lines: Vec<String>,
}

/// Parsed result of a read-only OMCI MIB query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MibTableSnapshot {
    /// Query that produced this snapshot.
    pub query: MibQuery,
    /// Table name reported in the device response.
    pub table_name: String,
    /// Parsed managed-entity instances.
    pub entities: Vec<MibEntity>,
    /// Unmodified command output with outer whitespace removed.
    pub raw_output: String,
    /// Local time at which the output was parsed.
    pub fetched_at: SystemTime,
}

impl FlowCounters {
    /// Returns `true` when any packet or byte counter is nonzero.
    pub fn is_active(&self) -> bool {
        self.ds_gem_packets != 0
            || self.ds_gem_bytes != 0
            || self.ds_rx_eth_packets != 0
            || self.ds_fwd_eth_packets != 0
            || self.us_gem_packets != 0
            || self.us_gem_bytes != 0
            || self.us_eth_packets != 0
    }
}

/// Timestamped flow counters and the interval since the preceding sample.
#[derive(Debug, Clone)]
pub struct CounterSample {
    /// Counters captured in this sample.
    pub counters: FlowCounters,
    /// Local time at which the sample was collected.
    pub sampled_at: SystemTime,
    /// Time since this flow ID was last read by this process.
    pub interval: Option<Duration>,
}

/// Consistent view of ONU line state and both flow tables.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnuSnapshot {
    /// Current optical state and alarms.
    pub line: LineStatus,
    /// Complete downstream flow table.
    pub downstream: Vec<DownstreamFlow>,
    /// Complete upstream flow table.
    pub upstream: Vec<UpstreamFlow>,
    /// Local time at which the snapshot was completed.
    pub fetched_at: SystemTime,
}

/// Direction or directions affected by a mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectionScope {
    /// Affect only the downstream flow table.
    Downstream,
    /// Affect only the upstream flow table.
    Upstream,
    /// Affect both flow tables.
    Both,
}

impl fmt::Display for DirectionScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Downstream => "downstream",
            Self::Upstream => "upstream",
            Self::Both => "both",
        })
    }
}

/// How flow identifiers should be selected for an add request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowIdChoice {
    /// Allocate unused identifiers automatically.
    Auto,
    /// Use one caller-selected identifier.
    Exact(u8),
}

/// Validated request to create one or more flow mappings.
#[derive(Debug, Clone)]
pub struct AddFlowRequest {
    /// Flow table or tables to modify.
    pub scope: DirectionScope,
    /// Automatic or exact flow-ID selection.
    pub flow_ids: FlowIdChoice,
    /// GEM ports for which mappings should be created.
    pub gem_ports: Vec<u16>,
    /// Payload type assigned to each mapping.
    pub flow_type: FlowType,
    /// Downstream multicast flag.
    pub multicast: bool,
    /// Downstream AES-decryption flag.
    pub aes: bool,
}

impl AddFlowRequest {
    /// Checks GEM-port bounds and cross-field request constraints.
    pub fn validate(&self) -> Result<()> {
        if self.gem_ports.is_empty() {
            return Err(Error::Validation(
                "at least one GEM port is required".into(),
            ));
        }
        if self.gem_ports.iter().any(|port| *port > GEM_PORT_MAX) {
            return Err(Error::Validation(format!(
                "GEM ports must be in {GEM_PORT_MIN}..={GEM_PORT_MAX}"
            )));
        }
        if matches!(self.flow_ids, FlowIdChoice::Exact(_)) && self.gem_ports.len() != 1 {
            return Err(Error::Validation(
                "an exact flow ID can only be used with one GEM port".into(),
            ));
        }
        if self.scope == DirectionScope::Upstream && (self.multicast || self.aes) {
            return Err(Error::Validation(
                "AES and multicast flags only apply to downstream flows".into(),
            ));
        }
        Ok(())
    }
}

/// Request to remove flow identifiers from one or both directions.
#[derive(Debug, Clone)]
pub struct DeleteFlowRequest {
    /// Flow table or tables from which mappings should be removed.
    pub scope: DirectionScope,
    /// `None` means every flow in the requested scope.
    pub flow_ids: Option<Vec<u8>>,
}

/// Outcome of one command in a multi-command mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationStep {
    /// Human-readable description of the attempted action.
    pub description: String,
    /// Exact device command, if the step invoked one.
    pub command: Option<String>,
    /// Whether this step completed successfully.
    pub success: bool,
    /// Device response or explanatory result text.
    pub message: String,
}

/// Ordered, non-transactional device mutation report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MutationReport {
    /// Commands and local operations in execution order.
    pub steps: Vec<OperationStep>,
}

impl MutationReport {
    /// Returns `true` when every recorded step succeeded.
    pub fn succeeded(&self) -> bool {
        self.steps.iter().all(|step| step.success)
    }
}

/// Transport-independent contract used by GPWN applications and workflows.
///
/// Mutation methods return every attempted command through [`MutationReport`]
/// so callers can surface partial completion rather than assuming atomicity.
#[async_trait]
pub trait OnuBackend: Send {
    /// Identifies the transport implementation.
    fn kind(&self) -> BackendKind;
    /// Returns metadata for the active connection, if connected.
    fn connection_info(&self) -> Option<&ConnectionInfo>;
    /// Establishes a backend connection and returns its metadata.
    async fn connect(&mut self) -> Result<ConnectionInfo>;
    /// Closes the active connection.
    async fn disconnect(&mut self) -> Result<()>;
    /// Reads a consistent line-status and flow-table snapshot.
    async fn fetch_snapshot(&mut self) -> Result<OnuSnapshot>;
    /// Reads current counters for one flow-table identifier.
    async fn read_flow_counters(&mut self, flow_id: u8) -> Result<FlowCounters>;
    /// Lists OMCI tables registered by the device runtime.
    async fn list_omci_mib_tables(&mut self) -> Result<Vec<MibTableDescriptor>>;
    /// Fetches and parses one read-only OMCI managed-entity table.
    async fn fetch_omci_mib(&mut self, query: MibQuery) -> Result<MibTableSnapshot>;
    /// Replace the complete downstream table with the supplied exact configuration.
    ///
    /// Implementations may execute multiple device commands. A failed report therefore
    /// means callers must refresh before assuming which table is installed.
    async fn replace_downstream_flows(
        &mut self,
        flows: Vec<DownstreamFlow>,
    ) -> Result<MutationReport>;
    /// Adds the requested flow mappings without replacing unrelated entries.
    async fn add_flows(&mut self, request: AddFlowRequest) -> Result<MutationReport>;
    /// Removes selected or all flow mappings in the requested scope.
    async fn delete_flows(&mut self, request: DeleteFlowRequest) -> Result<MutationReport>;
    /// Applies the backend's standard downstream listen-all configuration.
    async fn apply_listen_all_setup(&mut self) -> Result<MutationReport>;
}

/// Parses the table registry printed by `omcicli get tables`.
///
/// Invalid rows are ignored. The result is sorted and deduplicated by Realtek
/// runtime table ID; an error is returned when no valid rows are present.
pub fn parse_omci_mib_catalog(output: &str) -> Result<Vec<MibTableDescriptor>> {
    let mut tables = Vec::new();
    for line in output.lines().map(str::trim) {
        let Some(rest) = line.strip_prefix("TableId [") else {
            continue;
        };
        let Some((id, rest)) = rest.split_once("] Name:") else {
            continue;
        };
        let Ok(internal_id) = id.trim().parse::<u16>() else {
            continue;
        };
        let name = rest.trim().trim_end_matches('!').trim();
        if name.is_empty()
            || !name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            continue;
        }
        tables.push(MibTableDescriptor {
            internal_id,
            name: name.into(),
        });
    }
    if tables.is_empty() {
        return Err(Error::Parse {
            context: "OMCI MIB table catalog",
            details: "no `TableId [...] Name: ...` rows were found".into(),
        });
    }
    tables.sort_by_key(|table| table.internal_id);
    tables.dedup_by_key(|table| table.internal_id);
    Ok(tables)
}

/// Parses a table response from `omcicli mib get` for `query`.
///
/// Entity filtering is performed locally after parsing. A catalog response is
/// rejected explicitly because it commonly indicates that the MIB has not yet
/// synchronized or that the firmware does not support the requested selector.
pub fn parse_omci_mib_snapshot(output: &str, query: MibQuery) -> Result<MibTableSnapshot> {
    query.validate()?;
    if parse_omci_mib_catalog(output).is_ok() {
        return Err(Error::Validation(format!(
            "the device returned its table catalog instead of MIB data for {:?}; the OMCI MIB may not be synchronized yet or this firmware may not support that selector",
            query.selector
        )));
    }
    let lines: Vec<_> = output
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .collect();
    let separator = |line: &str, character: char| {
        let trimmed = line.trim();
        trimmed.len() >= 8 && trimmed.chars().all(|item| item == character)
    };
    let table_name = lines
        .windows(3)
        .find(|window| separator(window[0], 'X') && separator(window[2], 'X'))
        .map(|window| window[1].trim().to_owned())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| Error::Parse {
            context: "OMCI MIB table",
            details: "missing table-name header".into(),
        })?;

    let mut entities = Vec::new();
    let mut current: Option<MibEntity> = None;
    for line in &lines {
        let trimmed = line.trim();
        if separator(trimmed, 'X') || separator(trimmed, '=') || trimmed == table_name {
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("EntityID:") {
            if let Some(entity) = current.take() {
                entities.push(entity);
            }
            let entity_id = parse_mib_u16(value.trim()).ok_or_else(|| Error::Parse {
                context: "OMCI MIB entity",
                details: format!("invalid entity ID {value:?}"),
            })?;
            current = Some(MibEntity {
                entity_id,
                attributes: Vec::new(),
                raw_lines: vec![line.to_string()],
            });
            continue;
        }
        let Some(entity) = current.as_mut() else {
            continue;
        };
        entity.raw_lines.push(line.to_string());
        if let Some((name, value)) = trimmed.split_once(':') {
            if !name.trim().is_empty() {
                entity.attributes.push(MibAttribute {
                    name: name.trim().into(),
                    value: value.trim().into(),
                });
            }
        } else if !trimmed.is_empty()
            && let Some(attribute) = entity.attributes.last_mut()
        {
            if !attribute.value.is_empty() {
                attribute.value.push('\n');
            }
            attribute.value.push_str(trimmed);
        }
    }
    if let Some(entity) = current {
        entities.push(entity);
    }
    if let Some(requested) = query.entity_id {
        entities.retain(|entity| entity.entity_id == requested);
        if entities.is_empty() {
            return Err(Error::Validation(format!(
                "entity 0x{requested:04x} was not found in {table_name}"
            )));
        }
    }
    Ok(MibTableSnapshot {
        query,
        table_name,
        entities,
        raw_output: output.trim().into(),
        fetched_at: SystemTime::now(),
    })
}

fn parse_mib_u16(value: &str) -> Option<u16> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u16::from_str_radix(hex, 16).ok()
    } else {
        value.parse().ok()
    }
}

/// Parses a comma-separated selection expression into bounded `u8` values.
///
/// The expression accepts individual decimal numbers and inclusive ranges such
/// as `"1,4-6"`. Results are sorted and deduplicated.
pub fn parse_selection_expression_u8(expr: &str, min: u8, max: u8) -> Result<Vec<u8>> {
    parse_selection_expression(expr, min as u16, max as u16)
        .map(|values| values.into_iter().map(|value| value as u8).collect())
}

/// Parses a comma-separated selection expression into bounded `u16` values.
///
/// The expression accepts individual decimal numbers and inclusive ranges such
/// as `"1,4-6"`. Values outside `min..=max`, reversed ranges, and empty
/// segments return [`Error::Validation`]. Results are sorted and deduplicated.
pub fn parse_selection_expression(expr: &str, min: u16, max: u16) -> Result<Vec<u16>> {
    let text = expr.trim();
    if text.is_empty() {
        return Err(Error::Validation("selection expression is empty".into()));
    }
    let mut values = BTreeSet::new();
    for raw in text.split(',') {
        let part = raw.trim();
        if part.is_empty() {
            return Err(Error::Validation(format!(
                "invalid empty segment in {expr:?}"
            )));
        }
        let pieces: Vec<_> = part.split('-').map(str::trim).collect();
        match pieces.as_slice() {
            [value] => {
                let value = parse_bounded(value, min, max)?;
                values.insert(value);
            }
            [start, end] if !start.is_empty() && !end.is_empty() => {
                let start = parse_bounded(start, min, max)?;
                let end = parse_bounded(end, min, max)?;
                if start > end {
                    return Err(Error::Validation(format!(
                        "range start exceeds end: {part:?}"
                    )));
                }
                values.extend(start..=end);
            }
            _ => {
                return Err(Error::Validation(format!(
                    "invalid range segment: {part:?}"
                )));
            }
        }
    }
    Ok(values.into_iter().collect())
}

fn parse_bounded(value: &str, min: u16, max: u16) -> Result<u16> {
    let value: u16 = value
        .parse()
        .map_err(|_| Error::Validation(format!("invalid numeric segment: {value:?}")))?;
    if !(min..=max).contains(&value) {
        return Err(Error::Validation(format!(
            "value {value} is out of range [{min}, {max}]"
        )));
    }
    Ok(value)
}

/// Selects flow-table identifiers for an add operation.
///
/// Exact selection is valid only for one mapping and only when the identifier
/// is unused in every table covered by `scope`. Automatic selection returns the
/// lowest available identifiers, or an error when capacity is insufficient.
pub fn allocate_flow_ids(
    scope: DirectionScope,
    choice: FlowIdChoice,
    count: usize,
    downstream: &[DownstreamFlow],
    upstream: &[UpstreamFlow],
) -> Result<Vec<u8>> {
    let ds_used: BTreeSet<_> = downstream.iter().map(|flow| flow.flow_id).collect();
    let us_used: BTreeSet<_> = upstream.iter().map(|flow| flow.flow_id).collect();
    let is_free = |id: u8| match scope {
        DirectionScope::Downstream => !ds_used.contains(&id),
        DirectionScope::Upstream => !us_used.contains(&id),
        DirectionScope::Both => !ds_used.contains(&id) && !us_used.contains(&id),
    };
    match choice {
        FlowIdChoice::Exact(id) => {
            if is_free(id) {
                Ok(vec![id])
            } else {
                Err(Error::Validation(format!(
                    "flow ID {id} is already used in {scope}"
                )))
            }
        }
        FlowIdChoice::Auto => {
            let ids: Vec<_> = (FLOW_ID_MIN..=FLOW_ID_MAX)
                .filter(|id| is_free(*id))
                .take(count)
                .collect();
            if ids.len() == count {
                Ok(ids)
            } else {
                Err(Error::Validation(format!(
                    "not enough free {scope} flow IDs: need {count}, found {}",
                    ids.len()
                )))
            }
        }
    }
}

/// Parses the GPON activation state and accompanying description.
///
/// Returns an error when the output contains no recognizable state field.
pub fn parse_onu_state(output: &str) -> Result<(OnuState, String)> {
    let line = output
        .lines()
        .find(|line| line.to_ascii_lowercase().contains("onu state"))
        .ok_or_else(|| Error::Parse {
            context: "ONU state",
            details: "missing `ONU state` line".into(),
        })?;
    let lower = line.to_ascii_lowercase();
    let state = (1..=7)
        .find_map(|number| {
            lower
                .contains(&format!("o{number}"))
                .then_some(match number {
                    1 => OnuState::O1,
                    2 => OnuState::O2,
                    3 => OnuState::O3,
                    4 => OnuState::O4,
                    5 => OnuState::O5,
                    6 => OnuState::O6,
                    7 => OnuState::O7,
                    _ => unreachable!(),
                })
        })
        .unwrap_or(OnuState::Unknown);
    let description = line
        .split_once(':')
        .map(|(_, value)| value.trim().to_owned())
        .unwrap_or_else(|| line.trim().to_owned());
    Ok((state, description))
}

/// Parses loss-of-signal, loss-of-frame, and loss-of-message alarm states.
///
/// The tuple order is `(LOS, LOF, LOM)`. Missing or unrecognized fields are
/// represented by [`AlarmCondition::Unknown`].
pub fn parse_alarm_status(output: &str) -> (AlarmCondition, AlarmCondition, AlarmCondition) {
    fn find(output: &str, name: &str) -> AlarmCondition {
        output
            .lines()
            .find(|line| {
                let lower = line.to_ascii_lowercase();
                lower.contains(&format!("alarm {}", name.to_ascii_lowercase()))
            })
            .map(|line| {
                let lower = line.to_ascii_lowercase();
                if lower.contains("occur") || lower.contains("active") {
                    AlarmCondition::Active
                } else if lower.contains("clear") {
                    AlarmCondition::Clear
                } else {
                    AlarmCondition::Unknown
                }
            })
            .unwrap_or(AlarmCondition::Unknown)
    }
    (
        find(output, "LOS"),
        find(output, "LOF"),
        find(output, "LOM"),
    )
}

/// Parses Realtek downstream flow-table output.
///
/// Valid flow rows are returned in device-output order. An error is returned
/// when no recognizable flow rows are present.
pub fn parse_downstream_flows(output: &str) -> Result<Vec<DownstreamFlow>> {
    let mut flows = Vec::new();
    for line in output.lines() {
        let columns: Vec<_> = line.split('|').map(str::trim).collect();
        if columns.len() < 5 {
            continue;
        }
        let Ok(flow_id) = columns[0].parse::<u8>() else {
            continue;
        };
        let Ok(gem_port) = columns[1].parse::<u16>() else {
            continue;
        };
        flows.push(DownstreamFlow {
            flow_id,
            gem_port,
            flow_type: parse_flow_type(columns[2])?,
            multicast: parse_flag(columns[3]),
            aes: parse_flag(columns[4]),
        });
    }
    flows.sort_by_key(|flow| flow.flow_id);
    Ok(flows)
}

/// Parses Realtek upstream flow-table output.
///
/// Valid flow rows are returned in device-output order. An error is returned
/// when no recognizable flow rows are present.
pub fn parse_upstream_flows(output: &str) -> Result<Vec<UpstreamFlow>> {
    let mut flows = Vec::new();
    for line in output.lines() {
        let columns: Vec<_> = line.split('|').map(str::trim).collect();
        if columns.len() < 3 {
            continue;
        }
        let Ok(flow_id) = columns[0].parse::<u8>() else {
            continue;
        };
        let Ok(gem_port) = columns[1].parse::<u16>() else {
            continue;
        };
        flows.push(UpstreamFlow {
            flow_id,
            gem_port,
            flow_type: parse_flow_type(columns[2])?,
            tcont: columns.get(3).and_then(|value| value.parse().ok()),
            channel: columns.get(4).and_then(|value| value.parse().ok()),
            omci: columns.get(5).is_some_and(|value| parse_flag(value)),
        });
    }
    flows.sort_by_key(|flow| flow.flow_id);
    Ok(flows)
}

fn parse_flow_type(value: &str) -> Result<FlowType> {
    match value.trim().to_ascii_uppercase().as_str() {
        "ETH" | "ETHER" | "ETHERNET" => Ok(FlowType::Ethernet),
        "OMCI" => Ok(FlowType::Omci),
        other => Err(Error::Parse {
            context: "flow type",
            details: format!("unsupported value {other:?}"),
        }),
    }
}

fn parse_flag(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "*" | "yes" | "true" | "enable" | "enabled" | "1"
    )
}

/// Parses counters for `flow_id` from `gpon show counter flow` output.
///
/// Missing or malformed counters remain zero so callers can display partial
/// diagnostic output without failing the entire sampling loop.
pub fn parse_flow_counters(flow_id: u8, output: &str) -> FlowCounters {
    let mut counters = FlowCounters {
        flow_id,
        ..Default::default()
    };
    for line in output.lines() {
        let Some((label, raw_value)) = line.rsplit_once(':') else {
            continue;
        };
        let Ok(value) = raw_value.trim().parse::<u64>() else {
            continue;
        };
        let normalized = label
            .to_ascii_lowercase()
            .replace('/', "")
            .replace([' ', '\t'], "");
        if normalized.contains("dsgem")
            && (normalized.contains("packet") || normalized.contains("block"))
        {
            counters.ds_gem_packets = value;
        } else if normalized.contains("dsgembytes") {
            counters.ds_gem_bytes = value;
        } else if normalized.contains("rxeth") {
            counters.ds_rx_eth_packets = value;
        } else if normalized.contains("fwdeth") {
            counters.ds_fwd_eth_packets = value;
        } else if normalized.contains("usgem")
            && (normalized.contains("count")
                || normalized.contains("packet")
                || normalized.contains("block"))
        {
            counters.us_gem_packets = value;
        } else if normalized.contains("usgembytes") {
            counters.us_gem_bytes = value;
        } else if normalized.contains("useth") {
            counters.us_eth_packets = value;
        }
    }
    counters
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_expression_is_sorted_and_deduplicated() {
        assert_eq!(
            parse_selection_expression("5,1-3,2", 0, 10).unwrap(),
            vec![1, 2, 3, 5]
        );
        assert!(parse_selection_expression("4-2", 0, 10).is_err());
        assert!(parse_selection_expression("11", 0, 10).is_err());
    }

    #[test]
    fn parses_line_status() {
        let (state, description) =
            parse_onu_state("RTK.0>\r\nONU state: Operation State(O5)\r\n").unwrap();
        assert_eq!(state, OnuState::O5);
        assert_eq!(description, "Operation State(O5)");
        assert_eq!(
            parse_alarm_status(
                "Alarm LOS, status: clear\nAlarm LOF, status: occur\nAlarm LOM, status: clear"
            ),
            (
                AlarmCondition::Clear,
                AlarmCondition::Active,
                AlarmCondition::Clear
            )
        );
    }

    #[test]
    fn parses_flow_tables() {
        let ds = parse_downstream_flows(
            "Flow ID | GEM Port | Type | Multicast | AES\n0 | 1000 | ETH | | *",
        )
        .unwrap();
        assert_eq!(
            ds,
            vec![DownstreamFlow {
                flow_id: 0,
                gem_port: 1000,
                flow_type: FlowType::Ethernet,
                multicast: false,
                aes: true,
            }]
        );
        let us = parse_upstream_flows(
            "Flow ID | GEM Port | Type | TCont | Channel | OMCI\n0 | 1000 | ETH | 0 | 16 |",
        )
        .unwrap();
        assert_eq!(us[0].tcont, Some(0));
        assert_eq!(us[0].channel, Some(16));
    }

    #[test]
    fn parses_counter_firmware_variants() {
        let output = "
D/S GEM packets : 155
D/S GEM bytes   : 175126
RX Eth packetts : 151
Fwd Eth packets : 150
U/S GEM counts  : 9
U/S GEM bytes   : 800
U/S Eth packets : 7";
        let counters = parse_flow_counters(3, output);
        assert_eq!(counters.ds_gem_packets, 155);
        assert_eq!(counters.ds_gem_bytes, 175126);
        assert_eq!(counters.ds_rx_eth_packets, 151);
        assert_eq!(counters.ds_fwd_eth_packets, 150);
        assert_eq!(counters.us_gem_packets, 9);
        assert_eq!(counters.us_gem_bytes, 800);
        assert_eq!(counters.us_eth_packets, 7);
    }

    #[test]
    fn parses_omci_mib_catalog_and_entities() {
        let catalog =
            parse_omci_mib_catalog("TableId [1] Name: Anig!\nTableId [20] Name: GemPortCtp!\n")
                .unwrap();
        assert_eq!(
            catalog,
            vec![
                MibTableDescriptor {
                    internal_id: 1,
                    name: "Anig".into(),
                },
                MibTableDescriptor {
                    internal_id: 20,
                    name: "GemPortCtp".into(),
                },
            ]
        );

        let query = MibQuery {
            selector: MibSelector::ClassId(256),
            entity_id: None,
        };
        let snapshot = parse_omci_mib_snapshot(
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nOntg\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
             =================================\nEntityID: 0x00\nVID: ALCL\nLogicalPassword:\n\
             Description: first:second\n continuation\n=================================\n",
            query,
        )
        .unwrap();
        assert_eq!(snapshot.table_name, "Ontg");
        assert_eq!(snapshot.entities[0].entity_id, 0);
        assert_eq!(snapshot.entities[0].attributes[1].value, "");
        assert_eq!(
            snapshot.entities[0].attributes[2].value,
            "first:second\ncontinuation"
        );
    }

    #[test]
    fn resolves_realtek_table_names_to_omci_class_ids() {
        assert_eq!(omci_class_id_for_table("Ontg"), Some(256));
        assert_eq!(omci_class_id_for_table("gemportctp"), Some(268));
        assert_eq!(omci_class_id_for_table("VendorPrivateThing"), None);
    }

    #[test]
    fn reports_catalog_fallback_as_unavailable_mib_data() {
        let error = parse_omci_mib_snapshot(
            "TableId [1] Name: Anig!\n",
            MibQuery {
                selector: MibSelector::TableName("NotAClass".into()),
                entity_id: None,
            },
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("OMCI MIB may not be synchronized")
        );
    }

    #[test]
    fn allocates_a_common_id_for_both_directions() {
        let downstream = vec![DownstreamFlow {
            flow_id: 0,
            gem_port: 1,
            flow_type: FlowType::Ethernet,
            multicast: false,
            aes: false,
        }];
        let upstream = vec![UpstreamFlow {
            flow_id: 1,
            gem_port: 1,
            flow_type: FlowType::Ethernet,
            tcont: None,
            channel: None,
            omci: false,
        }];
        assert_eq!(
            allocate_flow_ids(
                DirectionScope::Both,
                FlowIdChoice::Auto,
                2,
                &downstream,
                &upstream
            )
            .unwrap(),
            vec![2, 3]
        );
    }
}
