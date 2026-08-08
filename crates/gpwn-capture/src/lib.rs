//! Local packet capture driven by a `dumpcap` child process.
//!
//! `tshark` shells out to `dumpcap` anyway, so this drives the capture engine
//! directly: no dissection layer we do not use, and pcapng without asking.
//!
//! Run `cargo run -p gpwn-capture --example interfaces` to enumerate capture
//! interfaces using the same privilege check as the application.

use gpwn_core::{Error, Result};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;

const DUMPCAP: &str = "dumpcap";

/// How long to wait for `dumpcap` to finalize the capture file per stop stage.
const STOP_GRACE: Duration = Duration::from_secs(3);

/// Per-packet pcapng Enhanced Packet Block cost: block type, total length,
/// interface ID, both timestamp halves, captured length, original length, and
/// the repeated trailing length.
const PCAPNG_PER_PACKET_OVERHEAD: u64 = 32;

/// Capture interface reported by `dumpcap`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceInfo {
    /// Device name accepted by `dumpcap`'s interface argument.
    pub name: String,
    /// Optional human-readable interface or vendor description.
    pub friendly: Option<String>,
    /// Network addresses reported for the interface.
    pub addresses: Vec<String>,
    /// Whether the interface is a loopback device.
    pub loopback: bool,
}

impl InterfaceInfo {
    /// Return a picker label containing the device name and friendly name.
    pub fn label(&self) -> String {
        match &self.friendly {
            Some(friendly) => format!("{} — {friendly}", self.name),
            None => self.name.clone(),
        }
    }

    /// Loopback and the virtual links macOS always reports, none of which can
    /// carry ONU traffic. Hidden by default so the picker shows real NICs.
    pub fn is_uninteresting(&self) -> bool {
        const VIRTUAL_PREFIXES: [&str; 8] =
            ["utun", "awdl", "llw", "anpi", "ap", "bridge", "gif", "stf"];
        self.loopback
            || VIRTUAL_PREFIXES
                .iter()
                .any(|prefix| self.name.starts_with(prefix))
    }
}

/// Parse the machine-readable interface listing from `dumpcap -D -M`.
///
/// Wireshark 4.6 emits JSON, while older releases emit rows containing
/// `<n>. <name>`, vendor description, friendly name, type, a comma-separated
/// address list, and `network` or `loopback`, all tab-separated.
pub fn parse_interface_list(output: &str) -> Vec<InterfaceInfo> {
    if let Some(interfaces) = parse_json_interface_list(output) {
        return interfaces;
    }
    output.lines().filter_map(parse_interface_row).collect()
}

#[derive(Deserialize)]
struct JsonInterface {
    friendly_name: Option<String>,
    vendor_description: Option<String>,
    #[serde(default)]
    addrs: Vec<String>,
    #[serde(default)]
    loopback: bool,
}

fn parse_json_interface_list(output: &str) -> Option<Vec<InterfaceInfo>> {
    let rows: Vec<std::collections::HashMap<String, JsonInterface>> =
        serde_json::from_str(output).ok()?;
    Some(
        rows.into_iter()
            .filter_map(|row| {
                let (name, interface) = row.into_iter().next()?;
                if name.trim().is_empty() {
                    return None;
                }
                Some(InterfaceInfo {
                    name,
                    friendly: interface
                        .friendly_name
                        .or(interface.vendor_description)
                        .filter(|value| !value.trim().is_empty()),
                    addresses: interface.addrs,
                    loopback: interface.loopback,
                })
            })
            .collect(),
    )
}

fn parse_interface_row(row: &str) -> Option<InterfaceInfo> {
    let fields: Vec<_> = row.split('\t').collect();
    if fields.len() < 6 {
        return None;
    }
    let name = fields[0].split_once(". ")?.1.trim();
    if name.is_empty() {
        return None;
    }
    Some(InterfaceInfo {
        name: name.to_owned(),
        friendly: [fields[2], fields[1]]
            .into_iter()
            .map(str::trim)
            .find(|value| !value.is_empty())
            .map(str::to_owned),
        addresses: fields[4]
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect(),
        loopback: fields[5].trim().eq_ignore_ascii_case("loopback"),
    })
}

/// List capturable interfaces. Doubles as the privilege probe: `dumpcap` cannot
/// enumerate without packet access, so a failure here is the same failure a
/// capture would hit, surfaced before the user has configured anything.
pub fn interfaces() -> Result<Vec<InterfaceInfo>> {
    let output = std::process::Command::new(DUMPCAP)
        .args(["-D", "-M"])
        .output()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::Backend(format!(
                    "{DUMPCAP} was not found; install Wireshark or put it on PATH"
                ))
            } else {
                Error::Backend(format!("could not run {DUMPCAP}: {error}"))
            }
        })?;
    if !output.status.success() {
        return Err(Error::Backend(privilege_hint(&String::from_utf8_lossy(
            &output.stderr,
        ))));
    }
    let interfaces = parse_interface_list(&String::from_utf8_lossy(&output.stdout));
    if interfaces.is_empty() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let details = if stdout.trim().is_empty() {
            "dumpcap succeeded but returned no interfaces".to_owned()
        } else {
            format!(
                "dumpcap returned an unrecognized interface-list format: {}",
                stdout.trim().chars().take(160).collect::<String>()
            )
        };
        return Err(Error::Backend(details));
    }
    Ok(interfaces)
}

/// Enumeration failures are almost always missing capture privileges rather
/// than anything the raw error explains, so lead with the fix.
fn privilege_hint(details: &str) -> String {
    format!(
        "{DUMPCAP} could not list interfaces ({}). Capturing needs packet privileges: \
         install ChmodBPF on macOS, or run \
         `sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)` on Linux.",
        details.trim()
    )
}

/// Build a filter that keeps our own management traffic out of the capture.
///
/// Management and capture share one link when the ONU is plugged straight into
/// the host, so without this every pcap contains the SSH session driving it.
/// Returns `None` when the endpoint is not a real address — the mock backend
/// reports `mock://healthy`, which correctly yields no filter.
pub fn management_filter(endpoint: &str) -> Option<String> {
    let address: SocketAddr = endpoint.trim().parse().ok()?;
    Some(format!(
        "not (host {} and port {})",
        address.ip(),
        address.port()
    ))
}

/// Estimated pcapng size for a capture held at this rate.
///
/// The per-packet block overhead dominates small frames: roughly 2% for
/// 1500-byte frames but around 50% for 64-byte ones, so it is worth carrying.
pub fn estimate_bytes(packets_per_second: f64, average_frame: f64, duration: Duration) -> u64 {
    if !packets_per_second.is_finite() || !average_frame.is_finite() {
        return 0;
    }
    let per_packet = average_frame.max(0.0) + PCAPNG_PER_PACKET_OVERHEAD as f64;
    // Float-to-integer casts saturate, so an absurd rate clamps instead of wrapping.
    (per_packet * packets_per_second.max(0.0) * duration.as_secs_f64()) as u64
}

/// Bytes an unprivileged writer can still add to the filesystem holding `path`.
pub fn free_space(path: &Path) -> Result<u64> {
    let probe = existing_ancestor(path);
    let stat = nix::sys::statvfs::statvfs(probe).map_err(|error| {
        Error::Backend(format!(
            "could not check free space on {}: {error}",
            probe.display()
        ))
    })?;
    Ok(stat.blocks_available() as u64 * stat.fragment_size() as u64)
}

/// `statvfs` needs a path that exists, but the output directory may not have
/// been created yet.
fn existing_ancestor(path: &Path) -> &Path {
    path.ancestors()
        .find(|candidate| candidate.exists())
        .unwrap_or_else(|| Path::new("."))
}

/// Validated settings used to start one capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfig {
    /// Interface name passed to `dumpcap`.
    pub interface: String,
    /// Directory in which the generated pcapng is created.
    pub output_dir: PathBuf,
    /// `None` records until stopped.
    pub duration: Option<Duration>,
    /// Optional libpcap capture filter.
    pub filter: Option<String>,
}

impl CaptureConfig {
    /// Validate required capture settings before starting a child process.
    pub fn validate(&self) -> Result<()> {
        if self.interface.trim().is_empty() {
            return Err(Error::Validation("a capture interface is required".into()));
        }
        if self.output_dir.as_os_str().is_empty() {
            return Err(Error::Validation("an output directory is required".into()));
        }
        Ok(())
    }
    /// Return the trimmed filter, or `None` when it is absent or blank.
    pub fn effective_filter(&self) -> Option<&str> {
        self.filter
            .as_deref()
            .map(str::trim)
            .filter(|filter| !filter.is_empty())
    }
}

/// Why a capture process completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// `dumpcap` reached the configured duration and stopped itself.
    Duration,
    /// The caller explicitly stopped the capture.
    Manual,
}

/// Finalized capture metadata returned after the child exits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureSummary {
    /// Path of the finalized pcapng file.
    pub path: PathBuf,
    /// Final capture-file size in bytes.
    pub bytes: u64,
    /// Wall-clock time for which the child process ran.
    pub duration: Duration,
    /// Reason the capture ended.
    pub stop_reason: StopReason,
}

/// A running `dumpcap`.
///
/// Dropping this signals the child rather than orphaning it, so a panic mid
/// capture still leaves a readable file.
pub struct Capture {
    child: tokio::process::Child,
    path: PathBuf,
    started_at: Instant,
    stderr: Arc<Mutex<String>>,
    finished: bool,
}

impl Capture {
    /// Validate `config`, create its output directory, and start `dumpcap`.
    pub async fn start(config: &CaptureConfig) -> Result<Self> {
        config.validate()?;
        std::fs::create_dir_all(&config.output_dir).map_err(|error| {
            Error::Backend(format!(
                "could not create {}: {error}",
                config.output_dir.display()
            ))
        })?;
        let path = config.output_dir.join(format!(
            "gpwn-capture-{}.pcapng",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        ));
        if path.exists() {
            return Err(Error::Validation(format!(
                "{} already exists; existing captures are never overwritten",
                path.display()
            )));
        }

        let mut command = tokio::process::Command::new(DUMPCAP);
        command.arg("-i").arg(&config.interface);
        command.arg("-w").arg(&path);
        if let Some(duration) = config.duration {
            // Sub-second durations would round to an immediate stop.
            command
                .arg("-a")
                .arg(format!("duration:{}", duration.as_secs().max(1)));
        }
        if let Some(filter) = config.effective_filter() {
            command.arg("-f").arg(filter);
        }
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| Error::Backend(format!("could not start {DUMPCAP}: {error}")))?;

        // Drain stderr continuously: a full pipe buffer would otherwise block
        // `dumpcap` partway through a long capture.
        let stderr = Arc::new(Mutex::new(String::new()));
        if let Some(mut pipe) = child.stderr.take() {
            let sink = Arc::clone(&stderr);
            tokio::spawn(async move {
                let mut collected = Vec::new();
                if pipe.read_to_end(&mut collected).await.is_ok()
                    && let Ok(mut guard) = sink.lock()
                {
                    guard.push_str(&String::from_utf8_lossy(&collected));
                }
            });
        }
        Ok(Self {
            child,
            path,
            started_at: Instant::now(),
            stderr,
            finished: false,
        })
    }

    /// Return the path of the capture file being written.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Bytes written so far, read from the file itself rather than from
    /// `dumpcap`, which reports nothing usable on a piped stderr.
    pub fn bytes(&self) -> u64 {
        std::fs::metadata(&self.path)
            .map(|metadata| metadata.len())
            .unwrap_or(0)
    }

    /// `Some` once `dumpcap` has exited on its own — the duration cap elapsed,
    /// or it failed.
    pub fn poll_exit(&mut self) -> Option<Result<CaptureSummary>> {
        match self.child.try_wait() {
            Ok(Some(status)) => {
                self.finished = true;
                Some(self.finish(&status, StopReason::Duration))
            }
            Ok(None) => None,
            Err(error) => {
                self.finished = true;
                Some(Err(Error::Backend(format!(
                    "could not poll {DUMPCAP}: {error}"
                ))))
            }
        }
    }

    /// Interrupt the capture and wait for the file to be finalized.
    pub async fn stop(&mut self) -> Result<CaptureSummary> {
        // SIGINT, never SIGKILL: `dumpcap` finalizes the pcapng on interrupt,
        // so a hard kill leaves a truncated, unreadable capture.
        self.signal(Signal::SIGINT);
        let status = match tokio::time::timeout(STOP_GRACE, self.child.wait()).await {
            Ok(Ok(status)) => status,
            Ok(Err(error)) => {
                self.finished = true;
                return Err(Error::Backend(format!("waiting for {DUMPCAP}: {error}")));
            }
            Err(_) => {
                self.signal(Signal::SIGTERM);
                match tokio::time::timeout(STOP_GRACE, self.child.wait()).await {
                    Ok(Ok(status)) => status,
                    _ => {
                        let _ = self.child.start_kill();
                        self.finished = true;
                        return Err(Error::Backend(format!(
                            "{DUMPCAP} ignored SIGINT and SIGTERM; {} may be truncated",
                            self.path.display()
                        )));
                    }
                }
            }
        };
        self.finished = true;
        self.finish(&status, StopReason::Manual)
    }

    fn finish(&self, status: &ExitStatus, stop_reason: StopReason) -> Result<CaptureSummary> {
        if !exited_cleanly(status) {
            return Err(Error::Backend(self.failure_message()));
        }
        Ok(CaptureSummary {
            path: self.path.clone(),
            bytes: self.bytes(),
            duration: self.started_at.elapsed(),
            stop_reason,
        })
    }

    /// `dumpcap` validates the interface and capture filter at startup, so its
    /// own message is more useful than anything reconstructed from the status.
    fn failure_message(&self) -> String {
        let reported = self
            .stderr
            .lock()
            .map(|guard| guard.trim().to_owned())
            .unwrap_or_default();
        if reported.is_empty() {
            format!("{DUMPCAP} exited unsuccessfully")
        } else {
            reported
        }
    }

    fn signal(&self, signal: Signal) {
        if let Some(pid) = self.child.id() {
            let _ = kill(Pid::from_raw(pid as i32), signal);
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // Backstop for panics and forced quits. Blocking briefly here is worth
        // it: the alternative is an orphaned `dumpcap` writing to a file nobody
        // will ever finalize.
        self.signal(Signal::SIGINT);
        let deadline = Instant::now() + STOP_GRACE;
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            }
        }
        let _ = self.child.start_kill();
    }
}

/// A capture stopped by SIGINT may report the signal rather than an exit code,
/// depending on how `dumpcap` was built; both mean the file was closed.
fn exited_cleanly(status: &ExitStatus) -> bool {
    status.success() || status.signal() == Some(Signal::SIGINT as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim `dumpcap -D -M` output, including the empty vendor-description
    /// column and the trailing tab.
    const INTERFACE_LISTING: &str = "1. ap1\t\t\t0\t\tnetwork\t\n\
         2. en0\t\tWi-Fi\t5\tfe80::8b0:25ab:928c:ade8,172.21.12.3\tnetwork\t\n\
         3. awdl0\t\t\t0\tfe80::3423:31ff:fec0:76ca\tnetwork\t\n\
         11. lo0\t\tLoopback\t0\t127.0.0.1,::1\tloopback\t\n";

    const JSON_INTERFACE_LISTING: &str = r#"[
        {"wlp0s20f3":{"friendly_name":null,"vendor_description":null,"type":5,
         "addrs":["192.168.0.216","fe80::1"],"loopback":false,"extcap":""}},
        {"lo":{"friendly_name":"Loopback","vendor_description":null,"type":0,
         "addrs":["127.0.0.1","::1"],"loopback":true,"extcap":""}}
    ]"#;

    #[test]
    fn parses_machine_readable_interface_listing() {
        let interfaces = parse_interface_list(INTERFACE_LISTING);
        assert_eq!(interfaces.len(), 4);
        assert_eq!(
            interfaces[1],
            InterfaceInfo {
                name: "en0".into(),
                friendly: Some("Wi-Fi".into()),
                addresses: vec!["fe80::8b0:25ab:928c:ade8".into(), "172.21.12.3".into()],
                loopback: false,
            }
        );
        assert_eq!(interfaces[0].friendly, None);
        assert!(interfaces[0].addresses.is_empty());
        assert!(interfaces[3].loopback);
        assert_eq!(interfaces[1].label(), "en0 — Wi-Fi");
        assert_eq!(interfaces[0].label(), "ap1");
    }

    #[test]
    fn parses_json_interface_listing_from_wireshark_4_6() {
        let interfaces = parse_interface_list(JSON_INTERFACE_LISTING);
        assert_eq!(
            interfaces,
            vec![
                InterfaceInfo {
                    name: "wlp0s20f3".into(),
                    friendly: None,
                    addresses: vec!["192.168.0.216".into(), "fe80::1".into()],
                    loopback: false,
                },
                InterfaceInfo {
                    name: "lo".into(),
                    friendly: Some("Loopback".into()),
                    addresses: vec!["127.0.0.1".into(), "::1".into()],
                    loopback: true,
                },
            ]
        );
    }

    #[test]
    fn hides_virtual_links_but_keeps_real_nics() {
        let interfaces = parse_interface_list(INTERFACE_LISTING);
        let visible: Vec<_> = interfaces
            .iter()
            .filter(|interface| !interface.is_uninteresting())
            .map(|interface| interface.name.as_str())
            .collect();
        assert_eq!(visible, vec!["en0"]);
    }

    #[test]
    fn ignores_rows_that_are_not_interfaces() {
        assert!(parse_interface_list("Capturing on 'en0'\n\n").is_empty());
    }

    #[test]
    fn derives_a_filter_only_from_a_real_endpoint() {
        assert_eq!(
            management_filter("192.168.69.1:22").as_deref(),
            Some("not (host 192.168.69.1 and port 22)")
        );
        // The port is taken from the connection, not assumed to be 22.
        assert_eq!(
            management_filter("10.0.0.5:2222").as_deref(),
            Some("not (host 10.0.0.5 and port 2222)")
        );
        assert_eq!(management_filter("mock://healthy"), None);
        assert_eq!(management_filter("onu.lab:22"), None);
    }

    #[test]
    fn estimates_include_per_packet_block_overhead() {
        let one_second = Duration::from_secs(1);
        assert_eq!(estimate_bytes(10.0, 1500.0, one_second), 15320);
        // Overhead dominates small frames.
        assert_eq!(estimate_bytes(10.0, 64.0, one_second), 960);
        assert_eq!(estimate_bytes(0.0, 1500.0, one_second), 0);
        assert_eq!(estimate_bytes(f64::NAN, 1500.0, one_second), 0);
        assert_eq!(estimate_bytes(10.0, 1500.0, Duration::ZERO), 0);
    }

    #[test]
    fn rejects_configurations_that_cannot_start() {
        let valid = CaptureConfig {
            interface: "en0".into(),
            output_dir: PathBuf::from("./captures"),
            duration: None,
            filter: None,
        };
        assert!(valid.validate().is_ok());
        assert!(
            CaptureConfig {
                interface: "  ".into(),
                ..valid.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            CaptureConfig {
                output_dir: PathBuf::new(),
                ..valid
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn blank_filters_are_not_passed_to_dumpcap() {
        let config = CaptureConfig {
            interface: "en0".into(),
            output_dir: PathBuf::from("."),
            duration: None,
            filter: Some("   ".into()),
        };
        assert_eq!(config.effective_filter(), None);
    }

    #[test]
    fn free_space_walks_up_to_an_existing_directory() {
        let free = free_space(Path::new("./does-not-exist/nor-this")).unwrap();
        assert!(free > 0);
    }

    /// Start a real `dumpcap` on loopback. Used by the privileged tests below.
    async fn loopback_capture(directory: &Path, duration: Option<Duration>) -> Capture {
        let _ = std::fs::remove_dir_all(directory);
        let loopback = interfaces()
            .expect("dumpcap should list interfaces")
            .into_iter()
            .find(|interface| interface.loopback)
            .expect("a loopback interface");
        Capture::start(&CaptureConfig {
            interface: loopback.name,
            output_dir: directory.to_path_buf(),
            duration,
            filter: None,
        })
        .await
        .expect("dumpcap should start")
    }

    /// A pcapng `dumpcap` closed properly opens with a Section Header Block; a
    /// truncated one does not.
    fn assert_finalized_pcapng(path: &Path) {
        let written = std::fs::read(path).expect("capture file should exist");
        assert!(written.len() >= 28, "expected at least a section header");
        assert_eq!(
            &written[..4],
            &[0x0a, 0x0d, 0x0d, 0x0a],
            "pcapng section header magic is missing, so the file was truncated"
        );
    }

    /// Proves SIGINT finalizes rather than truncates — the failure that would
    /// quietly ruin a long capture. Needs packet privileges, so it is excluded
    /// by default:
    ///
    /// ```text
    /// cargo test -p gpwn-capture -- --ignored
    /// ```
    #[tokio::test]
    #[ignore = "requires packet capture privileges"]
    async fn interrupting_a_capture_leaves_a_finalized_file() {
        let directory = std::env::temp_dir().join("gpwn-capture-selftest");
        let mut capture = loopback_capture(&directory, None).await;
        tokio::time::sleep(Duration::from_millis(800)).await;

        let summary = capture.stop().await.expect("dumpcap should stop cleanly");
        assert_eq!(summary.stop_reason, StopReason::Manual);
        assert_finalized_pcapng(&summary.path);
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// The wizard defaults to a bounded capture, so `dumpcap` stopping itself
    /// is the path most runs take. Same privileges, same opt-in.
    #[tokio::test]
    #[ignore = "requires packet capture privileges"]
    async fn a_bounded_capture_stops_itself() {
        let directory = std::env::temp_dir().join("gpwn-capture-selftest-duration");
        let mut capture = loopback_capture(&directory, Some(Duration::from_secs(1))).await;

        let deadline = Instant::now() + Duration::from_secs(15);
        let summary = loop {
            assert!(Instant::now() < deadline, "capture never stopped itself");
            if let Some(result) = capture.poll_exit() {
                break result.expect("a duration-capped capture should succeed");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };

        assert_eq!(summary.stop_reason, StopReason::Duration);
        assert_finalized_pcapng(&summary.path);
        let _ = std::fs::remove_dir_all(&directory);
    }
}
