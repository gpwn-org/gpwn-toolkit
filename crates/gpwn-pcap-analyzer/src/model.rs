use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Serializable snapshot of one capture and all analyzer-derived records.
pub struct CaptureModel {
    /// Capture filename shown to API consumers.
    pub source: String,
    /// Analysis mode: `live` for a growing file or `completed` otherwise.
    pub mode: String,
    /// Current pipeline state, such as `loading`, `ready`, or `error`.
    pub status: String,
    /// Number of valid packet rows consumed.
    pub packet_count: u64,
    /// Unix timestamp of the first consumed packet.
    pub first_timestamp: Option<f64>,
    /// Unix timestamp of the most recently consumed packet.
    pub last_timestamp: Option<f64>,
    /// Seconds elapsed from the first to the most recent packet.
    pub duration: f64,
    /// Observed endpoints sorted by identifier.
    pub nodes: Vec<Node>,
    /// Bidirectional endpoint pairs sorted by source and target.
    pub edges: Vec<Edge>,
    /// Protocol observations in emission order.
    pub events: Vec<Event>,
}

impl CaptureModel {
    /// Creates an empty model for `path` in completed or live-follow mode.
    pub fn new(path: &Path, follow: bool) -> Self {
        Self {
            source: path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("capture")
                .to_owned(),
            mode: if follow { "live" } else { "completed" }.to_owned(),
            status: "loading".to_owned(),
            packet_count: 0,
            first_timestamp: None,
            last_timestamp: None,
            duration: 0.0,
            nodes: Vec::new(),
            edges: Vec::new(),
            events: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// An observed L2 endpoint, or an `ip:`-prefixed endpoint when Ethernet is absent.
pub struct Node {
    /// Canonical lowercase MAC address or an `ip:`-prefixed IP endpoint.
    pub mac: String,
    /// Non-private OUI manufacturer labels observed for this endpoint.
    pub manufacturers: BTreeSet<String>,
    /// IPv4 and IPv6 addresses associated with the endpoint.
    pub ips: BTreeSet<String>,
    /// Hostnames learned from identity protocols such as DHCP.
    pub hostnames: BTreeSet<String>,
    /// Application protocols observed on packets involving this endpoint.
    pub protocols: BTreeSet<String>,
    /// Capture-relative time when the endpoint first appeared.
    pub first_seen: f64,
    /// Capture-relative time when the endpoint last appeared.
    pub last_seen: f64,
    /// Packets attributed to the endpoint.
    pub packet_count: u64,
    /// Captured bytes attributed to the endpoint.
    pub byte_count: u64,
    /// Events whose primary node is this endpoint.
    pub event_count: u64,
    /// Whether this endpoint received GTP-encapsulated subscriber traffic.
    #[serde(default)]
    pub gtp_receiver: bool,
    /// Capture-relative time when GTP reception was first observed.
    #[serde(default)]
    pub gtp_first_seen: Option<f64>,
    /// Inner subscriber sessions keyed by destination IP address.
    #[serde(default)]
    pub mobile_ues: BTreeMap<String, MobileUeSession>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Inner subscriber session observed behind a GTP receiver.
pub struct MobileUeSession {
    /// Inner destination IP identifying the subscriber session.
    pub ip: String,
    /// GTP tunnel endpoint identifiers associated with the session.
    pub teids: BTreeSet<String>,
    /// Capture-relative time when the session first appeared.
    pub first_seen: f64,
    /// Capture-relative time when the session last appeared.
    pub last_seen: f64,
    /// Encapsulated packets attributed to the session.
    pub packet_count: u64,
    /// Captured encapsulated bytes attributed to the session.
    pub byte_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Bidirectional traffic aggregate between two canonically ordered endpoints.
pub struct Edge {
    /// Lexicographically smaller endpoint identifier.
    pub source: String,
    /// Lexicographically larger endpoint identifier.
    pub target: String,
    /// Application protocols observed between the endpoints.
    pub protocols: BTreeSet<String>,
    /// Capture-relative time when traffic first appeared.
    pub first_seen: f64,
    /// Capture-relative time when traffic last appeared.
    pub last_seen: f64,
    /// Packets observed between the endpoints.
    pub packet_count: u64,
    /// Captured bytes observed between the endpoints.
    pub byte_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
/// A protocol-level observation derived from one packet.
pub struct Event {
    /// Monotonically increasing analyzer-local event identifier.
    pub id: u64,
    /// Capture-relative event time in seconds.
    pub time: f64,
    /// Source capture frame number.
    pub frame: u64,
    /// Endpoint primarily associated with the observation.
    pub node: String,
    /// Other endpoint involved in the observation, when known.
    pub peer: Option<String>,
    /// Stable machine-readable event-kind identifier.
    pub kind: String,
    /// Presentation severity such as `info`, `notable`, or `important`.
    pub severity: String,
    /// Protocol label associated with the observation.
    pub protocol: String,
    /// Concise human-readable event heading.
    pub title: String,
    /// Human-readable explanation of the observation.
    pub summary: String,
    /// Protocol-specific metadata extracted from the packet.
    pub details: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
/// Paginated event response returned by the HTTP API.
pub struct EventPage {
    /// Events in this page.
    pub items: Vec<Event>,
    /// Total number of events matching the query.
    pub total: usize,
    /// Number of matching events skipped before this page.
    pub offset: usize,
    /// Requested, bounded page size.
    pub limit: usize,
}

#[derive(Clone, Debug, Serialize)]
/// Metadata for one object exported from a capture.
pub struct Artifact {
    /// Stable relative-path identifier.
    pub id: String,
    /// Display filename relative to the artifact root.
    pub name: String,
    /// File size in bytes.
    pub size: u64,
    /// Safe media type used by the API.
    pub media_type: String,
    /// Percent-encoded API URL for this artifact.
    pub url: String,
}

#[derive(Debug, Serialize)]
/// Paginated artifact response returned by the HTTP API.
pub struct ArtifactPage {
    /// Artifacts in this page.
    pub items: Vec<Artifact>,
    /// Total number of currently available artifacts.
    pub total: usize,
    /// Number of sorted artifacts skipped before this page.
    pub offset: usize,
    /// Requested, bounded page size.
    pub limit: usize,
    /// Whether the artifact-export pass completed successfully.
    pub complete: bool,
    /// Available artifacts grouped into the visualizer's broad media categories.
    pub counts: BTreeMap<String, usize>,
}
