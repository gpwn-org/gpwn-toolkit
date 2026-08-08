//! Interactive terminal application for GPWN's ONU management workflows.
//!
//! Reusable device contracts, parsers, scanning, transport, and capture logic
//! live in the workspace library crates; this binary owns operator interaction.

use anyhow::Context;
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEventKind};
use gpwn_capture::{
    Capture, CaptureConfig, CaptureSummary, InterfaceInfo, StopReason, estimate_bytes, free_space,
    management_filter,
};
use gpwn_core::{
    AddFlowRequest, AlarmCondition, ConnectionInfo, DeleteFlowRequest, DirectionScope,
    FlowCounters, FlowIdChoice, FlowType, MibQuery, MibSelector, MibTableDescriptor,
    MibTableSnapshot, MutationReport, OnuBackend, OnuSnapshot, omci_class_id_for_table,
    parse_selection_expression,
};
use gpwn_mock::{MockBackend, MockScenario};
use gpwn_scan::{
    ApplyResult, AutoscanConfig, AutoscanPhase, AutoscanResult, CancellationToken, ScanOutcome,
    ScanProgress, apply_active_ports, plan_active_apply, retry_restore, run_autoscan,
};
use gpwn_ssh::{ConnectionConfig, LiveBackend};
use ratatui::layout::{Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, TableState, Tabs, Wrap,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

mod backend;
mod terminal;
mod ui;

use backend::*;
use terminal::TerminalGuard;
use ui::*;

#[derive(Parser)]
#[command(name = "gpwn-tui", about = "Interactive Realtek GPON ONU flow toolkit")]
struct Args {
    #[arg(long, default_value = "192.168.69.1")]
    host: String,
    #[arg(long, default_value_t = 22)]
    port: u16,
    #[arg(long, default_value = "admin")]
    user: String,
    #[arg(long, default_value_t = 10)]
    timeout: u64,
    #[arg(long, default_value_t = 10)]
    poll_interval: u64,
    #[arg(long)]
    mock: bool,
    #[arg(long, default_value = "healthy")]
    mock_scenario: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendChoice {
    Live,
    Mock,
}

impl BackendChoice {
    fn toggle(&mut self) {
        *self = match self {
            Self::Live => Self::Mock,
            Self::Mock => Self::Live,
        };
    }
}

impl std::fmt::Display for BackendChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Live => "Live SSH",
            Self::Mock => "Mock",
        })
    }
}

#[derive(Debug, Clone)]
struct ConnectionForm {
    backend: BackendChoice,
    scenario: MockScenario,
    host: String,
    port: String,
    user: String,
    password: String,
    timeout: String,
    poll_interval: String,
    focused: usize,
    connecting: bool,
    error: Option<String>,
}

impl ConnectionForm {
    fn from_args(args: Args) -> Self {
        let scenario = parse_scenario(&args.mock_scenario).unwrap_or(MockScenario::Healthy);
        Self {
            backend: if args.mock {
                BackendChoice::Mock
            } else {
                BackendChoice::Live
            },
            scenario,
            host: args.host,
            port: args.port.to_string(),
            user: args.user,
            password: std::env::var("GPWN_PASSWORD").unwrap_or_else(|_| "admin".into()),
            timeout: args.timeout.to_string(),
            poll_interval: args.poll_interval.to_string(),
            focused: 0,
            connecting: false,
            error: None,
        }
    }

    fn fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("Backend", self.backend.to_string()),
            ("Scenario", self.scenario.name().to_owned()),
            ("Host", self.host.clone()),
            ("Port", self.port.clone()),
            ("Username", self.user.clone()),
            ("Password", "•".repeat(self.password.chars().count())),
            ("Timeout (s)", self.timeout.clone()),
            ("Poll interval (s)", self.poll_interval.clone()),
        ]
    }

    fn visible(&self, index: usize) -> bool {
        match self.backend {
            BackendChoice::Live => index != 1,
            BackendChoice::Mock => matches!(index, 0 | 1 | 7),
        }
    }

    fn advance(&mut self, reverse: bool) {
        for _ in 0..8 {
            self.focused = if reverse {
                (self.focused + 7) % 8
            } else {
                (self.focused + 1) % 8
            };
            if self.visible(self.focused) {
                break;
            }
        }
    }

    fn edit(&mut self, character: char) {
        match self.focused {
            0 => self.backend.toggle(),
            1 => cycle_scenario(&mut self.scenario),
            2 => self.host.push(character),
            3 => self.port.push(character),
            4 => self.user.push(character),
            5 => self.password.push(character),
            6 => self.timeout.push(character),
            7 => self.poll_interval.push(character),
            _ => {}
        }
    }

    fn backspace(&mut self) {
        match self.focused {
            2 => {
                self.host.pop();
            }
            3 => {
                self.port.pop();
            }
            4 => {
                self.user.pop();
            }
            5 => {
                self.password.pop();
            }
            6 => {
                self.timeout.pop();
            }
            7 => {
                self.poll_interval.pop();
            }
            _ => {}
        }
    }

    fn settings(&self) -> Result<BackendSettings, String> {
        let poll_interval = self
            .poll_interval
            .parse::<u64>()
            .map_err(|_| "poll interval must be an integer".to_owned())?;
        if poll_interval == 0 {
            return Err("poll interval must be at least one second".into());
        }
        match self.backend {
            BackendChoice::Mock => Ok(BackendSettings::Mock {
                scenario: self.scenario,
                poll_interval: Duration::from_secs(poll_interval),
            }),
            BackendChoice::Live => {
                let port = self
                    .port
                    .parse::<u16>()
                    .map_err(|_| "port must be between 1 and 65535".to_owned())?;
                let timeout = self
                    .timeout
                    .parse::<u64>()
                    .map_err(|_| "timeout must be an integer".to_owned())?;
                if self.host.trim().is_empty() || self.user.trim().is_empty() {
                    return Err("host and username are required".into());
                }
                Ok(BackendSettings::Live {
                    config: ConnectionConfig {
                        host: self.host.trim().to_owned(),
                        port,
                        username: self.user.trim().to_owned(),
                        password: self.password.clone(),
                        timeout: Duration::from_secs(timeout.max(1)),
                    },
                    poll_interval: Duration::from_secs(poll_interval),
                })
            }
        }
    }
}

fn parse_scenario(value: &str) -> Option<MockScenario> {
    match value {
        "healthy" => Some(MockScenario::Healthy),
        "los" => Some(MockScenario::Los),
        "connection-failure" | "failure" => Some(MockScenario::ConnectionFailure),
        _ => None,
    }
}

fn cycle_scenario(scenario: &mut MockScenario) {
    *scenario = match scenario {
        MockScenario::Healthy => MockScenario::Los,
        MockScenario::Los => MockScenario::ConnectionFailure,
        MockScenario::ConnectionFailure => MockScenario::Healthy,
    };
}

#[derive(Clone)]
struct SampleView {
    counters: FlowCounters,
    interval: Option<Duration>,
    sampled_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pane {
    Downstream,
    Upstream,
}

impl Pane {
    fn scope(self) -> DirectionScope {
        match self {
            Self::Downstream => DirectionScope::Downstream,
            Self::Upstream => DirectionScope::Upstream,
        }
    }

    fn toggle(&mut self) {
        *self = match self {
            Self::Downstream => Self::Upstream,
            Self::Upstream => Self::Downstream,
        };
    }

    fn label(self) -> &'static str {
        match self {
            Self::Downstream => "downstream",
            Self::Upstream => "upstream",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivityFilter {
    All,
    Active,
    Idle,
}

impl ActivityFilter {
    fn cycle(&mut self) {
        *self = match self {
            Self::All => Self::Active,
            Self::Active => Self::Idle,
            Self::Idle => Self::All,
        };
    }
}

impl std::fmt::Display for ActivityFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::All => "all",
            Self::Active => "active",
            Self::Idle => "idle",
        })
    }
}

#[derive(Debug, Clone, Default)]
struct GemSearch {
    query: String,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct AddModal {
    scope: DirectionScope,
    gem_ports: String,
    flow_id: String,
    flow_type: FlowType,
    multicast: bool,
    aes: bool,
    focused: usize,
    error: Option<String>,
}

impl Default for AddModal {
    fn default() -> Self {
        Self {
            scope: DirectionScope::Downstream,
            gem_ports: String::new(),
            flow_id: "auto".into(),
            flow_type: FlowType::Ethernet,
            multicast: false,
            aes: false,
            focused: 0,
            error: None,
        }
    }
}

impl AddModal {
    fn advance(&mut self, reverse: bool) {
        self.focused = if reverse {
            (self.focused + 5) % 6
        } else {
            (self.focused + 1) % 6
        };
    }

    fn toggle(&mut self) {
        match self.focused {
            0 => {
                self.scope = match self.scope {
                    DirectionScope::Downstream => DirectionScope::Upstream,
                    DirectionScope::Upstream => DirectionScope::Both,
                    DirectionScope::Both => DirectionScope::Downstream,
                }
            }
            3 => {
                self.flow_type = match self.flow_type {
                    FlowType::Ethernet => FlowType::Omci,
                    FlowType::Omci => FlowType::Ethernet,
                }
            }
            4 => self.multicast = !self.multicast,
            5 => self.aes = !self.aes,
            _ => {}
        }
    }

    fn edit(&mut self, character: char) {
        match self.focused {
            1 => self.gem_ports.push(character),
            2 => {
                if self.flow_id.eq_ignore_ascii_case("auto") {
                    self.flow_id.clear();
                }
                self.flow_id.push(character);
            }
            _ => self.toggle(),
        }
    }

    fn backspace(&mut self) {
        match self.focused {
            1 => {
                self.gem_ports.pop();
            }
            2 => {
                self.flow_id.pop();
                if self.flow_id.is_empty() {
                    self.flow_id = "auto".into();
                }
            }
            _ => {}
        }
    }

    fn request(&self) -> Result<AddFlowRequest, String> {
        let gem_ports = parse_selection_expression(&self.gem_ports, 0, 4095)
            .map_err(|error| error.to_string())?;
        let flow_ids = if self.flow_id.trim().eq_ignore_ascii_case("auto") {
            FlowIdChoice::Auto
        } else {
            let id = self
                .flow_id
                .trim()
                .parse::<u8>()
                .map_err(|_| "flow ID must be `auto` or 0..=127".to_owned())?;
            if id > 127 {
                return Err("flow ID must be `auto` or 0..=127".into());
            }
            FlowIdChoice::Exact(id)
        };
        let request = AddFlowRequest {
            scope: self.scope,
            flow_ids,
            gem_ports,
            flow_type: self.flow_type,
            multicast: self.multicast,
            aes: self.aes,
        };
        request.validate().map_err(|error| error.to_string())?;
        Ok(request)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Monitor,
    Autoscan,
    Mib,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MibPane {
    Tables,
    Entities,
    Attributes,
}

impl MibPane {
    fn next(self) -> Self {
        match self {
            Self::Tables => Self::Entities,
            Self::Entities => Self::Attributes,
            Self::Attributes => Self::Tables,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Tables => Self::Attributes,
            Self::Entities => Self::Tables,
            Self::Attributes => Self::Entities,
        }
    }
}

#[derive(Debug, Clone)]
enum MibInputKind {
    Search(MibPane),
    Lookup,
}

#[derive(Debug, Clone)]
struct MibInput {
    kind: MibInputKind,
    value: String,
    error: Option<String>,
}

struct MibView {
    catalog: Vec<MibTableDescriptor>,
    catalog_loaded: bool,
    snapshots: BTreeMap<MibQuery, MibTableSnapshot>,
    active_query: Option<MibQuery>,
    selected_table: Option<u16>,
    selected_entity: Option<u16>,
    selected_attribute: Option<usize>,
    pane: MibPane,
    table_filter: String,
    attribute_filter: String,
    raw: bool,
    raw_scroll: u16,
    loading: bool,
    error: Option<String>,
    input: Option<MibInput>,
}

impl Default for MibView {
    fn default() -> Self {
        Self {
            catalog: Vec::new(),
            catalog_loaded: false,
            snapshots: BTreeMap::new(),
            active_query: None,
            selected_table: None,
            selected_entity: None,
            selected_attribute: None,
            pane: MibPane::Tables,
            table_filter: String::new(),
            attribute_filter: String::new(),
            raw: false,
            raw_scroll: 0,
            loading: false,
            error: None,
            input: None,
        }
    }
}

#[derive(Debug, Clone)]
struct AutoscanForm {
    gem_start: String,
    gem_end: String,
    batch_size: String,
    observation_secs: String,
    aes: bool,
    focused: usize,
    error: Option<String>,
}

impl Default for AutoscanForm {
    fn default() -> Self {
        Self {
            gem_start: "0".into(),
            gem_end: "4095".into(),
            batch_size: "128".into(),
            observation_secs: "5".into(),
            aes: false,
            focused: 0,
            error: None,
        }
    }
}

impl AutoscanForm {
    fn advance(&mut self, reverse: bool) {
        self.focused = if reverse {
            (self.focused + 4) % 5
        } else {
            (self.focused + 1) % 5
        };
    }

    fn edit(&mut self, character: char) {
        let field = match self.focused {
            0 => &mut self.gem_start,
            1 => &mut self.gem_end,
            2 => &mut self.batch_size,
            3 => &mut self.observation_secs,
            4 => {
                self.aes = !self.aes;
                return;
            }
            _ => return,
        };
        if character.is_ascii_digit() || (self.focused == 3 && character == '.') {
            field.push(character);
        }
        self.error = None;
    }

    fn backspace(&mut self) {
        match self.focused {
            0 => {
                self.gem_start.pop();
            }
            1 => {
                self.gem_end.pop();
            }
            2 => {
                self.batch_size.pop();
            }
            3 => {
                self.observation_secs.pop();
            }
            _ => {}
        }
        self.error = None;
    }

    fn config(&self) -> Result<AutoscanConfig, String> {
        let config = AutoscanConfig {
            gem_start: self
                .gem_start
                .parse()
                .map_err(|_| "GEM start must be 0..=4095".to_owned())?,
            gem_end: self
                .gem_end
                .parse()
                .map_err(|_| "GEM end must be 0..=4095".to_owned())?,
            batch_size: self
                .batch_size
                .parse()
                .map_err(|_| "batch size must be 1..=128".to_owned())?,
            observation_secs: self
                .observation_secs
                .parse()
                .map_err(|_| "observation window must be a number".to_owned())?,
            aes: self.aes,
        };
        config.validate().map_err(|error| error.to_string())?;
        Ok(config)
    }
}

#[derive(Debug, Clone)]
struct ExportModal {
    path: String,
    error: Option<String>,
}

#[derive(Default)]
struct AutoscanView {
    form: AutoscanForm,
    running: bool,
    progress: Option<ScanProgress>,
    live_activities: Vec<gpwn_scan::GemPortActivity>,
    result: Option<AutoscanResult>,
    recovery: Option<Vec<gpwn_core::DownstreamFlow>>,
    recovery_endpoint: Option<String>,
    recovery_abandoned: bool,
    cancel: Option<CancellationToken>,
    selected_gem: Option<u16>,
    show_all: bool,
    capacity_selecting: bool,
    apply_selected: BTreeSet<u16>,
    apply_busy: bool,
    awaiting_refresh: bool,
    last_apply: Option<ApplyResult>,
    export_modal: Option<ExportModal>,
}

/// Downstream traffic rate observed by the counter sampler, used to size a
/// capture before starting it.
#[derive(Debug, Clone, Copy, PartialEq)]
struct TrafficRate {
    packets_per_second: f64,
    average_frame: f64,
}

/// Field order within the wizard. `Directory` is called out because editing it
/// invalidates the cached free-space reading.
const CAPTURE_FIELDS: usize = 4;
const CAPTURE_FIELD_DIRECTORY: usize = 1;

struct CaptureModal {
    interfaces: Vec<InterfaceInfo>,
    /// Held by name rather than index, so filtering the list cannot silently
    /// move the selection — the same reason flows and GEM ports are tracked by
    /// identity elsewhere in this app.
    selected: String,
    show_all: bool,
    directory: String,
    duration: String,
    filter: String,
    focused: usize,
    /// Both sampled when the wizard opens: nothing can change the flow table
    /// while it holds focus, and re-reading either per frame would put a
    /// syscall on the draw path.
    rate: Option<TrafficRate>,
    free_space: Option<u64>,
    configured_flows: usize,
    error: Option<String>,
}

impl CaptureModal {
    fn visible(&self) -> impl Iterator<Item = &InterfaceInfo> {
        self.interfaces
            .iter()
            .filter(move |interface| self.show_all || !interface.is_uninteresting())
    }

    fn current_interface(&self) -> Option<&InterfaceInfo> {
        self.visible()
            .find(|interface| interface.name == self.selected)
            .or_else(|| self.visible().next())
    }

    fn cycle_interface(&mut self, delta: isize) {
        let names: Vec<_> = self.visible().map(|interface| &interface.name).collect();
        let Some(current) = self
            .current_interface()
            .map(|interface| interface.name.clone())
        else {
            return;
        };
        let index = names
            .iter()
            .position(|name| **name == current)
            .unwrap_or_default() as isize;
        self.selected = names[(index + delta).rem_euclid(names.len() as isize) as usize].clone();
    }

    fn advance(&mut self, reverse: bool) {
        self.focused = if reverse {
            (self.focused + CAPTURE_FIELDS - 1) % CAPTURE_FIELDS
        } else {
            (self.focused + 1) % CAPTURE_FIELDS
        };
    }

    fn field_mut(&mut self) -> Option<&mut String> {
        match self.focused {
            CAPTURE_FIELD_DIRECTORY => Some(&mut self.directory),
            2 => Some(&mut self.duration),
            3 => Some(&mut self.filter),
            _ => None,
        }
    }

    fn refresh_free_space(&mut self) {
        self.free_space = free_space(Path::new(self.directory.trim())).ok();
    }

    /// `None` records until stopped.
    fn parsed_duration(&self) -> Result<Option<Duration>, &'static str> {
        let text = self.duration.trim();
        if text.is_empty() {
            return Ok(None);
        }
        let seconds: u64 = text
            .parse()
            .map_err(|_| "duration must be a whole number of seconds")?;
        Ok((seconds > 0).then(|| Duration::from_secs(seconds)))
    }

    fn estimate(&self, duration: Option<Duration>) -> Option<u64> {
        let rate = self.rate?;
        Some(estimate_bytes(
            rate.packets_per_second,
            rate.average_frame,
            duration?,
        ))
    }

    /// Refuse a capture the filesystem cannot hold. Only possible with a
    /// bounded duration — an open-ended capture has no size to compare.
    fn capacity_error(&self, duration: Option<Duration>) -> Option<String> {
        let (estimate, free) = (self.estimate(duration)?, self.free_space?);
        (estimate > free).then(|| {
            format!(
                "estimated {} exceeds {} free on {}",
                human_bytes(estimate as f64),
                human_bytes(free as f64),
                self.directory.trim()
            )
        })
    }

    fn config(&self) -> Result<CaptureConfig, String> {
        let config = CaptureConfig {
            interface: self
                .current_interface()
                .map(|interface| interface.name.clone())
                .unwrap_or_default(),
            output_dir: PathBuf::from(self.directory.trim()),
            duration: self.parsed_duration()?,
            filter: Some(self.filter.clone()),
        };
        config.validate().map_err(|error| error.to_string())?;
        Ok(config)
    }
}

struct ActiveCapture {
    path: PathBuf,
    /// Exactly what `dumpcap` was started with, so the sidecar reports the
    /// settings that were applied rather than whatever the wizard held.
    config: CaptureConfig,
    started_at: Instant,
    started_wall: SystemTime,
    bytes: u64,
    /// The flow table the ONU was forwarding when recording began. Without it
    /// the capture is an anonymous blob — nothing in a frame names its GEM port.
    downstream_at_start: Vec<gpwn_core::DownstreamFlow>,
    line_at_start: Option<gpwn_core::LineStatus>,
    /// Restored when the capture ends.
    sampling_was_paused: bool,
}

/// Carried between captures in a session so the wizard reopens where it was
/// left. `duration` stays as typed text rather than a parsed value to preserve
/// exactly what was entered.
struct CaptureDefaults {
    directory: String,
    duration: String,
    interface: Option<String>,
}

impl Default for CaptureDefaults {
    fn default() -> Self {
        Self {
            directory: "./captures".into(),
            duration: "60".into(),
            interface: None,
        }
    }
}

#[derive(Default)]
struct CaptureView {
    modal: Option<CaptureModal>,
    active: Option<ActiveCapture>,
    stopping: bool,
    defaults: CaptureDefaults,
}

/// Written next to each pcapng. `DownstreamFlow`, `LineStatus`, and
/// `ConnectionInfo` already serialize, so this costs almost nothing.
#[derive(Serialize)]
struct CaptureSidecar<'a> {
    schema_version: u8,
    pcap: Option<&'a str>,
    interface: &'a str,
    filter: Option<&'a str>,
    started_at_unix: u64,
    duration_secs: f64,
    bytes: u64,
    stop_reason: StopReason,
    connection: Option<&'a ConnectionInfo>,
    line: Option<&'a gpwn_core::LineStatus>,
    downstream_at_start: &'a [gpwn_core::DownstreamFlow],
}

#[derive(Debug, Clone)]
enum ConfirmAction {
    DeleteOne { scope: DirectionScope, flow_id: u8 },
    DeleteAll { scope: DirectionScope },
    Setup,
    StartScan(AutoscanConfig),
    ApplyActive(Vec<u16>),
    AbandonRecovery,
}

struct App {
    connection_form: ConnectionForm,
    show_connection: bool,
    connected: Option<ConnectionInfo>,
    snapshot: Option<OnuSnapshot>,
    snapshot_stale: bool,
    samples: BTreeMap<u8, SampleView>,
    page: Page,
    autoscan: AutoscanView,
    mib: MibView,
    capture: CaptureView,
    pane: Pane,
    activity_filter: ActivityFilter,
    ds_selected: Option<u8>,
    us_selected: Option<u8>,
    poll_interval: Duration,
    next_sweep: Instant,
    sampling_paused: bool,
    sampling_pending: usize,
    status: String,
    logs: Vec<String>,
    show_logs: bool,
    show_help: bool,
    add_modal: Option<AddModal>,
    search_modal: Option<GemSearch>,
    confirm: Option<ConfirmAction>,
    should_quit: bool,
    quit_after_scan: bool,
    quit_after_capture: bool,
    high_tx: mpsc::Sender<BackendCommand>,
    sample_tx: mpsc::Sender<SampleCommand>,
    capture_tx: mpsc::Sender<CaptureCommand>,
}

impl App {
    fn new(
        form: ConnectionForm,
        high_tx: mpsc::Sender<BackendCommand>,
        sample_tx: mpsc::Sender<SampleCommand>,
        capture_tx: mpsc::Sender<CaptureCommand>,
    ) -> Self {
        let poll_interval =
            Duration::from_secs(form.poll_interval.parse::<u64>().unwrap_or(10).max(1));
        Self {
            connection_form: form,
            show_connection: true,
            connected: None,
            snapshot: None,
            snapshot_stale: false,
            samples: BTreeMap::new(),
            page: Page::Monitor,
            autoscan: AutoscanView::default(),
            mib: MibView::default(),
            capture: CaptureView::default(),
            pane: Pane::Downstream,
            activity_filter: ActivityFilter::All,
            ds_selected: None,
            us_selected: None,
            poll_interval,
            next_sweep: Instant::now(),
            sampling_paused: false,
            sampling_pending: 0,
            status: "Configure a backend and press Enter to connect".into(),
            logs: Vec::new(),
            show_logs: false,
            show_help: false,
            add_modal: None,
            search_modal: None,
            confirm: None,
            should_quit: false,
            quit_after_scan: false,
            quit_after_capture: false,
            high_tx,
            sample_tx,
            capture_tx,
        }
    }

    fn log(&mut self, message: impl Into<String>) {
        let message = message.into();
        self.status = message.clone();
        self.logs.push(message);
        if self.logs.len() > 200 {
            self.logs.drain(..50);
        }
    }

    fn handle_backend_event(&mut self, event: BackendEvent) {
        match event {
            BackendEvent::Connecting => {
                self.connection_form.connecting = true;
                self.connection_form.error = None;
                self.log("Connecting…");
            }
            BackendEvent::Connected(info) => {
                self.connection_form.connecting = false;
                self.show_connection = false;
                self.poll_interval = Duration::from_secs(
                    self.connection_form
                        .poll_interval
                        .parse::<u64>()
                        .unwrap_or(10)
                        .max(1),
                );
                self.log(format!("Connected to {}", info.endpoint));
                self.connected = Some(info);
                self.mib = MibView::default();
                self.snapshot_stale = false;
                self.next_sweep = Instant::now();
                if self.page == Page::Mib {
                    self.request_mib_catalog();
                }
            }
            BackendEvent::Snapshot(snapshot) => {
                let initialize_selection = self.snapshot.is_none();
                self.snapshot = Some(snapshot);
                self.snapshot_stale = false;
                self.autoscan.awaiting_refresh = false;
                self.reconcile_selections(initialize_selection);
                self.remove_orphan_samples();
                self.log("Line and flow configuration refreshed");
            }
            BackendEvent::Sample { counters, at } => {
                let interval = self
                    .samples
                    .get(&counters.flow_id)
                    .map(|previous| at.saturating_duration_since(previous.sampled_at));
                self.samples.insert(
                    counters.flow_id,
                    SampleView {
                        counters,
                        interval,
                        sampled_at: at,
                    },
                );
                self.sampling_pending = self.sampling_pending.saturating_sub(1);
                self.reconcile_selections(false);
            }
            BackendEvent::Report { operation, report } => {
                let succeeded = report.steps.iter().filter(|step| step.success).count();
                let failed = report.steps.len().saturating_sub(succeeded);
                self.log(format!(
                    "{operation}: {succeeded} completed, {failed} failed"
                ));
                for step in report.steps {
                    self.logs.push(format!(
                        "{}: {} — {}",
                        if step.success { "ok" } else { "FAILED" },
                        step.description,
                        step.message
                    ));
                }
            }
            BackendEvent::ScanProgress(progress) => {
                self.snapshot_stale = true;
                self.status = format!(
                    "Autoscan {} — batch {}/{} — {}",
                    progress.phase,
                    (progress.batch_index + 1).min(progress.total_batches),
                    progress.total_batches,
                    progress.message
                );
                if let Some(activity) = &progress.activity {
                    self.autoscan.live_activities.push(activity.clone());
                    if activity.is_active() && self.autoscan.selected_gem.is_none() {
                        self.autoscan.selected_gem = Some(activity.gem_port);
                    }
                }
                self.autoscan.progress = Some(progress);
            }
            BackendEvent::ScanFinished(outcome) => {
                self.autoscan.running = false;
                self.autoscan.cancel = None;
                self.autoscan.recovery = outcome
                    .result
                    .restore_error
                    .is_some()
                    .then_some(outcome.original_downstream);
                self.autoscan.recovery_endpoint = self
                    .autoscan
                    .recovery
                    .as_ref()
                    .and_then(|_| self.connected.as_ref().map(|info| info.endpoint.clone()));
                self.autoscan.recovery_abandoned = false;
                self.autoscan.selected_gem = outcome
                    .result
                    .active_ports()
                    .first()
                    .map(|row| row.gem_port);
                self.autoscan.awaiting_refresh = outcome.result.restore_error.is_none();
                self.snapshot_stale = true;
                self.log(format!(
                    "Autoscan {}: {} scanned, {} active{}",
                    outcome.result.terminal_phase,
                    outcome.result.scanned_count(),
                    outcome.result.active_ports().len(),
                    outcome
                        .result
                        .restore_error
                        .as_ref()
                        .map(|error| format!("; RESTORE PENDING: {error}"))
                        .unwrap_or_default()
                ));
                self.autoscan.result = Some(outcome.result);
                if self.quit_after_scan && self.autoscan.recovery.is_none() {
                    self.request_quit();
                }
            }
            BackendEvent::RestoreRetried { result } => match result {
                Ok(()) => {
                    self.autoscan.recovery = None;
                    self.autoscan.recovery_endpoint = None;
                    if let Some(result) = self.autoscan.result.as_mut() {
                        result.restore_error = None;
                        if result.terminal_phase == AutoscanPhase::RestorePending {
                            result.terminal_phase = if result.error.is_some() {
                                AutoscanPhase::Failed
                            } else {
                                AutoscanPhase::Completed
                            };
                        }
                    }
                    self.autoscan.awaiting_refresh = true;
                    self.snapshot_stale = true;
                    self.log("Original downstream table restored");
                    if self.quit_after_scan {
                        self.request_quit();
                    }
                }
                Err(error) => self.log(format!("Restore retry failed: {error}")),
            },
            BackendEvent::ActiveApplied(result) => {
                self.autoscan.apply_busy = false;
                self.autoscan.awaiting_refresh = true;
                self.snapshot_stale = true;
                self.log(format!(
                    "Autoscan apply: {} added, {} rolled back{}",
                    result.added.len(),
                    result.rolled_back.len(),
                    result
                        .error
                        .as_ref()
                        .map(|error| format!(" — {error}"))
                        .unwrap_or_default()
                ));
                self.autoscan.last_apply = Some(result);
                self.autoscan.capacity_selecting = false;
                self.autoscan.apply_selected.clear();
            }
            BackendEvent::MibCatalog(mut tables) => {
                tables.sort_by_key(|table| table.internal_id);
                self.mib.loading = false;
                self.mib.catalog_loaded = true;
                self.mib.error = None;
                let previous = self.mib.selected_table;
                self.mib.catalog = tables;
                let visible = self.mib_visible_table_ids();
                self.mib.selected_table = previous
                    .filter(|id| visible.contains(id))
                    .or_else(|| visible.first().copied());
                self.log(format!(
                    "Loaded {} registered OMCI MIB tables",
                    self.mib.catalog.len()
                ));
            }
            BackendEvent::MibSnapshot(snapshot) => {
                self.mib.loading = false;
                self.mib.error = None;
                let previous_entity = self.mib.selected_entity;
                let query = snapshot.query.clone();
                let table_name = snapshot.table_name.clone();
                let entity_ids: Vec<_> = snapshot
                    .entities
                    .iter()
                    .map(|entity| entity.entity_id)
                    .collect();
                self.mib.selected_entity = previous_entity
                    .filter(|id| entity_ids.contains(id))
                    .or(query.entity_id.filter(|id| entity_ids.contains(id)))
                    .or_else(|| entity_ids.first().copied());
                self.mib.selected_attribute = Some(0);
                self.mib.raw_scroll = 0;
                self.mib.snapshots.insert(query.clone(), snapshot);
                self.mib.active_query = Some(query);
                self.log(format!(
                    "Loaded {table_name}: {} entities",
                    entity_ids.len()
                ));
            }
            BackendEvent::CaptureStarted { path, config } => {
                // Pause the sampler for the duration: its SSH traffic shares the
                // link being captured, and a saturated link can starve it.
                let sampling_was_paused = self.sampling_paused;
                self.sampling_paused = true;
                self.log(format!("Recording to {}", path.display()));
                self.capture.active = Some(ActiveCapture {
                    path,
                    config,
                    started_at: Instant::now(),
                    started_wall: SystemTime::now(),
                    bytes: 0,
                    downstream_at_start: self
                        .snapshot
                        .as_ref()
                        .map(|snapshot| snapshot.downstream.clone())
                        .unwrap_or_default(),
                    line_at_start: self.snapshot.as_ref().map(|snapshot| snapshot.line.clone()),
                    sampling_was_paused,
                });
                self.capture.modal = None;
            }
            BackendEvent::CaptureProgress { bytes } => {
                if let Some(active) = self.capture.active.as_mut() {
                    active.bytes = bytes;
                }
            }
            BackendEvent::CaptureStopped(summary) => {
                let sidecar = self
                    .finish_capture()
                    .map(|active| self.write_capture_sidecar(&active, &summary));
                self.log(format!(
                    "Capture saved: {} ({}, {:.1}s){}",
                    summary.path.display(),
                    human_bytes(summary.bytes as f64),
                    summary.duration.as_secs_f64(),
                    match sidecar {
                        Some(Err(error)) => format!(" — sidecar not written: {error}"),
                        _ => String::new(),
                    }
                ));
            }
            BackendEvent::CaptureFailed { message } => {
                // A mid-capture failure still leaves bytes on disk; say where.
                let partial = self
                    .finish_capture()
                    .filter(|active| active.path.exists())
                    .map(|active| format!(" — partial capture left at {}", active.path.display()))
                    .unwrap_or_default();
                self.log(format!("Capture failed: {message}{partial}"));
            }
            BackendEvent::Error {
                operation,
                message,
                disconnected,
            } => {
                self.connection_form.connecting = false;
                self.connection_form.error = Some(message.clone());
                self.log(format!("{operation}: {message}"));
                if operation == "apply autoscan results" {
                    self.autoscan.apply_busy = false;
                }
                if operation == "load MIB catalog" || operation == "load MIB table" {
                    self.mib.loading = false;
                    self.mib.error = Some(message.clone());
                }
                if disconnected {
                    self.connected = None;
                    self.show_connection = true;
                    self.snapshot_stale = self.snapshot.is_some();
                    self.sampling_pending = 0;
                }
            }
        }
    }

    fn remove_orphan_samples(&mut self) {
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        let ids: BTreeSet<_> = snapshot
            .downstream
            .iter()
            .map(|flow| flow.flow_id)
            .chain(snapshot.upstream.iter().map(|flow| flow.flow_id))
            .collect();
        self.samples.retain(|id, _| ids.contains(id));
    }

    fn reconcile_selections(&mut self, initialize: bool) {
        let Some(snapshot) = &self.snapshot else {
            self.ds_selected = None;
            self.us_selected = None;
            return;
        };
        let ds_all: Vec<_> = snapshot
            .downstream
            .iter()
            .map(|flow| flow.flow_id)
            .collect();
        let ds_visible: BTreeSet<_> = snapshot
            .downstream
            .iter()
            .filter(|flow| self.flow_visible(Pane::Downstream, flow.flow_id))
            .map(|flow| flow.flow_id)
            .collect();
        let us_all: Vec<_> = snapshot.upstream.iter().map(|flow| flow.flow_id).collect();
        let us_visible: BTreeSet<_> = snapshot
            .upstream
            .iter()
            .filter(|flow| self.flow_visible(Pane::Upstream, flow.flow_id))
            .map(|flow| flow.flow_id)
            .collect();
        self.ds_selected =
            reconcile_filtered_selection(self.ds_selected, &ds_all, &ds_visible, initialize);
        self.us_selected =
            reconcile_filtered_selection(self.us_selected, &us_all, &us_visible, initialize);
    }

    fn start_sweep_if_due(&mut self) {
        if self.connected.is_none()
            || self.sampling_paused
            || self.backend_locked()
            || self.sampling_pending != 0
            || Instant::now() < self.next_sweep
        {
            return;
        }
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        let ids: BTreeSet<_> = snapshot
            .downstream
            .iter()
            .map(|flow| flow.flow_id)
            .chain(snapshot.upstream.iter().map(|flow| flow.flow_id))
            .collect();
        self.sampling_pending = ids.len();
        for id in ids {
            if self.sample_tx.try_send(SampleCommand::Read(id)).is_err() {
                self.sampling_pending = self.sampling_pending.saturating_sub(1);
            }
        }
        self.next_sweep = Instant::now() + self.poll_interval;
    }

    fn send_high(&mut self, command: BackendCommand) {
        if self.high_tx.try_send(command).is_err() {
            self.log("Command queue is busy; try again");
        }
    }

    fn backend_locked(&self) -> bool {
        self.autoscan.running
            || self.autoscan.recovery.is_some()
            || self.autoscan.apply_busy
            || self.autoscan.awaiting_refresh
            || self.mib.loading
    }

    /// Aggregate downstream rate across configured flows.
    ///
    /// Packets come from the forwarded Ethernet counter rather than the GEM
    /// counter: forwarded is post-filter, so it reflects what actually leaves
    /// the ONU and reaches the capture interface.
    fn downstream_rate(&self) -> Option<TrafficRate> {
        let snapshot = self.snapshot.as_ref()?;
        let mut packets_per_second = 0.0;
        let mut bytes_per_second = 0.0;
        let mut gem_packets_per_second = 0.0;
        let mut sampled = false;
        for flow in &snapshot.downstream {
            let Some(sample) = self.samples.get(&flow.flow_id) else {
                continue;
            };
            let Some(interval) = sample.interval.filter(|interval| !interval.is_zero()) else {
                continue;
            };
            let seconds = interval.as_secs_f64();
            sampled = true;
            packets_per_second += sample.counters.ds_fwd_eth_packets as f64 / seconds;
            bytes_per_second += sample.counters.ds_gem_bytes as f64 / seconds;
            gem_packets_per_second += sample.counters.ds_gem_packets as f64 / seconds;
        }
        sampled.then(|| TrafficRate {
            packets_per_second,
            average_frame: if gem_packets_per_second > 0.0 {
                bytes_per_second / gem_packets_per_second
            } else {
                0.0
            },
        })
    }

    fn toggle_capture(&mut self) {
        if self.capture.active.is_some() {
            self.stop_capture();
        } else if self.capture.modal.is_none() {
            self.open_capture_modal();
        }
    }

    fn open_capture_modal(&mut self) {
        let interfaces = match gpwn_capture::interfaces() {
            Ok(interfaces) => interfaces,
            Err(error) => {
                self.log(error.to_string());
                return;
            }
        };
        let mut modal = CaptureModal {
            interfaces,
            // Reopen on whichever interface was used last; `current_interface`
            // falls back to the first visible one when it is gone.
            selected: self.capture.defaults.interface.clone().unwrap_or_default(),
            show_all: false,
            directory: self.capture.defaults.directory.clone(),
            duration: self.capture.defaults.duration.clone(),
            filter: self
                .connected
                .as_ref()
                .and_then(|info| management_filter(&info.endpoint))
                .unwrap_or_default(),
            focused: 0,
            rate: self.downstream_rate(),
            free_space: None,
            configured_flows: self
                .snapshot
                .as_ref()
                .map(|snapshot| snapshot.downstream.len())
                .unwrap_or(0),
            error: None,
        };
        if modal.visible().next().is_none() {
            modal.show_all = true;
        }
        modal.refresh_free_space();
        self.capture.modal = Some(modal);
    }

    fn start_capture(&mut self) {
        let Some(modal) = self.capture.modal.as_ref() else {
            return;
        };
        let prepared =
            modal
                .config()
                .and_then(|config| match modal.capacity_error(config.duration) {
                    Some(message) => Err(message),
                    None => Ok(config),
                });
        let config = match prepared {
            Ok(config) => config,
            Err(message) => {
                if let Some(modal) = self.capture.modal.as_mut() {
                    modal.error = Some(message);
                }
                return;
            }
        };
        self.capture.defaults = CaptureDefaults {
            directory: modal.directory.trim().to_owned(),
            duration: modal.duration.trim().to_owned(),
            interface: Some(config.interface.clone()),
        };
        if self
            .capture_tx
            .try_send(CaptureCommand::Start(config))
            .is_err()
        {
            self.log("Capture worker is busy; try again");
        }
    }

    /// Quitting must not orphan a running `dumpcap`, so stop it first and let
    /// the resulting event finish the shutdown. A second request gives up
    /// waiting; the worker and `Capture`'s own `Drop` remain as backstops.
    fn request_quit(&mut self) {
        if self.capture.active.is_some() && !self.quit_after_capture {
            self.quit_after_capture = true;
            self.stop_capture();
            self.log("Stopping capture before quitting; press again to force quit");
            return;
        }
        self.should_quit = true;
    }

    fn stop_capture(&mut self) {
        if self.capture.active.is_none() || self.capture.stopping {
            return;
        }
        if self.capture_tx.try_send(CaptureCommand::Stop).is_err() {
            self.log("Capture worker is busy; try again");
            return;
        }
        self.capture.stopping = true;
        self.log("Stopping capture…");
    }

    /// Returns the finished capture so callers cannot read its state after it
    /// has been cleared.
    fn finish_capture(&mut self) -> Option<ActiveCapture> {
        self.capture.stopping = false;
        let active = self.capture.active.take();
        if let Some(active) = active.as_ref() {
            self.sampling_paused = active.sampling_was_paused;
            self.next_sweep = Instant::now();
        }
        if self.quit_after_capture {
            self.should_quit = true;
        }
        active
    }

    /// The pcap alone records nothing about what the ONU was forwarding, and no
    /// frame carries its GEM port, so the flow table is written beside it.
    fn write_capture_sidecar(
        &self,
        active: &ActiveCapture,
        summary: &CaptureSummary,
    ) -> io::Result<()> {
        write_json_new(
            &summary.path.with_extension("json"),
            &CaptureSidecar {
                schema_version: 1,
                pcap: summary.path.file_name().and_then(|name| name.to_str()),
                interface: &active.config.interface,
                // The filter as `dumpcap` received it, not as the wizard held it.
                filter: active.config.effective_filter(),
                started_at_unix: active
                    .started_wall
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                duration_secs: summary.duration.as_secs_f64(),
                bytes: summary.bytes,
                stop_reason: summary.stop_reason,
                connection: self.connected.as_ref(),
                line: active.line_at_start.as_ref(),
                downstream_at_start: &active.downstream_at_start,
            },
        )
    }

    fn request_mib_catalog(&mut self) {
        if self.connected.is_none() {
            self.log("Connect to an ONU before browsing the MIB");
        } else if self.autoscan.running || self.autoscan.recovery.is_some() {
            self.log("MIB access is unavailable while autoscan or recovery is active");
        } else if !self.mib.loading {
            self.mib.loading = true;
            self.mib.error = None;
            self.log("Loading OMCI MIB catalog…");
            self.send_high(BackendCommand::MibCatalog);
        }
    }

    fn request_mib_snapshot(&mut self, query: MibQuery) {
        if self.connected.is_none() {
            self.log("Connect to an ONU before browsing the MIB");
        } else if self.autoscan.running || self.autoscan.recovery.is_some() {
            self.log("MIB access is unavailable while autoscan or recovery is active");
        } else if !self.mib.loading {
            self.mib.loading = true;
            self.mib.error = None;
            self.log(format!(
                "Loading OMCI MIB selector {}…",
                query.selector.command_value()
            ));
            self.send_high(BackendCommand::MibFetch(query));
        }
    }

    fn mib_visible_table_ids(&self) -> Vec<u16> {
        let needle = self.mib.table_filter.to_ascii_lowercase();
        self.mib
            .catalog
            .iter()
            .filter(|table| {
                needle.is_empty()
                    || table.name.to_ascii_lowercase().contains(&needle)
                    || table.internal_id.to_string().contains(&needle)
            })
            .map(|table| table.internal_id)
            .collect()
    }

    fn selected_mib_table(&self) -> Option<&MibTableDescriptor> {
        let id = self.mib.selected_table?;
        self.mib
            .catalog
            .iter()
            .find(|table| table.internal_id == id)
    }

    fn active_mib_snapshot(&self) -> Option<&MibTableSnapshot> {
        self.mib
            .active_query
            .as_ref()
            .and_then(|query| self.mib.snapshots.get(query))
    }

    fn selected_mib_entity(&self) -> Option<&gpwn_core::MibEntity> {
        let id = self.mib.selected_entity?;
        self.active_mib_snapshot()?
            .entities
            .iter()
            .find(|entity| entity.entity_id == id)
    }

    fn mib_attribute_indices(&self) -> Vec<usize> {
        let needle = self.mib.attribute_filter.to_ascii_lowercase();
        self.selected_mib_entity()
            .map(|entity| {
                entity
                    .attributes
                    .iter()
                    .enumerate()
                    .filter(|(_, attribute)| {
                        needle.is_empty()
                            || attribute.name.to_ascii_lowercase().contains(&needle)
                            || attribute.value.to_ascii_lowercase().contains(&needle)
                    })
                    .map(|(index, _)| index)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn move_mib_selection(&mut self, delta: isize) {
        match self.mib.pane {
            MibPane::Tables => {
                let rows = self.mib_visible_table_ids();
                self.mib.selected_table = move_identity(self.mib.selected_table, &rows, delta);
            }
            MibPane::Entities => {
                let rows: Vec<_> = self
                    .active_mib_snapshot()
                    .map(|snapshot| {
                        snapshot
                            .entities
                            .iter()
                            .map(|entity| entity.entity_id)
                            .collect()
                    })
                    .unwrap_or_default();
                self.mib.selected_entity = move_identity(self.mib.selected_entity, &rows, delta);
                self.mib.selected_attribute = self.mib_attribute_indices().first().copied();
            }
            MibPane::Attributes if self.mib.raw => {
                self.mib.raw_scroll = if delta < 0 {
                    self.mib
                        .raw_scroll
                        .saturating_sub(delta.unsigned_abs() as u16)
                } else {
                    self.mib.raw_scroll.saturating_add(delta as u16)
                };
            }
            MibPane::Attributes => {
                let rows = self.mib_attribute_indices();
                self.mib.selected_attribute =
                    move_identity(self.mib.selected_attribute, &rows, delta);
            }
        }
    }

    fn load_selected_mib_table(&mut self) {
        let Some(name) = self.selected_mib_table().map(|table| table.name.clone()) else {
            self.log("Select a MIB table first");
            return;
        };
        let Some(class_id) = omci_class_id_for_table(&name) else {
            self.log(format!(
                "OMCI class ID for {name} is unknown; press g and enter its numeric class ID"
            ));
            return;
        };
        self.request_mib_snapshot(MibQuery {
            selector: MibSelector::ClassId(class_id),
            entity_id: None,
        });
    }

    fn parse_mib_lookup(&self, value: &str) -> Result<MibQuery, String> {
        let mut parts = value
            .split([',', ' '])
            .filter(|part| !part.trim().is_empty());
        let selector_text = parts
            .next()
            .ok_or_else(|| "enter a table name or OMCI class ID".to_owned())?;
        let selector = parse_mib_number(selector_text).map_or_else(
            || {
                let canonical = self
                    .mib
                    .catalog
                    .iter()
                    .find(|table| table.name.eq_ignore_ascii_case(selector_text))
                    .map(|table| table.name.clone())
                    .unwrap_or_else(|| selector_text.to_owned());
                omci_class_id_for_table(&canonical)
                    .map(MibSelector::ClassId)
                    .unwrap_or(MibSelector::TableName(canonical))
            },
            MibSelector::ClassId,
        );
        let entity_id = parts
            .next()
            .map(|part| {
                parse_mib_number(part)
                    .ok_or_else(|| "entity ID must be decimal or 0x-prefixed hex".to_owned())
            })
            .transpose()?;
        if parts.next().is_some() {
            return Err("use: TABLE_OR_CLASS[,ENTITY]".into());
        }
        let query = MibQuery {
            selector,
            entity_id,
        };
        query.validate().map_err(|error| error.to_string())?;
        Ok(query)
    }

    fn handle_mib_input_key(&mut self, key: KeyEvent) {
        let Some(mut input) = self.mib.input.take() else {
            return;
        };
        match key.code {
            KeyCode::Esc => return,
            KeyCode::Backspace => {
                input.value.pop();
                input.error = None;
            }
            KeyCode::Enter => match input.kind {
                MibInputKind::Lookup => match self.parse_mib_lookup(input.value.trim()) {
                    Ok(query) => {
                        self.request_mib_snapshot(query);
                        return;
                    }
                    Err(error) => input.error = Some(error),
                },
                MibInputKind::Search(MibPane::Tables) => {
                    self.mib.table_filter = input.value.clone();
                    let rows = self.mib_visible_table_ids();
                    self.mib.selected_table = self
                        .mib
                        .selected_table
                        .filter(|id| rows.contains(id))
                        .or_else(|| rows.first().copied());
                    return;
                }
                MibInputKind::Search(MibPane::Entities) => {
                    let Some(id) = parse_mib_number(input.value.trim()) else {
                        input.error = Some("entity ID must be decimal or 0x-prefixed hex".into());
                        self.mib.input = Some(input);
                        return;
                    };
                    let found = self.active_mib_snapshot().is_some_and(|snapshot| {
                        snapshot.entities.iter().any(|e| e.entity_id == id)
                    });
                    if found {
                        self.mib.selected_entity = Some(id);
                        self.mib.selected_attribute = self.mib_attribute_indices().first().copied();
                        return;
                    }
                    input.error = Some(format!("entity 0x{id:04X} is not loaded"));
                }
                MibInputKind::Search(MibPane::Attributes) => {
                    self.mib.attribute_filter = input.value.clone();
                    self.mib.selected_attribute = self.mib_attribute_indices().first().copied();
                    return;
                }
            },
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                input.value.push(character);
                input.error = None;
            }
            _ => {}
        }
        self.mib.input = Some(input);
    }

    fn handle_mib_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.request_quit(),
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Char('e') => self.show_logs = !self.show_logs,
            KeyCode::Char('/') => {
                let value = match self.mib.pane {
                    MibPane::Tables => self.mib.table_filter.clone(),
                    MibPane::Attributes => self.mib.attribute_filter.clone(),
                    MibPane::Entities => String::new(),
                };
                self.mib.input = Some(MibInput {
                    kind: MibInputKind::Search(self.mib.pane),
                    value,
                    error: None,
                });
            }
            KeyCode::Char('g') => {
                self.mib.input = Some(MibInput {
                    kind: MibInputKind::Lookup,
                    value: String::new(),
                    error: None,
                })
            }
            KeyCode::Char('R') => self.request_mib_catalog(),
            KeyCode::Char('r') => {
                if let Some(query) = self.mib.active_query.clone() {
                    self.request_mib_snapshot(query);
                } else {
                    self.load_selected_mib_table();
                }
            }
            KeyCode::Char('v') => {
                self.mib.raw = !self.mib.raw;
                self.mib.raw_scroll = 0;
            }
            KeyCode::Enter | KeyCode::Char('l') => match self.mib.pane {
                MibPane::Tables => {
                    self.load_selected_mib_table();
                    self.mib.pane = MibPane::Entities;
                }
                MibPane::Entities => self.mib.pane = MibPane::Attributes,
                MibPane::Attributes => {}
            },
            KeyCode::Tab | KeyCode::Right => self.mib.pane = self.mib.pane.next(),
            KeyCode::BackTab | KeyCode::Left | KeyCode::Esc => {
                self.mib.pane = self.mib.pane.previous()
            }
            KeyCode::Down => self.move_mib_selection(1),
            KeyCode::Up => self.move_mib_selection(-1),
            KeyCode::Home => self.move_mib_selection(isize::MIN / 2),
            KeyCode::End => self.move_mib_selection(isize::MAX / 2),
            _ => {}
        }
    }

    fn autoscan_rows(&self) -> Vec<&gpwn_scan::GemPortActivity> {
        let rows: Box<dyn Iterator<Item = &gpwn_scan::GemPortActivity> + '_> =
            if let Some(result) = &self.autoscan.result {
                Box::new(result.activities())
            } else {
                Box::new(self.autoscan.live_activities.iter())
            };
        rows.filter(|row| self.autoscan.show_all || row.is_active())
            .collect()
    }

    fn move_autoscan_selection(&mut self, delta: isize) {
        let gems: Vec<_> = self
            .autoscan_rows()
            .into_iter()
            .map(|row| row.gem_port)
            .collect();
        if gems.is_empty() {
            self.autoscan.selected_gem = None;
            return;
        }
        let current = self
            .autoscan
            .selected_gem
            .and_then(|gem| gems.iter().position(|item| *item == gem));
        let next = current.map_or_else(
            || if delta < 0 { gems.len() - 1 } else { 0 },
            |index| (index as isize + delta).clamp(0, gems.len() as isize - 1) as usize,
        );
        self.autoscan.selected_gem = Some(gems[next]);
    }

    fn handle_autoscan_key(&mut self, key: KeyEvent) {
        if self.autoscan.running {
            match key.code {
                KeyCode::Char('x') | KeyCode::Char('q') | KeyCode::Esc => {
                    if key.code == KeyCode::Char('q') {
                        self.quit_after_scan = true;
                    }
                    if let Some(cancel) = &self.autoscan.cancel {
                        cancel.cancel();
                        self.log("Cancellation requested; waiting for restoration");
                    }
                }
                KeyCode::Char('e') => self.show_logs = !self.show_logs,
                KeyCode::Char('f') => {
                    self.autoscan.show_all = !self.autoscan.show_all;
                    if !self
                        .autoscan_rows()
                        .iter()
                        .any(|row| Some(row.gem_port) == self.autoscan.selected_gem)
                    {
                        self.autoscan.selected_gem =
                            self.autoscan_rows().first().map(|row| row.gem_port);
                    }
                }
                KeyCode::Char('/') => self.search_modal = Some(GemSearch::default()),
                KeyCode::Down => self.move_autoscan_selection(1),
                KeyCode::Up => self.move_autoscan_selection(-1),
                KeyCode::Home => {
                    self.autoscan.selected_gem =
                        self.autoscan_rows().first().map(|row| row.gem_port)
                }
                KeyCode::End => {
                    self.autoscan.selected_gem = self.autoscan_rows().last().map(|row| row.gem_port)
                }
                _ => {}
            }
            return;
        }
        if self.autoscan.recovery.is_some() {
            match key.code {
                KeyCode::Char('R') => {
                    if let Some(original) = self.autoscan.recovery.clone() {
                        self.log("Retrying restoration of original downstream table");
                        self.send_high(BackendCommand::RetryRestore(original));
                    }
                }
                KeyCode::Char('X') => self.confirm = Some(ConfirmAction::AbandonRecovery),
                KeyCode::Char('e') => self.show_logs = !self.show_logs,
                KeyCode::Char('?') => self.show_help = true,
                KeyCode::Char('q') => {
                    self.log("Restore is pending; retry or abandon recovery before quitting")
                }
                _ => {}
            }
            return;
        }
        if self.autoscan.result.is_some() {
            match key.code {
                KeyCode::Char('f') => {
                    self.autoscan.show_all = !self.autoscan.show_all;
                    if !self
                        .autoscan_rows()
                        .iter()
                        .any(|row| Some(row.gem_port) == self.autoscan.selected_gem)
                    {
                        self.autoscan.selected_gem =
                            self.autoscan_rows().first().map(|row| row.gem_port);
                    }
                }
                KeyCode::Char('/') => self.search_modal = Some(GemSearch::default()),
                KeyCode::Down => self.move_autoscan_selection(1),
                KeyCode::Up => self.move_autoscan_selection(-1),
                KeyCode::Home => {
                    self.autoscan.selected_gem =
                        self.autoscan_rows().first().map(|row| row.gem_port)
                }
                KeyCode::End => {
                    self.autoscan.selected_gem = self.autoscan_rows().last().map(|row| row.gem_port)
                }
                KeyCode::Char(' ') if self.autoscan.capacity_selecting => {
                    if let Some(gem) = self.autoscan.selected_gem {
                        let is_candidate = self
                            .autoscan
                            .result
                            .as_ref()
                            .zip(self.snapshot.as_ref())
                            .map(|(result, snapshot)| {
                                plan_active_apply(result, &snapshot.downstream)
                                    .candidates
                                    .contains(&gem)
                            })
                            .unwrap_or(false);
                        if !is_candidate {
                            self.log(format!("GEM {gem} is already configured"));
                            return;
                        }
                        if self.autoscan.apply_selected.remove(&gem) {
                            self.log(format!("Removed GEM {gem} from apply selection"));
                        } else {
                            let capacity = self
                                .snapshot
                                .as_ref()
                                .map(|snapshot| 128usize.saturating_sub(snapshot.downstream.len()))
                                .unwrap_or_default();
                            if self.autoscan.apply_selected.len() < capacity {
                                self.autoscan.apply_selected.insert(gem);
                                self.log(format!("Selected GEM {gem} for apply"));
                            } else {
                                self.log(format!(
                                    "Selection already uses all {capacity} free flow IDs"
                                ));
                            }
                        }
                    }
                }
                KeyCode::Char('a') => self.prepare_apply_selected(),
                KeyCode::Char('A') => self.prepare_apply_active(),
                KeyCode::Char('E') => {
                    let timestamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    self.autoscan.export_modal = Some(ExportModal {
                        path: format!("./gpwn-autoscan-{timestamp}.json"),
                        error: None,
                    });
                }
                KeyCode::Char('n') => {
                    self.autoscan.result = None;
                    self.autoscan.progress = None;
                    self.autoscan.last_apply = None;
                    self.autoscan.capacity_selecting = false;
                    self.autoscan.apply_selected.clear();
                }
                KeyCode::Char('s') => self.prepare_scan(),
                KeyCode::Esc if self.autoscan.capacity_selecting => {
                    self.autoscan.capacity_selecting = false;
                    self.autoscan.apply_selected.clear();
                }
                KeyCode::Char('e') => self.show_logs = !self.show_logs,
                KeyCode::Char('?') => self.show_help = true,
                KeyCode::Char('q') => self.request_quit(),
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Tab => self
                .autoscan
                .form
                .advance(key.modifiers.contains(KeyModifiers::SHIFT)),
            KeyCode::BackTab | KeyCode::Up => self.autoscan.form.advance(true),
            KeyCode::Down => self.autoscan.form.advance(false),
            KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')
                if self.autoscan.form.focused == 4 =>
            {
                self.autoscan.form.aes = !self.autoscan.form.aes
            }
            KeyCode::Backspace => self.autoscan.form.backspace(),
            KeyCode::Enter | KeyCode::Char('s') => self.prepare_scan(),
            KeyCode::Char('e') => self.show_logs = !self.show_logs,
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Char('q') => self.request_quit(),
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.autoscan.form.edit(character)
            }
            _ => {}
        }
    }

    fn prepare_scan(&mut self) {
        if self.connected.is_none() {
            self.log("Connect to an ONU before starting autoscan");
            return;
        }
        match self.autoscan.form.config() {
            Ok(config) => self.confirm = Some(ConfirmAction::StartScan(config)),
            Err(error) => self.autoscan.form.error = Some(error),
        }
    }

    fn prepare_apply_active(&mut self) {
        if self.autoscan.apply_busy || self.autoscan.awaiting_refresh {
            self.log("Waiting for a fresh downstream flow table");
            return;
        }
        if self.autoscan.capacity_selecting && !self.autoscan.apply_selected.is_empty() {
            self.confirm = Some(ConfirmAction::ApplyActive(
                self.autoscan.apply_selected.iter().copied().collect(),
            ));
            return;
        }
        let (Some(result), Some(snapshot)) = (&self.autoscan.result, &self.snapshot) else {
            self.log("Autoscan results and a refreshed flow table are required");
            return;
        };
        let plan = plan_active_apply(result, &snapshot.downstream);
        if plan.candidates.is_empty() {
            self.log(format!(
                "All {} active GEM ports are already configured",
                plan.already_configured.len()
            ));
        } else if plan.capacity_sufficient() {
            self.confirm = Some(ConfirmAction::ApplyActive(plan.candidates));
        } else {
            self.autoscan.capacity_selecting = true;
            self.autoscan.apply_selected = plan
                .candidates
                .iter()
                .take(plan.free_flow_ids.len())
                .copied()
                .collect();
            self.autoscan.show_all = false;
            self.log(format!(
                "{} candidates but only {} free flow IDs; select a subset, then press A",
                plan.candidates.len(),
                plan.free_flow_ids.len()
            ));
        }
    }

    fn prepare_apply_selected(&mut self) {
        if self.autoscan.apply_busy || self.autoscan.awaiting_refresh {
            self.log("Waiting for a fresh downstream flow table");
            return;
        }
        let Some(gem_port) = self.autoscan.selected_gem else {
            self.log("Select an active GEM port first");
            return;
        };
        let (Some(result), Some(snapshot)) = (&self.autoscan.result, &self.snapshot) else {
            self.log("Autoscan results and a refreshed flow table are required");
            return;
        };
        let active = result
            .activities()
            .any(|row| row.gem_port == gem_port && row.is_active());
        if !active {
            self.log(format!("GEM {gem_port} was idle during the scan"));
            return;
        }
        let plan = plan_active_apply(result, &snapshot.downstream);
        if plan.already_configured.contains(&gem_port) {
            self.log(format!("GEM {gem_port} is already configured downstream"));
        } else if plan.free_flow_ids.is_empty() {
            self.log("No downstream flow IDs are available");
        } else if plan.candidates.contains(&gem_port) {
            self.confirm = Some(ConfirmAction::ApplyActive(vec![gem_port]));
        } else {
            self.log(format!("GEM {gem_port} is not an applicable active result"));
        }
    }

    fn handle_export_key(&mut self, key: KeyEvent) {
        let Some(modal) = self.autoscan.export_modal.as_mut() else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.autoscan.export_modal = None,
            KeyCode::Backspace => {
                modal.path.pop();
                modal.error = None;
            }
            KeyCode::Enter => {
                let path = PathBuf::from(modal.path.trim());
                let write = self
                    .autoscan
                    .result
                    .as_ref()
                    .ok_or_else(|| io::Error::other("no autoscan result is available"))
                    .and_then(|result| write_json_new(&path, result));
                match write {
                    Ok(()) => {
                        self.autoscan.export_modal = None;
                        self.log(format!("Exported autoscan results to {}", path.display()));
                    }
                    Err(error) => {
                        modal.error = Some(format!(
                            "Could not export (existing files are not overwritten): {error}"
                        ))
                    }
                }
            }
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                modal.path.push(character);
                modal.error = None;
            }
            _ => {}
        }
    }

    fn handle_capture_key(&mut self, key: KeyEvent) {
        let Some(modal) = self.capture.modal.as_mut() else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.capture.modal = None,
            KeyCode::Enter => self.start_capture(),
            KeyCode::Tab | KeyCode::Down => modal.advance(false),
            KeyCode::BackTab | KeyCode::Up => modal.advance(true),
            KeyCode::Left if modal.focused == 0 => modal.cycle_interface(-1),
            KeyCode::Right if modal.focused == 0 => modal.cycle_interface(1),
            KeyCode::Char(' ') if modal.focused == 0 => modal.cycle_interface(1),
            KeyCode::Char('*') if modal.focused == 0 => modal.show_all = !modal.show_all,
            KeyCode::Backspace => {
                let edited = modal.focused;
                if let Some(field) = modal.field_mut() {
                    field.pop();
                }
                modal.error = None;
                Self::after_capture_edit(modal, edited);
            }
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                let edited = modal.focused;
                if let Some(field) = modal.field_mut() {
                    field.push(character);
                    modal.error = None;
                    Self::after_capture_edit(modal, edited);
                }
            }
            _ => {}
        }
    }

    /// Free space is cached rather than read per frame, so editing the
    /// directory is what invalidates it.
    fn after_capture_edit(modal: &mut CaptureModal, edited: usize) {
        if edited == CAPTURE_FIELD_DIRECTORY {
            modal.refresh_free_space();
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            if let Some(cancel) = &self.autoscan.cancel {
                cancel.cancel();
                self.quit_after_scan = true;
                self.log("Cancellation requested; waiting for restoration");
            } else if self.autoscan.recovery.is_some() {
                self.log("Restore is pending; retry or abandon recovery before quitting");
                self.page = Page::Autoscan;
            } else {
                self.request_quit();
            }
            return;
        }
        if self.show_connection {
            self.handle_connection_key(key);
            return;
        }
        if self.show_help {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('?')) {
                self.show_help = false;
            }
            return;
        }
        if self.autoscan.export_modal.is_some() {
            self.handle_export_key(key);
            return;
        }
        if self.mib.input.is_some() {
            self.handle_mib_input_key(key);
            return;
        }
        if self.add_modal.is_some() {
            self.handle_add_key(key);
            return;
        }
        if self.search_modal.is_some() {
            self.handle_search_key(key);
            return;
        }
        if self.confirm.is_some() {
            self.handle_confirm_key(key);
            return;
        }
        if self.capture.modal.is_some() {
            self.handle_capture_key(key);
            return;
        }
        // Recording is page-independent and does not need the ONU connection:
        // it is a NIC operation, so it keeps working while disconnected.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('r') {
            self.toggle_capture();
            return;
        }
        if matches!(key.code, KeyCode::Char('1')) {
            self.page = Page::Monitor;
            return;
        }
        if matches!(key.code, KeyCode::Char('2')) {
            self.page = Page::Autoscan;
            return;
        }
        if matches!(key.code, KeyCode::Char('3')) {
            self.page = Page::Mib;
            if !self.mib.catalog_loaded {
                self.request_mib_catalog();
            }
            return;
        }
        if self.page == Page::Autoscan {
            self.handle_autoscan_key(key);
            return;
        }
        if self.page == Page::Mib {
            self.handle_mib_key(key);
            return;
        }
        match key.code {
            KeyCode::Char('q') if self.autoscan.recovery.is_some() => {
                self.page = Page::Autoscan;
                self.log("Restore is pending; retry or abandon recovery before quitting");
            }
            KeyCode::Char('q') if self.autoscan.running => {
                if let Some(cancel) = &self.autoscan.cancel {
                    cancel.cancel();
                    self.quit_after_scan = true;
                    self.log("Cancellation requested; waiting for restoration");
                }
            }
            KeyCode::Char('q') => self.request_quit(),
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Char('e') => self.show_logs = !self.show_logs,
            KeyCode::Char('f') => {
                self.activity_filter.cycle();
                self.reconcile_selections(false);
                self.log(format!("Flow filter: {}", self.activity_filter));
            }
            KeyCode::Char('/') => self.search_modal = Some(GemSearch::default()),
            KeyCode::Char('r') if !self.backend_locked() => self.send_high(BackendCommand::Refresh),
            KeyCode::Char('a') if self.connected.is_some() && !self.backend_locked() => {
                self.add_modal = Some(AddModal {
                    scope: self.pane.scope(),
                    ..Default::default()
                })
            }
            KeyCode::Char('d') if self.connected.is_some() && !self.backend_locked() => {
                if let Some(flow_id) = self.selected_flow_id() {
                    self.confirm = Some(ConfirmAction::DeleteOne {
                        scope: self.pane.scope(),
                        flow_id,
                    });
                }
            }
            KeyCode::Char('D') if self.connected.is_some() && !self.backend_locked() => {
                self.confirm = Some(ConfirmAction::DeleteAll {
                    scope: DirectionScope::Both,
                })
            }
            KeyCode::Char('l') if self.connected.is_some() && !self.backend_locked() => {
                self.confirm = Some(ConfirmAction::Setup)
            }
            KeyCode::Char('c') if !self.autoscan.running => {
                self.show_connection = true;
            }
            KeyCode::Char('p') => {
                self.sampling_paused = !self.sampling_paused;
                self.log(if self.sampling_paused {
                    "Traffic sampling paused"
                } else {
                    "Traffic sampling resumed"
                });
                self.next_sweep = Instant::now();
            }
            KeyCode::Tab | KeyCode::Left | KeyCode::Right => self.pane.toggle(),
            KeyCode::Down => self.move_selection(1),
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Home => self.set_selection(0),
            KeyCode::End => self.set_selection(usize::MAX),
            _ => {}
        }
    }

    fn handle_connection_key(&mut self, key: KeyEvent) {
        if self.connection_form.connecting {
            return;
        }
        match key.code {
            KeyCode::Esc => {
                if self.snapshot.is_some() {
                    self.show_connection = false;
                } else {
                    self.request_quit();
                }
            }
            KeyCode::Tab => self
                .connection_form
                .advance(key.modifiers.contains(KeyModifiers::SHIFT)),
            KeyCode::BackTab => self.connection_form.advance(true),
            KeyCode::Up => self.connection_form.advance(true),
            KeyCode::Down => self.connection_form.advance(false),
            KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')
                if matches!(self.connection_form.focused, 0 | 1) =>
            {
                self.connection_form.edit(' ')
            }
            KeyCode::Backspace => self.connection_form.backspace(),
            KeyCode::Enter => match self.connection_form.settings() {
                Ok(settings) => {
                    if self.autoscan.recovery.is_some()
                        && self
                            .autoscan
                            .recovery_endpoint
                            .as_ref()
                            .is_some_and(|endpoint| endpoint != &settings.endpoint())
                    {
                        self.connection_form.error = Some(format!(
                            "restore is pending for {}; reconnect to that same endpoint",
                            self.autoscan
                                .recovery_endpoint
                                .as_deref()
                                .unwrap_or("the ONU")
                        ));
                        return;
                    }
                    self.poll_interval = settings.poll_interval();
                    self.connection_form.error = None;
                    self.connection_form.connecting = true;
                    self.send_high(BackendCommand::Connect(settings));
                }
                Err(error) => self.connection_form.error = Some(error),
            },
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.connection_form.edit(character)
            }
            _ => {}
        }
    }

    fn handle_add_key(&mut self, key: KeyEvent) {
        let Some(modal) = self.add_modal.as_mut() else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.add_modal = None,
            KeyCode::Tab => modal.advance(key.modifiers.contains(KeyModifiers::SHIFT)),
            KeyCode::BackTab => modal.advance(true),
            KeyCode::Up => modal.advance(true),
            KeyCode::Down => modal.advance(false),
            KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')
                if matches!(modal.focused, 0 | 3 | 4 | 5) =>
            {
                modal.toggle()
            }
            KeyCode::Backspace => modal.backspace(),
            KeyCode::Enter => match modal.request() {
                Ok(request) => {
                    self.add_modal = None;
                    self.send_high(BackendCommand::Add(request));
                }
                Err(error) => modal.error = Some(error),
            },
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                modal.edit(character)
            }
            _ => {}
        }
    }

    fn handle_search_key(&mut self, key: KeyEvent) {
        let Some(search) = self.search_modal.as_mut() else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.search_modal = None,
            KeyCode::Backspace => {
                search.query.pop();
                search.error = None;
            }
            KeyCode::Enter => {
                let query = search.query.clone();
                match query.parse::<u16>() {
                    Ok(gem_port) if gem_port <= gpwn_core::GEM_PORT_MAX => {
                        self.search_modal = None;
                        if self.page == Page::Autoscan {
                            let found = self.autoscan.result.as_ref().is_some_and(|result| {
                                result.activities().any(|row| row.gem_port == gem_port)
                            }) || self
                                .autoscan
                                .live_activities
                                .iter()
                                .any(|row| row.gem_port == gem_port);
                            if found {
                                if !self
                                    .autoscan_rows()
                                    .iter()
                                    .any(|row| row.gem_port == gem_port)
                                {
                                    self.autoscan.show_all = true;
                                }
                                self.autoscan.selected_gem = Some(gem_port);
                                self.log(format!("Selected autoscan GEM port {gem_port}"));
                            } else {
                                self.log(format!(
                                    "GEM {gem_port} is not visible in autoscan results"
                                ));
                            }
                        } else {
                            self.jump_to_gem_port(gem_port);
                        }
                    }
                    _ => {
                        search.error = Some("Enter a GEM port from 0 to 4095".into());
                    }
                }
            }
            KeyCode::Char(character) if character.is_ascii_digit() => {
                search.query.push(character);
                search.error = None;
            }
            _ => {}
        }
    }

    fn jump_to_gem_port(&mut self, gem_port: u16) {
        let Some(snapshot) = &self.snapshot else {
            self.log("No flow data to search");
            return;
        };
        let downstream = snapshot
            .downstream
            .iter()
            .position(|flow| flow.gem_port == gem_port);
        let upstream = snapshot
            .upstream
            .iter()
            .position(|flow| flow.gem_port == gem_port);
        let match_in_preferred_pane = match self.pane {
            Pane::Downstream => downstream.map(|index| (Pane::Downstream, index)),
            Pane::Upstream => upstream.map(|index| (Pane::Upstream, index)),
        };
        let fallback = downstream
            .map(|index| (Pane::Downstream, index))
            .or_else(|| upstream.map(|index| (Pane::Upstream, index)));
        if let Some((pane, index)) = match_in_preferred_pane.or(fallback) {
            self.activity_filter = ActivityFilter::All;
            self.pane = pane;
            let flow_id = match pane {
                Pane::Downstream => snapshot.downstream[index].flow_id,
                Pane::Upstream => snapshot.upstream[index].flow_id,
            };
            match pane {
                Pane::Downstream => self.ds_selected = Some(flow_id),
                Pane::Upstream => self.us_selected = Some(flow_id),
            }
            self.log(format!("Selected GEM port {gem_port} in {}", pane.label()));
        } else {
            self.log(format!("No configured flow uses GEM port {gem_port}"));
        }
    }

    fn handle_confirm_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('n') => self.confirm = None,
            KeyCode::Char('s') | KeyCode::Left | KeyCode::Right => {
                if let Some(ConfirmAction::DeleteAll { scope }) = self.confirm.as_mut() {
                    *scope = next_scope(*scope);
                }
            }
            KeyCode::Enter | KeyCode::Char('y') => {
                let Some(action) = self.confirm.take() else {
                    return;
                };
                match action {
                    ConfirmAction::DeleteOne { scope, flow_id } => {
                        self.send_high(BackendCommand::Delete(DeleteFlowRequest {
                            scope,
                            flow_ids: Some(vec![flow_id]),
                        }));
                    }
                    ConfirmAction::DeleteAll { scope } => {
                        self.send_high(BackendCommand::Delete(DeleteFlowRequest {
                            scope,
                            flow_ids: None,
                        }));
                    }
                    ConfirmAction::Setup => self.send_high(BackendCommand::Setup),
                    ConfirmAction::StartScan(config) => {
                        let cancel = CancellationToken::default();
                        self.autoscan = AutoscanView {
                            form: self.autoscan.form.clone(),
                            running: true,
                            cancel: Some(cancel.clone()),
                            ..Default::default()
                        };
                        self.snapshot_stale = true;
                        self.sampling_pending = 0;
                        self.log("Autoscan started; monitor data is now stale/read-only");
                        self.send_high(BackendCommand::StartScan { config, cancel });
                    }
                    ConfirmAction::ApplyActive(gem_ports) => {
                        let aes = self
                            .autoscan
                            .result
                            .as_ref()
                            .map(|result| result.config.aes)
                            .unwrap_or(false);
                        self.autoscan.apply_busy = true;
                        self.send_high(BackendCommand::ApplyActive { gem_ports, aes });
                    }
                    ConfirmAction::AbandonRecovery => {
                        self.autoscan.recovery = None;
                        self.autoscan.recovery_endpoint = None;
                        self.autoscan.recovery_abandoned = true;
                        if let Some(result) = self.autoscan.result.as_mut() {
                            result.restore_error =
                                Some("restoration was explicitly abandoned".into());
                            result.terminal_phase = AutoscanPhase::Failed;
                        }
                        self.snapshot_stale = true;
                        self.autoscan.awaiting_refresh = true;
                        self.log(
                            "Recovery abandoned; downstream configuration is unknown—refresh before modifying",
                        );
                        self.send_high(BackendCommand::Refresh);
                        if self.quit_after_scan {
                            self.request_quit();
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn selected_flow_id(&self) -> Option<u8> {
        let selected = match self.pane {
            Pane::Downstream => self.ds_selected,
            Pane::Upstream => self.us_selected,
        }?;
        let visible = match self.pane {
            Pane::Downstream => self
                .filtered_downstream()
                .iter()
                .any(|flow| flow.flow_id == selected),
            Pane::Upstream => self
                .filtered_upstream()
                .iter()
                .any(|flow| flow.flow_id == selected),
        };
        visible.then_some(selected)
    }

    fn move_selection(&mut self, delta: isize) {
        let ids: Vec<u8> = match self.pane {
            Pane::Downstream => self
                .filtered_downstream()
                .iter()
                .map(|flow| flow.flow_id)
                .collect(),
            Pane::Upstream => self
                .filtered_upstream()
                .iter()
                .map(|flow| flow.flow_id)
                .collect(),
        };
        let selected = match self.pane {
            Pane::Downstream => self.ds_selected,
            Pane::Upstream => self.us_selected,
        };
        let next = if ids.is_empty() {
            None
        } else if let Some(position) =
            selected.and_then(|selected| ids.iter().position(|id| *id == selected))
        {
            let position = (position as isize + delta).clamp(0, ids.len() as isize - 1) as usize;
            Some(ids[position])
        } else if delta < 0 {
            ids.last().copied()
        } else {
            ids.first().copied()
        };
        match self.pane {
            Pane::Downstream => self.ds_selected = next,
            Pane::Upstream => self.us_selected = next,
        }
    }

    fn set_selection(&mut self, requested: usize) {
        let ids: Vec<u8> = match self.pane {
            Pane::Downstream => self
                .filtered_downstream()
                .iter()
                .map(|flow| flow.flow_id)
                .collect(),
            Pane::Upstream => self
                .filtered_upstream()
                .iter()
                .map(|flow| flow.flow_id)
                .collect(),
        };
        let selected = ids.get(requested.min(ids.len().saturating_sub(1))).copied();
        match self.pane {
            Pane::Downstream => self.ds_selected = selected,
            Pane::Upstream => self.us_selected = selected,
        }
    }

    fn handle_mouse(&mut self, column: u16, row: u16, height: u16) {
        if row + 2 < height {
            return;
        }
        if self.page != Page::Monitor || self.backend_locked() {
            return;
        }
        // The action bar is behind the wizard; clicking through it would leave
        // the wizard drawn while another overlay owns the keyboard.
        if self.capture.modal.is_some() {
            return;
        }
        match column {
            0..=12 => self.send_high(BackendCommand::Refresh),
            13..=24 => {
                self.activity_filter.cycle();
                self.reconcile_selections(false);
                self.log(format!("Flow filter: {}", self.activity_filter));
            }
            25..=33 => self.search_modal = Some(GemSearch::default()),
            34..=42 if self.connected.is_some() => {
                self.add_modal = Some(AddModal {
                    scope: self.pane.scope(),
                    ..Default::default()
                })
            }
            43..=55 if self.connected.is_some() => {
                if let Some(flow_id) = self.selected_flow_id() {
                    self.confirm = Some(ConfirmAction::DeleteOne {
                        scope: self.pane.scope(),
                        flow_id,
                    });
                }
            }
            56..=72 if self.connected.is_some() => {
                self.confirm = Some(ConfirmAction::DeleteAll {
                    scope: DirectionScope::Both,
                })
            }
            73..=91 if self.connected.is_some() => self.confirm = Some(ConfirmAction::Setup),
            92..=105 => {
                self.show_connection = true;
            }
            106..=118 => self.sampling_paused = !self.sampling_paused,
            119..=129 => self.show_logs = !self.show_logs,
            130..=140 => self.show_help = true,
            _ => self.request_quit(),
        }
    }

    fn handle_mouse_scroll(&mut self, column: u16, width: u16, delta: isize) {
        if self.show_connection
            || self.add_modal.is_some()
            || self.search_modal.is_some()
            || self.capture.modal.is_some()
            || self.confirm.is_some()
            || self.show_help
        {
            return;
        }
        if self.page == Page::Autoscan {
            self.move_autoscan_selection(delta);
            return;
        }
        if self.page == Page::Mib {
            if width >= 100 {
                self.mib.pane = if column < width * 30 / 100 {
                    MibPane::Tables
                } else if column < width * 52 / 100 {
                    MibPane::Entities
                } else {
                    MibPane::Attributes
                };
            }
            self.move_mib_selection(delta);
            return;
        }
        if width >= 150 {
            self.pane = if column < width / 2 {
                Pane::Downstream
            } else {
                Pane::Upstream
            };
        }
        self.move_selection(delta);
    }

    fn flow_visible(&self, pane: Pane, flow_id: u8) -> bool {
        activity_matches(self.activity_filter, pane, self.samples.get(&flow_id))
    }

    fn filtered_downstream(&self) -> Vec<&gpwn_core::DownstreamFlow> {
        self.snapshot
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .downstream
                    .iter()
                    .filter(|flow| self.flow_visible(Pane::Downstream, flow.flow_id))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn filtered_upstream(&self) -> Vec<&gpwn_core::UpstreamFlow> {
        self.snapshot
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .upstream
                    .iter()
                    .filter(|flow| self.flow_visible(Pane::Upstream, flow.flow_id))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn render(&mut self, frame: &mut ratatui::Frame) {
        if self.show_connection && self.snapshot.is_none() {
            render_connection(frame, &self.connection_form);
            return;
        }
        let area = frame.area();
        let log_height = if self.show_logs { 8 } else { 0 };
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(2),
                Constraint::Length(6),
                Constraint::Min(8),
                Constraint::Length(log_height),
                Constraint::Length(2),
            ])
            .split(area);
        self.render_status(frame, chunks[0]);
        frame.render_widget(
            Tabs::new(vec!["1 Monitor", "2 Autoscan", "3 MIB"])
                .select(match self.page {
                    Page::Monitor => 0,
                    Page::Autoscan => 1,
                    Page::Mib => 2,
                })
                .highlight_style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            chunks[1],
        );
        match self.page {
            Page::Monitor => {
                self.render_line(frame, chunks[2]);
                self.render_flows(frame, chunks[3]);
            }
            Page::Autoscan => {
                self.render_autoscan_summary(frame, chunks[2]);
                self.render_autoscan_body(frame, chunks[3]);
            }
            Page::Mib => {
                self.render_mib_summary(frame, chunks[2]);
                self.render_mib_body(frame, chunks[3]);
            }
        }
        if self.show_logs {
            self.render_logs(frame, chunks[4]);
        }
        self.render_actions(frame, chunks[5]);

        if self.show_connection {
            render_connection(frame, &self.connection_form);
        } else if let Some(modal) = &self.add_modal {
            render_add_modal(frame, modal);
        } else if let Some(search) = &self.search_modal {
            render_search(frame, search);
        } else if let Some(input) = &self.mib.input {
            render_mib_input(frame, input);
        } else if let Some(export) = &self.autoscan.export_modal {
            render_export(frame, export);
        } else if let Some(modal) = &self.capture.modal {
            render_capture_modal(frame, modal);
        } else if let Some(confirm) = &self.confirm {
            render_confirm(frame, confirm);
        } else if self.show_help {
            render_help(frame);
        }
    }

    fn render_status(&self, frame: &mut ratatui::Frame, area: Rect) {
        let connection = self
            .connected
            .as_ref()
            .map(|info| {
                let user = info
                    .username
                    .as_ref()
                    .map(|user| format!("{user}@"))
                    .unwrap_or_default();
                format!("{} {}{}", info.kind, user, info.endpoint)
            })
            .unwrap_or_else(|| "DISCONNECTED".into());
        let insecure = self
            .connected
            .as_ref()
            .is_some_and(|info| !info.host_key_verified);
        let stale = if self.snapshot_stale { "  STALE" } else { "" };
        let sampling = if self.sampling_paused {
            "sampling paused".into()
        } else if self.sampling_pending > 0 {
            format!("sampling {}", self.sampling_pending)
        } else {
            format!("poll {}s", self.poll_interval.as_secs())
        };
        let scan = if self.autoscan.running {
            self.autoscan
                .progress
                .as_ref()
                .map(|progress| {
                    format!(
                        " | SCAN {} {}/{}",
                        progress.phase,
                        (progress.batch_index + 1).min(progress.total_batches),
                        progress.total_batches
                    )
                })
                .unwrap_or_else(|| " | SCAN starting".into())
        } else if self.autoscan.recovery.is_some() {
            " | RESTORE PENDING".into()
        } else {
            String::new()
        };
        let recording = match self.capture.active.as_ref() {
            Some(active) if self.capture.stopping => {
                format!(" | ● REC stopping {}", active.config.interface)
            }
            Some(active) => {
                let against = active
                    .config
                    .duration
                    .map(|total| format!(" / {}", clock(total)))
                    .unwrap_or_default();
                format!(
                    " | ● REC {}{}  {}  {}",
                    clock(active.started_at.elapsed()),
                    against,
                    human_bytes(active.bytes as f64),
                    active.config.interface
                )
            }
            None => String::new(),
        };
        let style = if self.connected.is_some() {
            Style::default().fg(Color::Black).bg(Color::Green)
        } else {
            Style::default().fg(Color::White).bg(Color::Red)
        };
        let text = format!(
            " GPWN  {connection}{stale}  |  {sampling}{scan}{recording}{} ",
            if insecure {
                "  |  ⚠ host key unverified"
            } else {
                ""
            }
        );
        frame.render_widget(Paragraph::new(text).style(style), area);
    }

    fn render_autoscan_summary(&self, frame: &mut ratatui::Frame, area: Rect) {
        let (title, lines, color) = if self.autoscan.running {
            let progress = self.autoscan.progress.as_ref();
            (
                " Autoscan running ",
                vec![
                    Line::from(progress.map_or_else(
                        || "Starting…".into(),
                        |item| {
                            format!(
                                "{} — batch {}/{} GEM {}–{}",
                                item.phase,
                                (item.batch_index + 1).min(item.total_batches),
                                item.total_batches,
                                item.gem_start,
                                item.gem_end
                            )
                        },
                    )),
                    Line::from(progress.map_or_else(String::new, |item| item.message.clone())),
                    Line::from(progress.map_or_else(String::new, |item| {
                        if item.item_total == 0 {
                            String::new()
                        } else {
                            format!("Item {}/{}", item.item_index, item.item_total)
                        }
                    })),
                ],
                Color::Yellow,
            )
        } else if let Some(result) = &self.autoscan.result {
            let restore = if self.autoscan.recovery.is_some() {
                "RESTORE PENDING"
            } else if self.autoscan.recovery_abandoned {
                "RESTORE ABANDONED"
            } else {
                "original table restored"
            };
            (
                " Autoscan results ",
                vec![
                    Line::from(format!(
                        "{} — {} scanned, {} active, {:.1}s",
                        result.terminal_phase,
                        result.scanned_count(),
                        result.active_ports().len(),
                        result.wall_time_secs
                    )),
                    Line::from(format!(
                        "Range {}–{} | batch {} | window {:.1}s | AES {}",
                        result.config.gem_start,
                        result.config.gem_end,
                        result.config.batch_size,
                        result.config.observation_secs,
                        yes_no(result.config.aes)
                    )),
                    Line::from(restore),
                ],
                if self.autoscan.recovery.is_some() {
                    Color::Red
                } else {
                    Color::Cyan
                },
            )
        } else {
            let config = self.autoscan.form.config();
            let estimate = config.as_ref().map_or_else(
                |_| "Fix invalid fields to calculate scan size".into(),
                |config| {
                    format!(
                        "{} batches; observation time alone ≈ {:.0}s",
                        config.total_batches(),
                        config.total_batches() as f64 * config.observation_secs
                    )
                },
            );
            (
                " Configure autoscan ",
                vec![
                    Line::from(
                        "Temporarily replaces downstream flows, measures activity, then restores them.",
                    ),
                    Line::from(estimate),
                    Line::from(
                        "The recovery copy exists only in this process. Listen-all is never run.",
                    ),
                ],
                Color::Cyan,
            )
        };
        frame.render_widget(
            Paragraph::new(lines)
                .block(
                    Block::default()
                        .title(title)
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(color)),
                )
                .wrap(Wrap { trim: true }),
            area,
        );
    }

    fn render_autoscan_body(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        if self.autoscan.result.is_none() && !self.autoscan.running {
            let fields = [
                ("GEM start", self.autoscan.form.gem_start.clone()),
                ("GEM end", self.autoscan.form.gem_end.clone()),
                ("Batch size", self.autoscan.form.batch_size.clone()),
                (
                    "Observation (s)",
                    self.autoscan.form.observation_secs.clone(),
                ),
                ("AES", yes_no(self.autoscan.form.aes).into()),
            ];
            let mut lines = fields
                .iter()
                .enumerate()
                .map(|(index, (label, value))| {
                    let style = if index == self.autoscan.form.focused {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    Line::from(vec![
                        Span::styled(
                            format!(
                                "{} {label:<18}",
                                if index == self.autoscan.form.focused {
                                    "▶"
                                } else {
                                    " "
                                }
                            ),
                            style,
                        ),
                        Span::styled(value.clone(), style),
                    ])
                })
                .collect::<Vec<_>>();
            lines.push(Line::from(""));
            lines.push(Line::from(
                "Tab/↑/↓ fields  Space toggles AES  Enter/s start",
            ));
            if let Some(error) = &self.autoscan.form.error {
                lines.push(Line::from(Span::styled(
                    error.clone(),
                    Style::default().fg(Color::Red),
                )));
            }
            frame.render_widget(
                Paragraph::new(lines).block(
                    Block::default()
                        .title(" Scan settings ")
                        .borders(Borders::ALL),
                ),
                area,
            );
            return;
        }

        let configured: BTreeSet<_> = self
            .snapshot
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .downstream
                    .iter()
                    .map(|flow| flow.gem_port)
                    .collect()
            })
            .unwrap_or_default();
        let added: BTreeSet<_> = self
            .autoscan
            .last_apply
            .as_ref()
            .map(|result| {
                result
                    .added
                    .iter()
                    .filter(|(id, _)| !result.rolled_back.contains(id))
                    .map(|(_, gem)| *gem)
                    .collect()
            })
            .unwrap_or_default();
        let failed_gem = self
            .autoscan
            .last_apply
            .as_ref()
            .and_then(|result| result.failed_gem);
        let rows = self
            .autoscan_rows()
            .into_iter()
            .map(|row| {
                let apply = if added.contains(&row.gem_port) {
                    "added"
                } else if failed_gem == Some(row.gem_port) {
                    "failed"
                } else if configured.contains(&row.gem_port) {
                    "configured"
                } else if self.autoscan.capacity_selecting
                    && self.autoscan.apply_selected.contains(&row.gem_port)
                {
                    "selected"
                } else if self.autoscan.capacity_selecting && row.is_active() {
                    "not selected"
                } else {
                    "—"
                };
                Row::new(vec![
                    Cell::from(row.gem_port.to_string()),
                    Cell::from(if row.is_active() { "active" } else { "idle" }),
                    Cell::from(row.ds_gem_packets.to_string()),
                    Cell::from(human_bytes(row.ds_gem_bytes as f64)),
                    Cell::from(row.ds_rx_eth_packets.to_string()),
                    Cell::from(row.ds_fwd_eth_packets.to_string()),
                    Cell::from(human_rate(row.packets_per_sec)),
                    Cell::from(human_rate(row.bytes_per_sec)),
                    Cell::from(format!("{:.1}s", row.elapsed_secs)),
                    Cell::from((row.batch_index + 1).to_string()),
                    Cell::from(apply),
                ])
            })
            .collect::<Vec<_>>();
        let selected = self.autoscan.selected_gem.and_then(|selected| {
            self.autoscan_rows()
                .iter()
                .position(|row| row.gem_port == selected)
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(6),
                Constraint::Length(7),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Length(8),
                Constraint::Length(6),
                Constraint::Min(11),
            ],
        )
        .header(
            Row::new([
                "GEM", "State", "DS pkts", "DS bytes", "RX eth", "FWD eth", "pkt/s", "B/s",
                "Window", "Batch", "Apply",
            ])
            .style(Style::default().fg(Color::Cyan)),
        )
        .block(
            Block::default()
                .title(if self.autoscan.show_all {
                    " All scanned GEM ports "
                } else {
                    " Active GEM ports "
                })
                .borders(Borders::ALL),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
        let mut state = TableState::default().with_selected(selected);
        frame.render_stateful_widget(table, area, &mut state);
    }

    fn render_mib_summary(&self, frame: &mut ratatui::Frame, area: Rect) {
        let active = self.active_mib_snapshot();
        let state = if self.mib.loading {
            "loading…".to_owned()
        } else if let Some(error) = &self.mib.error {
            format!("last request failed: {error}")
        } else if let Some(snapshot) = active {
            format!(
                "{} — {} entities — cached",
                snapshot.table_name,
                snapshot.entities.len()
            )
        } else if self.mib.catalog_loaded {
            "select a table and press Enter".into()
        } else {
            "catalog not loaded".into()
        };
        let selector = self
            .mib
            .active_query
            .as_ref()
            .map(|query| {
                let entity = query
                    .entity_id
                    .map(|id| format!(", entity 0x{id:04X}"))
                    .unwrap_or_default();
                format!("Active query: {}{entity}", query.selector.command_value())
            })
            .unwrap_or_else(|| "No table query has been run".into());
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(format!(
                    "{} registered tables | {state}",
                    self.mib.catalog.len()
                )),
                Line::from(selector),
                Line::from(
                    "Read-only OMCI explorer. Table IDs at left are Realtek catalog indexes, not OMCI class IDs.",
                ),
            ])
            .block(
                Block::default()
                    .title(" OMCI MIB ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: true }),
            area,
        );
    }

    fn render_mib_body(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        if area.width < 100 {
            match self.mib.pane {
                MibPane::Tables => self.render_mib_tables(frame, area),
                MibPane::Entities => self.render_mib_entities(frame, area),
                MibPane::Attributes => self.render_mib_attributes(frame, area),
            }
            return;
        }
        let panes = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(30),
                Constraint::Percentage(22),
                Constraint::Percentage(48),
            ])
            .split(area);
        self.render_mib_tables(frame, panes[0]);
        self.render_mib_entities(frame, panes[1]);
        self.render_mib_attributes(frame, panes[2]);
    }

    fn render_mib_tables(&self, frame: &mut ratatui::Frame, area: Rect) {
        let ids = self.mib_visible_table_ids();
        let rows = ids
            .iter()
            .filter_map(|id| {
                self.mib
                    .catalog
                    .iter()
                    .find(|table| table.internal_id == *id)
            })
            .map(|table| {
                let cached = self
                    .mib
                    .snapshots
                    .values()
                    .find(|snapshot| snapshot.table_name == table.name);
                Row::new(vec![
                    Cell::from(table.internal_id.to_string()),
                    Cell::from(
                        omci_class_id_for_table(&table.name)
                            .map(|id| id.to_string())
                            .unwrap_or_else(|| "—".into()),
                    ),
                    Cell::from(table.name.clone()),
                    Cell::from(
                        cached
                            .map(|snapshot| snapshot.entities.len().to_string())
                            .unwrap_or_else(|| "—".into()),
                    ),
                ])
            })
            .collect::<Vec<_>>();
        let selected = self
            .mib
            .selected_table
            .and_then(|id| ids.iter().position(|candidate| *candidate == id));
        let title = if self.mib.table_filter.is_empty() {
            format!(" Tables — {} ", self.mib.catalog.len())
        } else {
            format!(
                " Tables — {}/{} — /{} ",
                ids.len(),
                self.mib.catalog.len(),
                self.mib.table_filter
            )
        };
        let table = Table::new(
            rows,
            [
                Constraint::Length(5),
                Constraint::Length(6),
                Constraint::Min(12),
                Constraint::Length(4),
            ],
        )
        .header(Row::new(["Idx", "Class", "Name", "Ent"]).style(Style::default().fg(Color::Cyan)))
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(mib_pane_style(self.mib.pane == MibPane::Tables)),
        )
        .row_highlight_style(Style::default().bg(Color::DarkGray))
        .highlight_symbol("▶ ");
        frame.render_stateful_widget(
            table,
            area,
            &mut TableState::default().with_selected(selected),
        );
    }

    fn render_mib_entities(&self, frame: &mut ratatui::Frame, area: Rect) {
        let entities = self
            .active_mib_snapshot()
            .map(|snapshot| snapshot.entities.as_slice())
            .unwrap_or_default();
        let rows = entities
            .iter()
            .map(|entity| {
                Row::new(vec![
                    Cell::from(format!("0x{:04X}", entity.entity_id)),
                    Cell::from(entity.entity_id.to_string()),
                    Cell::from(entity.attributes.len().to_string()),
                ])
            })
            .collect::<Vec<_>>();
        let selected = self
            .mib
            .selected_entity
            .and_then(|id| entities.iter().position(|entity| entity.entity_id == id));
        let table = Table::new(
            rows,
            [
                Constraint::Length(8),
                Constraint::Length(6),
                Constraint::Min(4),
            ],
        )
        .header(Row::new(["Entity", "Dec", "Attrs"]).style(Style::default().fg(Color::Cyan)))
        .block(
            Block::default()
                .title(format!(" Entities — {} ", entities.len()))
                .borders(Borders::ALL)
                .border_style(mib_pane_style(self.mib.pane == MibPane::Entities)),
        )
        .row_highlight_style(Style::default().bg(Color::DarkGray))
        .highlight_symbol("▶ ");
        frame.render_stateful_widget(
            table,
            area,
            &mut TableState::default().with_selected(selected),
        );
    }

    fn render_mib_attributes(&self, frame: &mut ratatui::Frame, area: Rect) {
        let title = if self.mib.raw {
            " Raw device output "
        } else if self.mib.attribute_filter.is_empty() {
            " Attributes "
        } else {
            " Attributes — filtered "
        };
        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(mib_pane_style(self.mib.pane == MibPane::Attributes));
        if self.mib.raw {
            let text = self
                .active_mib_snapshot()
                .map(|snapshot| snapshot.raw_output.as_str())
                .unwrap_or("Load a table to inspect its raw output.");
            frame.render_widget(
                Paragraph::new(text)
                    .block(block)
                    .scroll((self.mib.raw_scroll, 0))
                    .wrap(Wrap { trim: false }),
                area,
            );
            return;
        }
        let indices = self.mib_attribute_indices();
        let rows = self
            .selected_mib_entity()
            .map(|entity| {
                indices
                    .iter()
                    .filter_map(|index| entity.attributes.get(*index))
                    .map(|attribute| {
                        Row::new(vec![
                            Cell::from(attribute.name.clone()),
                            Cell::from(attribute.value.clone()),
                        ])
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let selected = self
            .mib
            .selected_attribute
            .and_then(|index| indices.iter().position(|candidate| *candidate == index));
        let table = Table::new(
            rows,
            [Constraint::Percentage(38), Constraint::Percentage(62)],
        )
        .header(Row::new(["Attribute", "Value"]).style(Style::default().fg(Color::Cyan)))
        .block(block)
        .row_highlight_style(Style::default().bg(Color::DarkGray))
        .highlight_symbol("▶ ");
        frame.render_stateful_widget(
            table,
            area,
            &mut TableState::default().with_selected(selected),
        );
    }

    fn render_line(&self, frame: &mut ratatui::Frame, area: Rect) {
        let block = Block::default()
            .title(" Fiber line ")
            .borders(Borders::ALL)
            .border_style(if self.snapshot_stale {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Cyan)
            });
        let content = if let Some(snapshot) = &self.snapshot {
            let line = &snapshot.line;
            let alarm_style = |condition: AlarmCondition| {
                if condition == AlarmCondition::Active {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Green)
                }
            };
            vec![
                Line::from(vec![
                    Span::raw("State: "),
                    Span::styled(
                        format!("{} {}", line.onu_state, line.state_description),
                        Style::default()
                            .fg(if line.onu_state == gpwn_core::OnuState::O5 {
                                Color::Green
                            } else {
                                Color::Yellow
                            })
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("    RX: "),
                    Span::raw(format_power(line.rx_power_dbm)),
                    Span::raw("    TX: "),
                    Span::raw(format_power(line.tx_power_dbm)),
                ]),
                Line::from(vec![
                    Span::raw("Alarms: LOS "),
                    Span::styled(line.los.to_string(), alarm_style(line.los)),
                    Span::raw("   LOF "),
                    Span::styled(line.lof.to_string(), alarm_style(line.lof)),
                    Span::raw("   LOM "),
                    Span::styled(line.lom.to_string(), alarm_style(line.lom)),
                ]),
                Line::from(format!(
                    "Last refresh: {}{}",
                    system_time_age(snapshot.fetched_at),
                    if self.snapshot_stale {
                        " — data retained after disconnect"
                    } else {
                        ""
                    }
                )),
            ]
        } else {
            vec![Line::from("No line data")]
        };
        frame.render_widget(Paragraph::new(content).block(block), area);
    }

    fn render_flows(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        if area.width >= 150 {
            let columns = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(area);
            self.render_downstream(frame, columns[0]);
            self.render_upstream(frame, columns[1]);
        } else {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(2), Constraint::Min(1)])
                .split(area);
            let selected = match self.pane {
                Pane::Downstream => 0,
                Pane::Upstream => 1,
            };
            frame.render_widget(
                Tabs::new(vec!["Downstream", "Upstream"])
                    .select(selected)
                    .highlight_style(
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                chunks[0],
            );
            match self.pane {
                Pane::Downstream => self.render_downstream(frame, chunks[1]),
                Pane::Upstream => self.render_upstream(frame, chunks[1]),
            }
        }
    }

    fn render_downstream(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        let total_count = self
            .snapshot
            .as_ref()
            .map_or(0, |snapshot| snapshot.downstream.len());
        let visible_count = self.filtered_downstream().len();
        let rows = self
            .snapshot
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .downstream
                    .iter()
                    .filter(|flow| self.flow_visible(Pane::Downstream, flow.flow_id))
                    .map(|flow| {
                        let sample = self.samples.get(&flow.flow_id);
                        Row::new(vec![
                            Cell::from(flow.flow_id.to_string()),
                            Cell::from(flow.gem_port.to_string()),
                            Cell::from(flow.flow_type.to_string()),
                            Cell::from(if flow.aes { "yes" } else { "no" }),
                            Cell::from(if flow.multicast { "yes" } else { "no" }),
                            Cell::from(sample_count(sample, |counters| counters.ds_gem_packets)),
                            Cell::from(sample_bytes(sample, |counters| counters.ds_gem_bytes)),
                            Cell::from(sample_rate(sample, |counters| counters.ds_gem_bytes)),
                            Cell::from(sample_state(Pane::Downstream, sample)),
                            Cell::from(sample_age(sample)),
                        ])
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let table = Table::new(
            rows,
            [
                Constraint::Length(4),
                Constraint::Length(6),
                Constraint::Length(5),
                Constraint::Length(4),
                Constraint::Length(3),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Length(7),
                Constraint::Length(6),
            ],
        )
        .header(
            Row::new([
                "ID", "GEM", "Type", "AES", "MC", "DS pkts", "DS bytes", "DS B/s", "State", "Age",
            ])
            .style(Style::default().fg(Color::Cyan)),
        )
        .block(
            Block::default()
                .title(format!(
                    " Downstream [{}] — {visible_count}/{total_count} flows ",
                    self.activity_filter
                ))
                .borders(Borders::ALL)
                .border_style(if self.pane == Pane::Downstream {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                }),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
        let selected = self.ds_selected.and_then(|selected| {
            self.filtered_downstream()
                .iter()
                .position(|flow| flow.flow_id == selected)
        });
        let mut state = TableState::default().with_selected(selected);
        frame.render_stateful_widget(table, area, &mut state);
    }

    fn render_upstream(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        let total_count = self
            .snapshot
            .as_ref()
            .map_or(0, |snapshot| snapshot.upstream.len());
        let visible_count = self.filtered_upstream().len();
        let rows = self
            .snapshot
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .upstream
                    .iter()
                    .filter(|flow| self.flow_visible(Pane::Upstream, flow.flow_id))
                    .map(|flow| {
                        let sample = self.samples.get(&flow.flow_id);
                        Row::new(vec![
                            Cell::from(flow.flow_id.to_string()),
                            Cell::from(flow.gem_port.to_string()),
                            Cell::from(flow.flow_type.to_string()),
                            Cell::from(format_optional(flow.tcont)),
                            Cell::from(format_optional(flow.channel)),
                            Cell::from(sample_count(sample, |counters| counters.us_gem_packets)),
                            Cell::from(sample_bytes(sample, |counters| counters.us_gem_bytes)),
                            Cell::from(sample_rate(sample, |counters| counters.us_gem_bytes)),
                            Cell::from(sample_state(Pane::Upstream, sample)),
                            Cell::from(sample_age(sample)),
                        ])
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let table = Table::new(
            rows,
            [
                Constraint::Length(4),
                Constraint::Length(6),
                Constraint::Length(5),
                Constraint::Length(5),
                Constraint::Length(4),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Length(7),
                Constraint::Length(6),
            ],
        )
        .header(
            Row::new([
                "ID", "GEM", "Type", "TCont", "Ch", "US pkts", "US bytes", "US B/s", "State", "Age",
            ])
            .style(Style::default().fg(Color::Cyan)),
        )
        .block(
            Block::default()
                .title(format!(
                    " Upstream [{}] — {visible_count}/{total_count} flows ",
                    self.activity_filter
                ))
                .borders(Borders::ALL)
                .border_style(if self.pane == Pane::Upstream {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                }),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
        let selected = self.us_selected.and_then(|selected| {
            self.filtered_upstream()
                .iter()
                .position(|flow| flow.flow_id == selected)
        });
        let mut state = TableState::default().with_selected(selected);
        frame.render_stateful_widget(table, area, &mut state);
    }

    fn render_logs(&self, frame: &mut ratatui::Frame, area: Rect) {
        let visible = area.height.saturating_sub(2) as usize;
        let items = self
            .logs
            .iter()
            .rev()
            .take(visible)
            .rev()
            .map(|line| ListItem::new(line.as_str()))
            .collect::<Vec<_>>();
        frame.render_widget(
            List::new(items).block(Block::default().title(" Event log ").borders(Borders::ALL)),
            area,
        );
    }

    fn render_actions(&self, frame: &mut ratatui::Frame, area: Rect) {
        let actions = match self.page {
            Page::Monitor => {
                "[r] Refresh  [f] Filter  [/] GEM  [a] Add  [d] Delete  [D] Delete all  [l] Listen-all  [p] Pause  [?] Help  [q] Quit"
            }
            Page::Autoscan if self.autoscan.running => {
                "[↑/↓] Select  [f] Active/all  [/] GEM  [x] Cancel  [e] Log"
            }
            Page::Autoscan if self.autoscan.recovery.is_some() => {
                "[R] Retry restore  [X] Abandon recovery  [e] Log  [?] Help"
            }
            Page::Autoscan if self.autoscan.result.is_some() => {
                "[f] Active/all  [/] GEM  [a] Add selected  [A] Add all active  [E] Export  [n] New scan  [s] Rerun  [?] Help  [q] Quit"
            }
            Page::Autoscan => "[Tab] Field  [Space] AES  [Enter/s] Start  [?] Help  [q] Quit",
            Page::Mib => {
                "[Enter/l] Load  [r] Refresh  [R] Catalog  [/] Search  [g] Lookup  [v] Parsed/raw  [Tab] Pane  [?] Help"
            }
        };
        let text = vec![
            Line::from(actions).style(Style::default().fg(Color::Yellow)),
            Line::from(self.status.as_str()).style(Style::default().fg(Color::Gray)),
        ];
        frame.render_widget(Paragraph::new(text), area);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let form = ConnectionForm::from_args(args);
    let (high_tx, high_rx) = mpsc::channel(32);
    let (sample_tx, sample_rx) = mpsc::channel(256);
    let (capture_tx, capture_rx) = mpsc::channel(8);
    let (event_tx, mut event_rx) = mpsc::channel(256);
    let capture = tokio::spawn(capture_worker(capture_rx, event_tx.clone()));
    let worker = tokio::spawn(backend_worker(high_rx, sample_rx, event_tx));
    let mut app = App::new(form, high_tx, sample_tx, capture_tx);
    let mut terminal = TerminalGuard::enter()?;

    while !app.should_quit {
        while let Ok(event) = event_rx.try_recv() {
            app.handle_backend_event(event);
        }
        app.start_sweep_if_due();
        terminal.terminal.draw(|frame| app.render(frame))?;
        if event::poll(Duration::from_millis(50)).context("poll terminal events")? {
            match event::read().context("read terminal event")? {
                Event::Key(key) if key.kind == event::KeyEventKind::Press => app.handle_key(key),
                Event::Mouse(mouse) => {
                    let size = terminal.terminal.size()?;
                    match mouse.kind {
                        MouseEventKind::Down(MouseButton::Left) => {
                            app.handle_mouse(mouse.column, mouse.row, size.height);
                        }
                        MouseEventKind::ScrollUp => {
                            app.handle_mouse_scroll(mouse.column, size.width, -1);
                        }
                        MouseEventKind::ScrollDown => {
                            app.handle_mouse_scroll(mouse.column, size.width, 1);
                        }
                        _ => {}
                    }
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }

    // Both workers are told to stop before either is awaited, so a capture
    // finalizing for up to two stop grace periods does not hold up the backend.
    // The terminal guard still drops only once both have returned.
    let _ = app.capture_tx.send(CaptureCommand::Quit).await;
    let _ = app.high_tx.send(BackendCommand::Quit).await;
    let _ = tokio::join!(capture, worker);
    Ok(())
}

#[cfg(test)]
mod tests;
