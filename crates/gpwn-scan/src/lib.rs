//! Transport-independent downstream GEM activity scanning and result application.
//!
//! Scans temporarily replace the downstream table, observe counters, and
//! restore the exact original configuration before returning. Run
//! `cargo run -p gpwn-scan --example batches` to inspect scan partitioning.

use gpwn_core::{
    AddFlowRequest, DeleteFlowRequest, DirectionScope, DownstreamFlow, Error, FLOW_ID_MAX,
    FlowIdChoice, FlowType, GEM_PORT_MAX, MutationReport, OnuBackend, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

/// Range, batching, observation, and encryption settings for one scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AutoscanConfig {
    /// First GEM port in the inclusive scan range.
    pub gem_start: u16,
    /// Last GEM port in the inclusive scan range.
    pub gem_end: u16,
    /// Number of GEM ports temporarily programmed per batch.
    pub batch_size: u8,
    /// Counter observation window for each batch, in seconds.
    pub observation_secs: f64,
    /// Whether temporary downstream flows request AES decryption.
    pub aes: bool,
}

impl Default for AutoscanConfig {
    fn default() -> Self {
        Self {
            gem_start: 0,
            gem_end: GEM_PORT_MAX,
            batch_size: 128,
            observation_secs: 5.0,
            aes: false,
        }
    }
}

impl AutoscanConfig {
    /// Validate the GEM range, batch size, and observation duration.
    pub fn validate(&self) -> Result<()> {
        if self.gem_start > self.gem_end || self.gem_end > GEM_PORT_MAX {
            return Err(Error::Validation(
                "autoscan GEM range must be within 0..=4095 and start <= end".into(),
            ));
        }
        if self.batch_size == 0 || self.batch_size > 128 {
            return Err(Error::Validation(
                "autoscan batch size must be in 1..=128".into(),
            ));
        }
        if !self.observation_secs.is_finite() || self.observation_secs < 0.0 {
            return Err(Error::Validation(
                "autoscan observation window must be a non-negative number".into(),
            ));
        }
        Ok(())
    }

    /// Return the number of batches needed to cover the configured range.
    pub fn total_batches(&self) -> usize {
        let count = usize::from(self.gem_end - self.gem_start) + 1;
        count.div_ceil(usize::from(self.batch_size))
    }

    /// Partition the configured range into inclusive `(start, end)` batches.
    pub fn batches(&self) -> Vec<(u16, u16)> {
        let size = u16::from(self.batch_size);
        let mut batches = Vec::new();
        let mut start = self.gem_start;
        loop {
            let end = start.saturating_add(size - 1).min(self.gem_end);
            batches.push((start, end));
            if end == self.gem_end {
                break;
            }
            start = end + 1;
        }
        batches
    }
}

/// Lifecycle state reported by an autoscan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoscanPhase {
    /// Saving the device's original downstream flow table.
    Snapshot,
    /// Programming temporary downstream flows for a scan batch.
    Programming,
    /// Reading and thereby resetting counters before observation.
    Resetting,
    /// Waiting for traffic to arrive during the observation window.
    Observing,
    /// Reading counters and producing per-port activity records.
    Measuring,
    /// Restoring the original downstream flow table.
    Restoring,
    /// The scan and restoration both completed successfully.
    Completed,
    /// Cooperative cancellation stopped the scan.
    Cancelled,
    /// The scan failed before successful completion.
    Failed,
    /// Restoration failed and should be retried by the caller.
    RestorePending,
}

impl std::fmt::Display for AutoscanPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Incremental progress notification emitted by [`run_autoscan`].
#[derive(Debug, Clone)]
pub struct ScanProgress {
    /// Current scan lifecycle phase.
    pub phase: AutoscanPhase,
    /// Zero-based index of the batch being processed.
    pub batch_index: usize,
    /// Total number of configured batches.
    pub total_batches: usize,
    /// First GEM port in the current inclusive range.
    pub gem_start: u16,
    /// Last GEM port in the current inclusive range.
    pub gem_end: u16,
    /// One-based completed-item count within the current operation.
    pub item_index: usize,
    /// Total item count for the current operation.
    pub item_total: usize,
    /// Human-readable description of the current work or outcome.
    pub message: String,
    /// Newly measured activity when the notification reports a port result.
    pub activity: Option<GemPortActivity>,
}

/// Counter evidence observed for one GEM port.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GemPortActivity {
    /// GEM port that was measured.
    pub gem_port: u16,
    /// Zero-based batch index in which the port was measured.
    pub batch_index: usize,
    /// Downstream GEM packets counted during observation.
    pub ds_gem_packets: u64,
    /// Downstream GEM bytes counted during observation.
    pub ds_gem_bytes: u64,
    /// Downstream Ethernet packets received during observation.
    pub ds_rx_eth_packets: u64,
    /// Downstream Ethernet packets forwarded during observation.
    pub ds_fwd_eth_packets: u64,
    /// Actual interval between counter reset and measurement.
    pub elapsed_secs: f64,
    /// Observed downstream GEM packet rate.
    pub packets_per_sec: f64,
    /// Observed downstream GEM byte rate.
    pub bytes_per_sec: f64,
}

impl GemPortActivity {
    /// Return whether any measured counter indicates traffic.
    pub fn is_active(&self) -> bool {
        self.ds_gem_packets != 0
            || self.ds_gem_bytes != 0
            || self.ds_rx_eth_packets != 0
            || self.ds_fwd_eth_packets != 0
    }
}

/// Results for one programmed range of GEM ports.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchResult {
    /// Zero-based batch index.
    pub batch_index: usize,
    /// First GEM port in the batch's inclusive range.
    pub gem_start: u16,
    /// Last GEM port in the batch's inclusive range.
    pub gem_end: u16,
    /// Per-port counter observations in the batch.
    pub activities: Vec<GemPortActivity>,
}

/// Serializable result and terminal status of an autoscan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AutoscanResult {
    /// Serialization schema version for compatibility checks.
    pub schema_version: u8,
    /// Configuration used for the scan.
    pub config: AutoscanConfig,
    /// Final lifecycle phase reached by the scan.
    pub terminal_phase: AutoscanPhase,
    /// Completed batch results.
    pub batches: Vec<BatchResult>,
    /// Total scan wall time in seconds.
    pub wall_time_secs: f64,
    /// Scan error, when scanning itself failed.
    pub error: Option<String>,
    /// Restoration error, when the original table could not be restored.
    pub restore_error: Option<String>,
}

impl AutoscanResult {
    /// Iterate over every per-port activity record across all batches.
    pub fn activities(&self) -> impl Iterator<Item = &GemPortActivity> {
        self.batches.iter().flat_map(|batch| &batch.activities)
    }

    /// Collect activity records whose counters indicate traffic.
    pub fn active_ports(&self) -> Vec<&GemPortActivity> {
        self.activities().filter(|row| row.is_active()).collect()
    }

    /// Return the number of GEM ports for which results were recorded.
    pub fn scanned_count(&self) -> usize {
        self.activities().count()
    }
}

/// Autoscan result plus the original table retained for restoration retries.
#[derive(Debug, Clone)]
pub struct ScanOutcome {
    /// Serializable scan result and terminal status.
    pub result: AutoscanResult,
    /// Retained so a UI can retry a failed restoration while the process remains alive.
    pub original_downstream: Vec<DownstreamFlow>,
}

/// Cheap cooperative-cancellation flag for an in-progress scan.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Request cooperative cancellation of the associated scan.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Return whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

fn ensure_report(report: MutationReport, operation: &str) -> Result<()> {
    if report.succeeded() {
        Ok(())
    } else {
        let message = report
            .steps
            .iter()
            .find(|step| !step.success)
            .map(|step| step.message.clone())
            .unwrap_or_else(|| "device rejected a command".into());
        Err(Error::Backend(format!("{operation}: {message}")))
    }
}

/// Scan a GEM range for downstream activity and restore the original table.
///
/// `progress` receives lifecycle and measurement updates synchronously. The
/// returned outcome retains the original flow table when restoration needs a
/// later retry.
pub async fn run_autoscan<F>(
    backend: &mut dyn OnuBackend,
    config: AutoscanConfig,
    cancel: CancellationToken,
    mut progress: F,
) -> ScanOutcome
where
    F: FnMut(ScanProgress) + Send,
{
    let started = Instant::now();
    let mut result = AutoscanResult {
        schema_version: 1,
        config: config.clone(),
        terminal_phase: AutoscanPhase::Failed,
        batches: Vec::new(),
        wall_time_secs: 0.0,
        error: None,
        restore_error: None,
    };
    if let Err(error) = config.validate() {
        result.error = Some(error.to_string());
        return ScanOutcome {
            result,
            original_downstream: Vec::new(),
        };
    }

    progress(ScanProgress {
        phase: AutoscanPhase::Snapshot,
        batch_index: 0,
        total_batches: config.total_batches(),
        gem_start: config.gem_start,
        gem_end: config.gem_end,
        item_index: 0,
        item_total: 0,
        message: "Saving the original downstream table".into(),
        activity: None,
    });
    let original = match backend.fetch_snapshot().await {
        Ok(snapshot) => snapshot.downstream,
        Err(error) => {
            result.error = Some(error.to_string());
            return ScanOutcome {
                result,
                original_downstream: Vec::new(),
            };
        }
    };

    let scan_result = scan_batches(backend, &config, &cancel, &mut progress, &mut result).await;
    match scan_result {
        Ok(()) if cancel.is_cancelled() => result.terminal_phase = AutoscanPhase::Cancelled,
        Ok(()) => result.terminal_phase = AutoscanPhase::Completed,
        Err(error) => {
            result.terminal_phase = if cancel.is_cancelled() {
                AutoscanPhase::Cancelled
            } else {
                AutoscanPhase::Failed
            };
            result.error = Some(error.to_string());
        }
    }

    progress(ScanProgress {
        phase: AutoscanPhase::Restoring,
        batch_index: result.batches.len(),
        total_batches: config.total_batches(),
        gem_start: config.gem_start,
        gem_end: config.gem_end,
        item_index: 0,
        item_total: original.len(),
        message: "Restoring the original downstream table".into(),
        activity: None,
    });
    match backend.replace_downstream_flows(original.clone()).await {
        Ok(report) => {
            if let Err(error) = ensure_report(report, "restore downstream table") {
                result.restore_error = Some(error.to_string());
                result.terminal_phase = AutoscanPhase::RestorePending;
            }
        }
        Err(error) => {
            result.restore_error = Some(error.to_string());
            result.terminal_phase = AutoscanPhase::RestorePending;
        }
    }
    result.wall_time_secs = started.elapsed().as_secs_f64();
    progress(ScanProgress {
        phase: result.terminal_phase,
        batch_index: result.batches.len(),
        total_batches: config.total_batches(),
        gem_start: config.gem_start,
        gem_end: config.gem_end,
        item_index: result.scanned_count(),
        item_total: usize::from(config.gem_end - config.gem_start) + 1,
        message: result
            .restore_error
            .clone()
            .or_else(|| result.error.clone())
            .unwrap_or_else(|| format!("{} GEM ports scanned", result.scanned_count())),
        activity: None,
    });
    ScanOutcome {
        result,
        original_downstream: original,
    }
}

async fn scan_batches<F>(
    backend: &mut dyn OnuBackend,
    config: &AutoscanConfig,
    cancel: &CancellationToken,
    progress: &mut F,
    result: &mut AutoscanResult,
) -> Result<()>
where
    F: FnMut(ScanProgress) + Send,
{
    let ranges = config.batches();
    for (batch_index, (gem_start, gem_end)) in ranges.iter().copied().enumerate() {
        if cancel.is_cancelled() {
            return Ok(());
        }
        let count = usize::from(gem_end - gem_start) + 1;
        progress(ScanProgress {
            phase: AutoscanPhase::Programming,
            batch_index,
            total_batches: ranges.len(),
            gem_start,
            gem_end,
            item_index: 0,
            item_total: count,
            message: format!("Programming GEM {gem_start}–{gem_end}"),
            activity: None,
        });
        let flows = (gem_start..=gem_end)
            .enumerate()
            .map(|(flow_id, gem_port)| DownstreamFlow {
                flow_id: flow_id as u8,
                gem_port,
                flow_type: FlowType::Ethernet,
                multicast: false,
                aes: config.aes,
            })
            .collect();
        ensure_report(
            backend.replace_downstream_flows(flows).await?,
            "program scan batch",
        )?;

        let mut reset_at = BTreeMap::new();
        for flow_id in 0..count {
            if cancel.is_cancelled() {
                return Ok(());
            }
            progress(ScanProgress {
                phase: AutoscanPhase::Resetting,
                batch_index,
                total_batches: ranges.len(),
                gem_start,
                gem_end,
                item_index: flow_id + 1,
                item_total: count,
                message: "Resetting downstream counters".into(),
                activity: None,
            });
            backend.read_flow_counters(flow_id as u8).await?;
            reset_at.insert(flow_id as u8, Instant::now());
        }

        let wait = Duration::from_secs_f64(config.observation_secs);
        let wait_started = Instant::now();
        while wait_started.elapsed() < wait {
            if cancel.is_cancelled() {
                return Ok(());
            }
            progress(ScanProgress {
                phase: AutoscanPhase::Observing,
                batch_index,
                total_batches: ranges.len(),
                gem_start,
                gem_end,
                item_index: wait_started.elapsed().as_millis() as usize,
                item_total: wait.as_millis() as usize,
                message: format!(
                    "Observing traffic ({:.1}s remaining)",
                    wait.saturating_sub(wait_started.elapsed()).as_secs_f64()
                ),
                activity: None,
            });
            tokio::time::sleep(
                wait.saturating_sub(wait_started.elapsed())
                    .min(Duration::from_millis(100)),
            )
            .await;
        }

        let mut activities = Vec::with_capacity(count);
        for flow_id in 0..count {
            if cancel.is_cancelled() {
                return Ok(());
            }
            progress(ScanProgress {
                phase: AutoscanPhase::Measuring,
                batch_index,
                total_batches: ranges.len(),
                gem_start,
                gem_end,
                item_index: flow_id + 1,
                item_total: count,
                message: "Reading downstream activity".into(),
                activity: None,
            });
            let counters = backend.read_flow_counters(flow_id as u8).await?;
            let elapsed = reset_at[&(flow_id as u8)].elapsed().as_secs_f64();
            let safe_elapsed = elapsed.max(0.001);
            let activity = GemPortActivity {
                gem_port: gem_start + flow_id as u16,
                batch_index,
                ds_gem_packets: counters.ds_gem_packets,
                ds_gem_bytes: counters.ds_gem_bytes,
                ds_rx_eth_packets: counters.ds_rx_eth_packets,
                ds_fwd_eth_packets: counters.ds_fwd_eth_packets,
                elapsed_secs: elapsed,
                packets_per_sec: counters.ds_gem_packets as f64 / safe_elapsed,
                bytes_per_sec: counters.ds_gem_bytes as f64 / safe_elapsed,
            };
            progress(ScanProgress {
                phase: AutoscanPhase::Measuring,
                batch_index,
                total_batches: ranges.len(),
                gem_start,
                gem_end,
                item_index: flow_id + 1,
                item_total: count,
                message: if activity.is_active() {
                    format!("Active GEM {} detected", activity.gem_port)
                } else {
                    format!("Measured GEM {}", activity.gem_port)
                },
                activity: Some(activity.clone()),
            });
            activities.push(activity);
        }
        result.batches.push(BatchResult {
            batch_index,
            gem_start,
            gem_end,
            activities,
        });
    }
    Ok(())
}

/// Retry replacing the downstream table with a previously saved snapshot.
pub async fn retry_restore(
    backend: &mut dyn OnuBackend,
    original: Vec<DownstreamFlow>,
) -> Result<()> {
    ensure_report(
        backend.replace_downstream_flows(original).await?,
        "restore downstream table",
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Capacity and deduplication plan for applying active scan results.
pub struct ApplyPlan {
    /// Active GEM ports already present in the current table.
    pub already_configured: Vec<u16>,
    /// Active, unconfigured GEM ports ordered by decreasing activity.
    pub candidates: Vec<u16>,
    /// Downstream flow identifiers available for candidates.
    pub free_flow_ids: Vec<u8>,
}

impl ApplyPlan {
    /// Return whether every candidate can be assigned a free flow identifier.
    pub fn capacity_sufficient(&self) -> bool {
        self.candidates.len() <= self.free_flow_ids.len()
    }
}

/// Plan how active scan results fit alongside current downstream flows.
pub fn plan_active_apply(result: &AutoscanResult, current: &[DownstreamFlow]) -> ApplyPlan {
    let configured: BTreeSet<_> = current.iter().map(|flow| flow.gem_port).collect();
    let mut active: BTreeMap<u16, f64> = BTreeMap::new();
    for row in result.activities().filter(|row| row.is_active()) {
        active
            .entry(row.gem_port)
            .and_modify(|rate| *rate = rate.max(row.packets_per_sec))
            .or_insert(row.packets_per_sec);
    }
    let already_configured = active
        .keys()
        .filter(|gem| configured.contains(gem))
        .copied()
        .collect();
    let mut candidates: Vec<_> = active
        .into_iter()
        .filter(|(gem, _)| !configured.contains(gem))
        .collect();
    candidates.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    let used: BTreeSet<_> = current.iter().map(|flow| flow.flow_id).collect();
    let free_flow_ids = (0..=FLOW_ID_MAX).filter(|id| !used.contains(id)).collect();
    ApplyPlan {
        already_configured,
        candidates: candidates.into_iter().map(|(gem, _)| gem).collect(),
        free_flow_ids,
    }
}

#[derive(Debug, Clone, Default)]
/// Outcome of adding selected active GEM ports, including rollback details.
pub struct ApplyResult {
    /// Successfully added `(flow_id, gem_port)` pairs.
    pub added: Vec<(u8, u16)>,
    /// Flow identifiers removed during rollback after a later failure.
    pub rolled_back: Vec<u8>,
    /// GEM port whose add operation failed, if any.
    pub failed_gem: Option<u16>,
    /// Device or rollback error reported by the operation.
    pub error: Option<String>,
}

/// Add selected active GEM ports to the downstream table transactionally.
///
/// Ports already configured are ignored. If an add fails, previously added
/// flows from this invocation are removed in reverse order.
pub async fn apply_active_ports(
    backend: &mut dyn OnuBackend,
    selected_gems: Vec<u16>,
    aes: bool,
) -> Result<ApplyResult> {
    let snapshot = backend.fetch_snapshot().await?;
    let configured: BTreeSet<_> = snapshot
        .downstream
        .iter()
        .map(|flow| flow.gem_port)
        .collect();
    let selected: Vec<_> = selected_gems
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|gem| !configured.contains(gem))
        .collect();
    let used: BTreeSet<_> = snapshot
        .downstream
        .iter()
        .map(|flow| flow.flow_id)
        .collect();
    let free: Vec<_> = (0..=FLOW_ID_MAX)
        .filter(|id| !used.contains(id))
        .take(selected.len())
        .collect();
    if free.len() != selected.len() {
        return Err(Error::Validation(format!(
            "not enough free downstream flow IDs: need {}, found {}",
            selected.len(),
            free.len()
        )));
    }

    let mut outcome = ApplyResult::default();
    for (flow_id, gem_port) in free.into_iter().zip(selected) {
        let request = AddFlowRequest {
            scope: DirectionScope::Downstream,
            flow_ids: FlowIdChoice::Exact(flow_id),
            gem_ports: vec![gem_port],
            flow_type: FlowType::Ethernet,
            multicast: false,
            aes,
        };
        match backend.add_flows(request).await {
            Ok(report) if report.succeeded() => outcome.added.push((flow_id, gem_port)),
            Ok(report) => {
                outcome.failed_gem = Some(gem_port);
                outcome.error = Some(
                    report
                        .steps
                        .iter()
                        .find(|step| !step.success)
                        .map(|step| step.message.clone())
                        .unwrap_or_else(|| "device rejected add".into()),
                );
                break;
            }
            Err(error) => {
                outcome.failed_gem = Some(gem_port);
                outcome.error = Some(error.to_string());
                break;
            }
        }
    }
    if outcome.error.is_some() && !outcome.added.is_empty() {
        let ids: Vec<_> = outcome.added.iter().map(|(id, _)| *id).collect();
        match backend
            .delete_flows(DeleteFlowRequest {
                scope: DirectionScope::Downstream,
                flow_ids: Some(ids.clone()),
            })
            .await
        {
            Ok(report) if report.succeeded() => outcome.rolled_back = ids,
            Ok(_) => {
                outcome
                    .error
                    .get_or_insert_with(String::new)
                    .push_str("; rollback was incomplete");
            }
            Err(error) => {
                outcome
                    .error
                    .get_or_insert_with(String::new)
                    .push_str(&format!("; rollback failed: {error}"));
            }
        }
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use gpwn_core::{
        BackendKind, ConnectionInfo, FlowCounters, MibQuery, MibTableDescriptor, MibTableSnapshot,
        OnuSnapshot,
    };
    use gpwn_mock::{MockBackend, MockScenario};

    struct FailReplaceOnce {
        inner: MockBackend,
        fail_on_call: usize,
        calls: usize,
    }

    impl FailReplaceOnce {
        fn new(fail_on_call: usize) -> Self {
            Self {
                inner: MockBackend::new(MockScenario::Healthy),
                fail_on_call,
                calls: 0,
            }
        }
    }

    #[async_trait]
    impl OnuBackend for FailReplaceOnce {
        fn kind(&self) -> BackendKind {
            self.inner.kind()
        }

        fn connection_info(&self) -> Option<&ConnectionInfo> {
            self.inner.connection_info()
        }

        async fn connect(&mut self) -> Result<ConnectionInfo> {
            self.inner.connect().await
        }

        async fn disconnect(&mut self) -> Result<()> {
            self.inner.disconnect().await
        }

        async fn fetch_snapshot(&mut self) -> Result<OnuSnapshot> {
            self.inner.fetch_snapshot().await
        }

        async fn read_flow_counters(&mut self, flow_id: u8) -> Result<FlowCounters> {
            self.inner.read_flow_counters(flow_id).await
        }

        async fn list_omci_mib_tables(&mut self) -> Result<Vec<MibTableDescriptor>> {
            self.inner.list_omci_mib_tables().await
        }

        async fn fetch_omci_mib(&mut self, query: MibQuery) -> Result<MibTableSnapshot> {
            self.inner.fetch_omci_mib(query).await
        }

        async fn replace_downstream_flows(
            &mut self,
            flows: Vec<DownstreamFlow>,
        ) -> Result<MutationReport> {
            self.calls += 1;
            if self.calls == self.fail_on_call {
                Err(Error::Backend("injected replacement failure".into()))
            } else {
                self.inner.replace_downstream_flows(flows).await
            }
        }

        async fn add_flows(&mut self, request: AddFlowRequest) -> Result<MutationReport> {
            self.inner.add_flows(request).await
        }

        async fn delete_flows(&mut self, request: DeleteFlowRequest) -> Result<MutationReport> {
            self.inner.delete_flows(request).await
        }

        async fn apply_listen_all_setup(&mut self) -> Result<MutationReport> {
            self.inner.apply_listen_all_setup().await
        }
    }

    #[test]
    fn partitions_inclusive_range() {
        let config = AutoscanConfig {
            gem_start: 10,
            gem_end: 20,
            batch_size: 4,
            observation_secs: 0.0,
            aes: false,
        };
        assert_eq!(config.batches(), vec![(10, 13), (14, 17), (18, 20)]);
    }

    #[tokio::test]
    async fn scan_restores_original_table() {
        let mut backend = MockBackend::new(MockScenario::Healthy);
        backend.connect().await.unwrap();
        let original = backend.fetch_snapshot().await.unwrap().downstream;
        let outcome = run_autoscan(
            &mut backend,
            AutoscanConfig {
                gem_start: 160,
                gem_end: 170,
                batch_size: 6,
                observation_secs: 0.0,
                aes: false,
            },
            CancellationToken::default(),
            |_| {},
        )
        .await;
        assert_eq!(outcome.result.terminal_phase, AutoscanPhase::Completed);
        assert_eq!(
            outcome
                .result
                .active_ports()
                .iter()
                .map(|row| row.gem_port)
                .collect::<Vec<_>>(),
            vec![165]
        );
        assert_eq!(backend.fetch_snapshot().await.unwrap().downstream, original);
    }

    #[tokio::test]
    async fn pre_cancelled_scan_keeps_partial_result_and_restores() {
        let mut backend = MockBackend::new(MockScenario::Healthy);
        backend.connect().await.unwrap();
        let original = backend.fetch_snapshot().await.unwrap().downstream;
        let cancel = CancellationToken::default();
        cancel.cancel();
        let outcome = run_autoscan(
            &mut backend,
            AutoscanConfig {
                gem_start: 0,
                gem_end: 10,
                batch_size: 4,
                observation_secs: 0.0,
                aes: false,
            },
            cancel,
            |_| {},
        )
        .await;
        assert_eq!(outcome.result.terminal_phase, AutoscanPhase::Cancelled);
        assert_eq!(outcome.result.scanned_count(), 0);
        assert_eq!(backend.fetch_snapshot().await.unwrap().downstream, original);
    }

    #[tokio::test]
    async fn applies_only_missing_active_ports() {
        let mut backend = MockBackend::new(MockScenario::Healthy);
        backend.connect().await.unwrap();
        let scan = run_autoscan(
            &mut backend,
            AutoscanConfig {
                gem_start: 1024,
                gem_end: 1024,
                batch_size: 1,
                observation_secs: 0.0,
                aes: true,
            },
            CancellationToken::default(),
            |_| {},
        )
        .await;
        let snapshot = backend.fetch_snapshot().await.unwrap();
        let plan = plan_active_apply(&scan.result, &snapshot.downstream);
        assert_eq!(plan.candidates, vec![1024]);
        let applied = apply_active_ports(&mut backend, plan.candidates, true)
            .await
            .unwrap();
        assert_eq!(applied.error, None);
        let snapshot = backend.fetch_snapshot().await.unwrap();
        let flow = snapshot
            .downstream
            .iter()
            .find(|flow| flow.gem_port == 1024)
            .unwrap();
        assert!(flow.aes);
        assert_eq!(flow.flow_type, FlowType::Ethernet);
    }

    #[tokio::test]
    async fn restore_failure_retains_table_for_retry() {
        let mut backend = FailReplaceOnce::new(2);
        backend.connect().await.unwrap();
        let original = backend.fetch_snapshot().await.unwrap().downstream;
        let outcome = run_autoscan(
            &mut backend,
            AutoscanConfig {
                gem_start: 165,
                gem_end: 165,
                batch_size: 1,
                observation_secs: 0.0,
                aes: false,
            },
            CancellationToken::default(),
            |_| {},
        )
        .await;
        assert_eq!(outcome.result.terminal_phase, AutoscanPhase::RestorePending);
        assert_eq!(outcome.original_downstream, original);
        retry_restore(&mut backend, outcome.original_downstream)
            .await
            .unwrap();
        assert_eq!(backend.fetch_snapshot().await.unwrap().downstream, original);
    }

    #[tokio::test]
    async fn batch_failure_still_restores_original_table() {
        let mut backend = FailReplaceOnce::new(1);
        backend.connect().await.unwrap();
        let original = backend.fetch_snapshot().await.unwrap().downstream;
        let outcome = run_autoscan(
            &mut backend,
            AutoscanConfig {
                gem_start: 0,
                gem_end: 1,
                batch_size: 2,
                observation_secs: 0.0,
                aes: false,
            },
            CancellationToken::default(),
            |_| {},
        )
        .await;
        assert_eq!(outcome.result.terminal_phase, AutoscanPhase::Failed);
        assert!(outcome.result.error.is_some());
        assert_eq!(backend.fetch_snapshot().await.unwrap().downstream, original);
    }

    #[test]
    fn apply_plan_deduplicates_and_ranks() {
        let result = AutoscanResult {
            schema_version: 1,
            config: AutoscanConfig::default(),
            terminal_phase: AutoscanPhase::Completed,
            batches: vec![BatchResult {
                batch_index: 0,
                gem_start: 1,
                gem_end: 3,
                activities: vec![
                    GemPortActivity {
                        gem_port: 1,
                        batch_index: 0,
                        ds_gem_packets: 1,
                        ds_gem_bytes: 1,
                        ds_rx_eth_packets: 0,
                        ds_fwd_eth_packets: 0,
                        elapsed_secs: 1.0,
                        packets_per_sec: 1.0,
                        bytes_per_sec: 1.0,
                    },
                    GemPortActivity {
                        gem_port: 2,
                        batch_index: 0,
                        ds_gem_packets: 10,
                        ds_gem_bytes: 10,
                        ds_rx_eth_packets: 0,
                        ds_fwd_eth_packets: 0,
                        elapsed_secs: 1.0,
                        packets_per_sec: 10.0,
                        bytes_per_sec: 10.0,
                    },
                ],
            }],
            wall_time_secs: 1.0,
            error: None,
            restore_error: None,
        };
        let current = vec![DownstreamFlow {
            flow_id: 4,
            gem_port: 1,
            flow_type: FlowType::Omci,
            multicast: true,
            aes: true,
        }];
        let plan = plan_active_apply(&result, &current);
        assert_eq!(plan.already_configured, vec![1]);
        assert_eq!(plan.candidates, vec![2]);
        assert!(!plan.free_flow_ids.contains(&4));
    }
}
