//! Deterministic, stateful mock implementation of the GPWN backend contract.
//!
//! The mock performs no network or device I/O and is suitable for examples,
//! UI development, and workflow tests. Run
//! `cargo run -p gpwn-mock --example snapshot` for a complete example.

use async_trait::async_trait;
use gpwn_core::{
    AddFlowRequest, AlarmCondition, BackendKind, ConnectionInfo, DeleteFlowRequest, DirectionScope,
    DownstreamFlow, Error, FlowCounters, FlowType, LineStatus, MibQuery, MibSelector,
    MibTableDescriptor, MibTableSnapshot, MutationReport, OnuBackend, OnuSnapshot, OnuState,
    OperationStep, Result, UpstreamFlow, allocate_flow_ids, parse_omci_mib_snapshot,
};
use std::collections::BTreeSet;
use std::time::SystemTime;

/// Deterministic device state exposed by [`MockBackend`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockScenario {
    /// An operational O5 ONU with clear alarms and representative flows.
    Healthy,
    /// A loss-of-signal ONU with active LOS/LOF alarms.
    Los,
    /// A backend that deterministically rejects connection attempts.
    ConnectionFailure,
}

impl MockScenario {
    /// Stable command-line name for this scenario.
    pub fn name(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Los => "los",
            Self::ConnectionFailure => "connection-failure",
        }
    }
}

/// Stateful in-process implementation of [`OnuBackend`].
pub struct MockBackend {
    scenario: MockScenario,
    connected: bool,
    info: Option<ConnectionInfo>,
    downstream: Vec<DownstreamFlow>,
    upstream: Vec<UpstreamFlow>,
    counter_reads: [u64; 128],
    listen_all_applied: bool,
}

impl MockBackend {
    /// Construct a disconnected backend with the selected deterministic state.
    pub fn new(scenario: MockScenario) -> Self {
        let downstream = vec![
            DownstreamFlow {
                flow_id: 0,
                gem_port: 165,
                flow_type: FlowType::Ethernet,
                multicast: false,
                aes: true,
            },
            DownstreamFlow {
                flow_id: 7,
                gem_port: 256,
                flow_type: FlowType::Ethernet,
                multicast: true,
                aes: false,
            },
        ];
        let upstream = vec![
            UpstreamFlow {
                flow_id: 0,
                gem_port: 165,
                flow_type: FlowType::Ethernet,
                tcont: Some(0),
                channel: Some(16),
                omci: false,
            },
            UpstreamFlow {
                flow_id: 4,
                gem_port: 1024,
                flow_type: FlowType::Omci,
                tcont: Some(1),
                channel: Some(17),
                omci: true,
            },
        ];
        Self {
            scenario,
            connected: false,
            info: None,
            downstream,
            upstream,
            counter_reads: [0; 128],
            listen_all_applied: false,
        }
    }

    fn ensure_connected(&self) -> Result<()> {
        if self.connected {
            Ok(())
        } else {
            Err(Error::NotConnected)
        }
    }

    fn line_status(&self) -> LineStatus {
        match self.scenario {
            MockScenario::Los => LineStatus {
                onu_state: OnuState::O2,
                state_description: "Standby State(O2)".into(),
                los: AlarmCondition::Active,
                lof: AlarmCondition::Active,
                lom: AlarmCondition::Clear,
                rx_power_dbm: Some(-39.8),
                tx_power_dbm: Some(0.0),
            },
            _ => LineStatus {
                onu_state: OnuState::O5,
                state_description: "Operation State(O5)".into(),
                los: AlarmCondition::Clear,
                lof: AlarmCondition::Clear,
                lom: AlarmCondition::Clear,
                rx_power_dbm: Some(-18.42),
                tx_power_dbm: Some(2.16),
            },
        }
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new(MockScenario::Healthy)
    }
}

#[async_trait]
impl OnuBackend for MockBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Mock
    }

    fn connection_info(&self) -> Option<&ConnectionInfo> {
        self.info.as_ref()
    }

    async fn connect(&mut self) -> Result<ConnectionInfo> {
        if self.scenario == MockScenario::ConnectionFailure {
            return Err(Error::Connection(
                "mock scenario rejected the connection".into(),
            ));
        }
        let info = ConnectionInfo {
            kind: BackendKind::Mock,
            endpoint: format!("mock://{}", self.scenario.name()),
            username: None,
            host_fingerprint: None,
            host_key_verified: true,
            connected_at: SystemTime::now(),
        };
        self.connected = true;
        self.info = Some(info.clone());
        Ok(info)
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        self.info = None;
        Ok(())
    }

    async fn fetch_snapshot(&mut self) -> Result<OnuSnapshot> {
        self.ensure_connected()?;
        Ok(OnuSnapshot {
            line: self.line_status(),
            downstream: self.downstream.clone(),
            upstream: self.upstream.clone(),
            fetched_at: SystemTime::now(),
        })
    }

    async fn read_flow_counters(&mut self, flow_id: u8) -> Result<FlowCounters> {
        self.ensure_connected()?;
        let read = self
            .counter_reads
            .get_mut(flow_id as usize)
            .ok_or_else(|| Error::Validation(format!("flow ID {flow_id} is outside 0..=127")))?;
        *read += 1;
        let downstream_gem = self
            .downstream
            .iter()
            .find(|flow| flow.flow_id == flow_id)
            .map(|flow| flow.gem_port);
        let upstream_active = self.upstream.iter().any(|flow| flow.flow_id == flow_id);
        if downstream_gem.is_none() && !upstream_active {
            return Ok(FlowCounters {
                flow_id,
                ..Default::default()
            });
        }
        // Autoscan tests and the mock TUI can discover a stable, sparse set of GEMs.
        let ds_active =
            downstream_gem.is_some_and(|gem| matches!(gem, 165 | 256 | 1024 | 2048 | 4095));
        let pulse = if ds_active {
            70 + downstream_gem.map(u64::from).unwrap_or_default() + (*read % 11)
        } else {
            0
        };
        let us_pulse = if upstream_active {
            20 + u64::from(flow_id)
        } else {
            0
        };
        Ok(FlowCounters {
            flow_id,
            ds_gem_packets: pulse,
            ds_gem_bytes: pulse * 842,
            ds_rx_eth_packets: pulse.saturating_sub(2),
            ds_fwd_eth_packets: pulse.saturating_sub(3),
            us_gem_packets: us_pulse,
            us_gem_bytes: us_pulse * 214,
            us_eth_packets: us_pulse,
        })
    }

    async fn list_omci_mib_tables(&mut self) -> Result<Vec<MibTableDescriptor>> {
        self.ensure_connected()?;
        Ok(mock_mib_catalog())
    }

    async fn fetch_omci_mib(&mut self, query: MibQuery) -> Result<MibTableSnapshot> {
        self.ensure_connected()?;
        query.validate()?;
        let name = match &query.selector {
            MibSelector::ClassId(256) => "Ontg".to_owned(),
            MibSelector::ClassId(268) => "GemPortCtp".to_owned(),
            MibSelector::ClassId(262) => "Tcont".to_owned(),
            MibSelector::ClassId(171) => "ExtVlanTagOperCfgData".to_owned(),
            MibSelector::ClassId(class_id) => {
                return Err(Error::Validation(format!(
                    "mock OMCI class {class_id} is not registered"
                )));
            }
            MibSelector::TableName(requested) => mock_mib_catalog()
                .into_iter()
                .find(|table| table.name.eq_ignore_ascii_case(requested))
                .map(|table| table.name)
                .ok_or_else(|| {
                    Error::Validation(format!("mock OMCI table {requested:?} is not registered"))
                })?,
        };
        parse_omci_mib_snapshot(mock_mib_output(&name), query)
    }

    async fn add_flows(&mut self, request: AddFlowRequest) -> Result<MutationReport> {
        self.ensure_connected()?;
        request.validate()?;
        let ids = allocate_flow_ids(
            request.scope,
            request.flow_ids,
            request.gem_ports.len(),
            &self.downstream,
            &self.upstream,
        )?;
        let mut report = MutationReport::default();
        for (flow_id, gem_port) in ids.into_iter().zip(request.gem_ports) {
            if matches!(
                request.scope,
                DirectionScope::Downstream | DirectionScope::Both
            ) {
                self.downstream.push(DownstreamFlow {
                    flow_id,
                    gem_port,
                    flow_type: request.flow_type,
                    multicast: request.multicast,
                    aes: request.aes,
                });
                report.steps.push(mock_step(format!(
                    "added downstream flow {flow_id} for GEM {gem_port}"
                )));
            }
            if matches!(
                request.scope,
                DirectionScope::Upstream | DirectionScope::Both
            ) {
                self.upstream.push(UpstreamFlow {
                    flow_id,
                    gem_port,
                    flow_type: request.flow_type,
                    tcont: Some(0),
                    channel: Some(16),
                    omci: request.flow_type == FlowType::Omci,
                });
                report.steps.push(mock_step(format!(
                    "added upstream flow {flow_id} for GEM {gem_port}"
                )));
            }
        }
        self.downstream.sort_by_key(|flow| flow.flow_id);
        self.upstream.sort_by_key(|flow| flow.flow_id);
        Ok(report)
    }

    async fn replace_downstream_flows(
        &mut self,
        mut flows: Vec<DownstreamFlow>,
    ) -> Result<MutationReport> {
        self.ensure_connected()?;
        let mut ids = BTreeSet::new();
        if flows.iter().any(|flow| {
            flow.flow_id > gpwn_core::FLOW_ID_MAX
                || flow.gem_port > gpwn_core::GEM_PORT_MAX
                || !ids.insert(flow.flow_id)
        }) {
            return Err(Error::Validation(
                "invalid or duplicate downstream flow in exact table".into(),
            ));
        }
        flows.sort_by_key(|flow| flow.flow_id);
        let removed = self.downstream.len();
        let added = flows.len();
        self.downstream = flows;
        self.counter_reads = [0; 128];
        let mut report = MutationReport::default();
        for _ in 0..removed {
            report.steps.push(mock_step("deleted downstream flow"));
        }
        for _ in 0..added {
            report.steps.push(mock_step("added downstream flow"));
        }
        Ok(report)
    }

    async fn delete_flows(&mut self, request: DeleteFlowRequest) -> Result<MutationReport> {
        self.ensure_connected()?;
        let requested: Option<BTreeSet<_>> = request.flow_ids.map(|ids| ids.into_iter().collect());
        let selected = |id: u8| requested.as_ref().is_none_or(|ids| ids.contains(&id));
        let mut report = MutationReport::default();
        if matches!(
            request.scope,
            DirectionScope::Downstream | DirectionScope::Both
        ) {
            let before = self.downstream.len();
            self.downstream.retain(|flow| !selected(flow.flow_id));
            for _ in 0..before - self.downstream.len() {
                report.steps.push(mock_step("deleted downstream flow"));
            }
        }
        if matches!(
            request.scope,
            DirectionScope::Upstream | DirectionScope::Both
        ) {
            let before = self.upstream.len();
            self.upstream.retain(|flow| !selected(flow.flow_id));
            for _ in 0..before - self.upstream.len() {
                report.steps.push(mock_step("deleted upstream flow"));
            }
        }
        if report.steps.is_empty() {
            report.steps.push(mock_step("no matching flows"));
        }
        Ok(report)
    }

    async fn apply_listen_all_setup(&mut self) -> Result<MutationReport> {
        self.ensure_connected()?;
        self.listen_all_applied = true;
        Ok(MutationReport {
            steps: (1..=12)
                .map(|index| mock_step(format!("listen-all command {index}/12")))
                .collect(),
        })
    }
}

fn mock_mib_catalog() -> Vec<MibTableDescriptor> {
    ["Ontg", "Tcont", "GemPortCtp", "ExtVlanTagOperCfgData"]
        .into_iter()
        .enumerate()
        .map(|(index, name)| MibTableDescriptor {
            internal_id: index as u16 + 1,
            name: name.into(),
        })
        .collect()
}

fn mock_mib_output(name: &str) -> &'static str {
    match name {
        "Ontg" => {
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nOntg\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
             =================================\nEntityID: 0x00\nVID: MOCK\nVersion: 1.0\n\
             SerialNum: MOCK00000001\nAdminState: 0\nOpState: 0\n=================================\n"
        }
        "GemPortCtp" => {
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nGemPortCtp\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
             =================================\nEntityID: 0x0100\nPortID: 165\nTcAdapterPtr: 0x8000\n\
             Direction: 3\nEncryptionState: 1\n=================================\n\
             =================================\nEntityID: 0x0101\nPortID: 256\nTcAdapterPtr: 0x8001\n\
             Direction: 3\nEncryptionState: 0\n=================================\n"
        }
        "Tcont" => {
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nTcont\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
             =================================\nEntityID: 0x8000\nAllocID: 1024\nPolicy: 2\n=================================\n"
        }
        "ExtVlanTagOperCfgData" => {
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nExtVlanTagOperCfgData\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
        }
        _ => unreachable!("mock catalog and output must agree"),
    }
}

fn mock_step(message: impl Into<String>) -> OperationStep {
    OperationStep {
        description: "mock operation".into(),
        command: None,
        success: true,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpwn_core::{FlowIdChoice, FlowType};

    #[test]
    fn scenario_names_are_stable() {
        assert_eq!(MockScenario::Healthy.name(), "healthy");
        assert_eq!(MockScenario::Los.name(), "los");
    }

    #[tokio::test]
    async fn mock_mutates_both_tables_with_a_common_id() {
        let mut backend = MockBackend::default();
        backend.connect().await.unwrap();
        backend
            .add_flows(AddFlowRequest {
                scope: DirectionScope::Both,
                flow_ids: FlowIdChoice::Auto,
                gem_ports: vec![777],
                flow_type: FlowType::Ethernet,
                multicast: false,
                aes: true,
            })
            .await
            .unwrap();
        let snapshot = backend.fetch_snapshot().await.unwrap();
        let ds = snapshot
            .downstream
            .iter()
            .find(|flow| flow.gem_port == 777)
            .unwrap();
        let us = snapshot
            .upstream
            .iter()
            .find(|flow| flow.gem_port == 777)
            .unwrap();
        assert_eq!(ds.flow_id, us.flow_id);
    }

    #[tokio::test]
    async fn counter_reads_are_interval_values() {
        let mut backend = MockBackend::default();
        backend.connect().await.unwrap();
        let first = backend.read_flow_counters(0).await.unwrap();
        let second = backend.read_flow_counters(0).await.unwrap();
        assert_ne!(first.ds_gem_bytes, second.ds_gem_bytes);
    }

    #[tokio::test]
    async fn mock_exposes_read_only_omci_mib_data() {
        let mut backend = MockBackend::default();
        backend.connect().await.unwrap();
        let catalog = backend.list_omci_mib_tables().await.unwrap();
        assert!(catalog.iter().any(|table| table.name == "Ontg"));

        let snapshot = backend
            .fetch_omci_mib(MibQuery {
                selector: MibSelector::ClassId(256),
                entity_id: Some(0),
            })
            .await
            .unwrap();
        assert_eq!(snapshot.table_name, "Ontg");
        assert_eq!(snapshot.entities.len(), 1);
        assert_eq!(snapshot.entities[0].entity_id, 0);
        assert!(!snapshot.entities[0].attributes.is_empty());
    }
}
