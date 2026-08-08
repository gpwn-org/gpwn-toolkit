use super::*;

pub(super) enum BackendSettings {
    Live {
        config: ConnectionConfig,
        poll_interval: Duration,
    },
    Mock {
        scenario: MockScenario,
        poll_interval: Duration,
    },
}

impl BackendSettings {
    pub(super) fn poll_interval(&self) -> Duration {
        match self {
            Self::Live { poll_interval, .. } | Self::Mock { poll_interval, .. } => *poll_interval,
        }
    }

    pub(super) fn endpoint(&self) -> String {
        match self {
            Self::Live { config, .. } => format!("{}:{}", config.host, config.port),
            Self::Mock { scenario, .. } => format!("mock://{}", scenario.name()),
        }
    }
}

pub(super) enum BackendCommand {
    Connect(BackendSettings),
    Refresh,
    Add(AddFlowRequest),
    Delete(DeleteFlowRequest),
    Setup,
    StartScan {
        config: AutoscanConfig,
        cancel: CancellationToken,
    },
    RetryRestore(Vec<gpwn_core::DownstreamFlow>),
    ApplyActive {
        gem_ports: Vec<u16>,
        aes: bool,
    },
    MibCatalog,
    MibFetch(MibQuery),
    Quit,
}

pub(super) enum SampleCommand {
    Read(u8),
}

/// Capture runs on its own channel so a stop is never queued behind an
/// in-flight SSH operation; a flow-table read alone is four device commands.
pub(super) enum CaptureCommand {
    Start(CaptureConfig),
    Stop,
    Quit,
}

pub(super) enum BackendEvent {
    Connecting,
    Connected(ConnectionInfo),
    Snapshot(OnuSnapshot),
    Sample {
        counters: FlowCounters,
        at: Instant,
    },
    Report {
        operation: &'static str,
        report: MutationReport,
    },
    ScanProgress(ScanProgress),
    ScanFinished(ScanOutcome),
    RestoreRetried {
        result: Result<(), String>,
    },
    ActiveApplied(ApplyResult),
    MibCatalog(Vec<MibTableDescriptor>),
    MibSnapshot(MibTableSnapshot),
    CaptureStarted {
        path: PathBuf,
        config: CaptureConfig,
    },
    CaptureProgress {
        bytes: u64,
    },
    CaptureStopped(CaptureSummary),
    CaptureFailed {
        message: String,
    },
    Error {
        operation: &'static str,
        message: String,
        disconnected: bool,
    },
}

pub(super) async fn capture_worker(
    mut commands: mpsc::Receiver<CaptureCommand>,
    events: mpsc::Sender<BackendEvent>,
) {
    let mut active: Option<Capture> = None;
    let mut ticker = tokio::time::interval(Duration::from_millis(500));
    loop {
        tokio::select! {
            biased;
            command = commands.recv() => {
                match command {
                    Some(CaptureCommand::Start(config)) => {
                        if active.is_some() {
                            continue;
                        }
                        match Capture::start(&config).await {
                            Ok(capture) => {
                                let _ = events.send(BackendEvent::CaptureStarted {
                                    path: capture.path().to_path_buf(),
                                    config,
                                }).await;
                                active = Some(capture);
                            }
                            Err(error) => {
                                let _ = events.send(BackendEvent::CaptureFailed {
                                    message: error.to_string(),
                                }).await;
                            }
                        }
                    }
                    Some(CaptureCommand::Stop) => {
                        if let Some(mut capture) = active.take() {
                            let _ = events.send(finished_event(capture.stop().await)).await;
                        }
                    }
                    Some(CaptureCommand::Quit) | None => {
                        // Never leave `dumpcap` running past the UI that owns it.
                        if let Some(mut capture) = active.take() {
                            let _ = capture.stop().await;
                        }
                        return;
                    }
                }
            }
            _ = ticker.tick(), if active.is_some() => {
                let Some(capture) = active.as_mut() else { continue };
                // `dumpcap` stops itself once the duration cap elapses.
                if let Some(result) = capture.poll_exit() {
                    active = None;
                    let _ = events.send(finished_event(result)).await;
                } else {
                    let _ = events.send(BackendEvent::CaptureProgress {
                        bytes: capture.bytes(),
                    }).await;
                }
            }
        }
    }
}

fn finished_event(result: gpwn_core::Result<CaptureSummary>) -> BackendEvent {
    match result {
        Ok(summary) => BackendEvent::CaptureStopped(summary),
        Err(error) => BackendEvent::CaptureFailed {
            message: error.to_string(),
        },
    }
}

pub(super) async fn backend_worker(
    mut high_rx: mpsc::Receiver<BackendCommand>,
    mut sample_rx: mpsc::Receiver<SampleCommand>,
    event_tx: mpsc::Sender<BackendEvent>,
) {
    let mut backend: Option<Box<dyn OnuBackend>> = None;
    loop {
        tokio::select! {
            biased;
            command = high_rx.recv() => {
                let Some(command) = command else { break };
                match command {
                    BackendCommand::Connect(settings) => {
                        while sample_rx.try_recv().is_ok() {}
                        if let Some(current) = backend.as_mut() {
                            let _ = current.disconnect().await;
                        }
                        let _ = event_tx.send(BackendEvent::Connecting).await;
                        let mut candidate: Box<dyn OnuBackend> = match settings {
                            BackendSettings::Live { config, .. } => Box::new(LiveBackend::new(config)),
                            BackendSettings::Mock { scenario, .. } => Box::new(MockBackend::new(scenario)),
                        };
                        match candidate.connect().await {
                            Ok(info) => {
                                backend = Some(candidate);
                                let _ = event_tx.send(BackendEvent::Connected(info)).await;
                                refresh_backend(&mut backend, &event_tx).await;
                            }
                            Err(error) => {
                                backend = None;
                                let _ = event_tx.send(BackendEvent::Error {
                                    operation: "connect",
                                    message: error.to_string(),
                                    disconnected: true,
                                }).await;
                            }
                        }
                    }
                    BackendCommand::Refresh => refresh_backend(&mut backend, &event_tx).await,
                    BackendCommand::Add(request) => {
                        run_mutation(&mut backend, &event_tx, "add flows", |backend| {
                            Box::pin(backend.add_flows(request))
                        }).await;
                    }
                    BackendCommand::Delete(request) => {
                        run_mutation(&mut backend, &event_tx, "delete flows", |backend| {
                            Box::pin(backend.delete_flows(request))
                        }).await;
                    }
                    BackendCommand::Setup => {
                        run_mutation(&mut backend, &event_tx, "listen-all setup", |backend| {
                            Box::pin(backend.apply_listen_all_setup())
                        }).await;
                    }
                    BackendCommand::StartScan { config, cancel } => {
                        while sample_rx.try_recv().is_ok() {}
                        let Some(current) = backend.as_deref_mut() else {
                            let _ = event_tx.send(BackendEvent::Error {
                                operation: "autoscan",
                                message: "not connected".into(),
                                disconnected: true,
                            }).await;
                            continue;
                        };
                        let progress_tx = event_tx.clone();
                        let outcome = run_autoscan(current, config, cancel, move |progress| {
                            let _ = progress_tx.try_send(BackendEvent::ScanProgress(progress));
                        }).await;
                        let restored = outcome.result.restore_error.is_none();
                        let _ = event_tx.send(BackendEvent::ScanFinished(outcome)).await;
                        if restored {
                            refresh_backend(&mut backend, &event_tx).await;
                        }
                    }
                    BackendCommand::RetryRestore(original) => {
                        let result = match backend.as_deref_mut() {
                            Some(current) => retry_restore(current, original).await.map_err(|error| error.to_string()),
                            None => Err("not connected".into()),
                        };
                        let succeeded = result.is_ok();
                        let _ = event_tx.send(BackendEvent::RestoreRetried { result }).await;
                        if succeeded {
                            refresh_backend(&mut backend, &event_tx).await;
                        }
                    }
                    BackendCommand::ApplyActive { gem_ports, aes } => {
                        let result = match backend.as_deref_mut() {
                            Some(current) => apply_active_ports(current, gem_ports, aes).await,
                            None => Err(gpwn_core::Error::NotConnected),
                        };
                        match result {
                            Ok(result) => {
                                let _ = event_tx.send(BackendEvent::ActiveApplied(result)).await;
                                refresh_backend(&mut backend, &event_tx).await;
                            }
                            Err(error) => {
                                let _ = event_tx.send(BackendEvent::Error {
                                    operation: "apply autoscan results",
                                    message: error.to_string(),
                                    disconnected: matches!(error, gpwn_core::Error::NotConnected | gpwn_core::Error::Connection(_)),
                                }).await;
                            }
                        }
                    }
                    BackendCommand::MibCatalog => {
                        let result = match backend.as_deref_mut() {
                            Some(current) => current.list_omci_mib_tables().await,
                            None => Err(gpwn_core::Error::NotConnected),
                        };
                        match result {
                            Ok(tables) => {
                                let _ = event_tx.send(BackendEvent::MibCatalog(tables)).await;
                            }
                            Err(error) => {
                                let _ = event_tx.send(BackendEvent::Error {
                                    operation: "load MIB catalog",
                                    message: error.to_string(),
                                    disconnected: matches!(error, gpwn_core::Error::NotConnected | gpwn_core::Error::Connection(_)),
                                }).await;
                            }
                        }
                    }
                    BackendCommand::MibFetch(query) => {
                        let result = match backend.as_deref_mut() {
                            Some(current) => current.fetch_omci_mib(query).await,
                            None => Err(gpwn_core::Error::NotConnected),
                        };
                        match result {
                            Ok(snapshot) => {
                                let _ = event_tx.send(BackendEvent::MibSnapshot(snapshot)).await;
                            }
                            Err(error) => {
                                let _ = event_tx.send(BackendEvent::Error {
                                    operation: "load MIB table",
                                    message: error.to_string(),
                                    disconnected: matches!(error, gpwn_core::Error::NotConnected | gpwn_core::Error::Connection(_)),
                                }).await;
                            }
                        }
                    }
                    BackendCommand::Quit => {
                        if let Some(current) = backend.as_mut() {
                            let _ = current.disconnect().await;
                        }
                        break;
                    }
                }
            }
            command = sample_rx.recv(), if backend.is_some() => {
                if let Some(SampleCommand::Read(flow_id)) = command {
                    let result = match backend.as_mut() {
                        Some(current) => current.read_flow_counters(flow_id).await,
                        None => continue,
                    };
                    match result {
                        Ok(counters) => {
                            let _ = event_tx.send(BackendEvent::Sample {
                                counters,
                                at: Instant::now(),
                            }).await;
                        }
                        Err(error) => {
                            let disconnected = matches!(error, gpwn_core::Error::NotConnected | gpwn_core::Error::Connection(_));
                            let _ = event_tx.send(BackendEvent::Error {
                                operation: "sample traffic",
                                message: error.to_string(),
                                disconnected,
                            }).await;
                        }
                    }
                }
            }
        }
    }
}

async fn refresh_backend(
    backend: &mut Option<Box<dyn OnuBackend>>,
    event_tx: &mpsc::Sender<BackendEvent>,
) {
    let Some(current) = backend.as_mut() else {
        let _ = event_tx
            .send(BackendEvent::Error {
                operation: "refresh",
                message: "not connected".into(),
                disconnected: true,
            })
            .await;
        return;
    };
    match current.fetch_snapshot().await {
        Ok(snapshot) => {
            let _ = event_tx.send(BackendEvent::Snapshot(snapshot)).await;
        }
        Err(error) => {
            let disconnected = matches!(
                error,
                gpwn_core::Error::NotConnected | gpwn_core::Error::Connection(_)
            );
            let _ = event_tx
                .send(BackendEvent::Error {
                    operation: "refresh",
                    message: error.to_string(),
                    disconnected,
                })
                .await;
        }
    }
}

type MutationFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = gpwn_core::Result<MutationReport>> + Send + 'a>,
>;

async fn run_mutation<F>(
    backend: &mut Option<Box<dyn OnuBackend>>,
    event_tx: &mpsc::Sender<BackendEvent>,
    operation: &'static str,
    action: F,
) where
    F: for<'a> FnOnce(&'a mut dyn OnuBackend) -> MutationFuture<'a>,
{
    let Some(current) = backend.as_deref_mut() else {
        let _ = event_tx
            .send(BackendEvent::Error {
                operation,
                message: "not connected".into(),
                disconnected: true,
            })
            .await;
        return;
    };
    match action(current).await {
        Ok(report) => {
            let _ = event_tx
                .send(BackendEvent::Report { operation, report })
                .await;
            refresh_backend(backend, event_tx).await;
        }
        Err(error) => {
            let disconnected = matches!(
                error,
                gpwn_core::Error::NotConnected | gpwn_core::Error::Connection(_)
            );
            let _ = event_tx
                .send(BackendEvent::Error {
                    operation,
                    message: error.to_string(),
                    disconnected,
                })
                .await;
            refresh_backend(backend, event_tx).await;
        }
    }
}
