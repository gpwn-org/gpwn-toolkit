use super::*;
use ratatui::Terminal;
use ratatui::backend::TestBackend;

fn test_app() -> App {
    let (high_tx, _high_rx) = mpsc::channel(8);
    let (sample_tx, _sample_rx) = mpsc::channel(8);
    let (capture_tx, _capture_rx) = mpsc::channel(8);
    App::new(
        ConnectionForm::from_args(Args {
            host: "192.168.69.1".into(),
            port: 22,
            user: "admin".into(),
            timeout: 10,
            poll_interval: 10,
            mock: true,
            mock_scenario: "healthy".into(),
        }),
        high_tx,
        sample_tx,
        capture_tx,
    )
}

fn test_snapshot() -> OnuSnapshot {
    OnuSnapshot {
        line: gpwn_core::LineStatus {
            onu_state: gpwn_core::OnuState::O5,
            state_description: "Operation State(O5)".into(),
            los: AlarmCondition::Clear,
            lof: AlarmCondition::Clear,
            lom: AlarmCondition::Clear,
            rx_power_dbm: Some(-18.0),
            tx_power_dbm: Some(2.0),
        },
        downstream: vec![
            gpwn_core::DownstreamFlow {
                flow_id: 1,
                gem_port: 100,
                flow_type: FlowType::Ethernet,
                multicast: false,
                aes: true,
            },
            gpwn_core::DownstreamFlow {
                flow_id: 2,
                gem_port: 200,
                flow_type: FlowType::Ethernet,
                multicast: false,
                aes: true,
            },
        ],
        upstream: vec![gpwn_core::UpstreamFlow {
            flow_id: 3,
            gem_port: 300,
            flow_type: FlowType::Ethernet,
            tcont: Some(0),
            channel: Some(16),
            omci: false,
        }],
        fetched_at: SystemTime::now(),
    }
}

fn scan_result(gems: &[u16]) -> AutoscanResult {
    AutoscanResult {
        schema_version: 1,
        config: AutoscanConfig {
            gem_start: 0,
            gem_end: 4095,
            batch_size: 128,
            observation_secs: 5.0,
            aes: true,
        },
        terminal_phase: AutoscanPhase::Completed,
        batches: vec![gpwn_scan::BatchResult {
            batch_index: 0,
            gem_start: 0,
            gem_end: 4095,
            activities: gems
                .iter()
                .map(|gem| gpwn_scan::GemPortActivity {
                    gem_port: *gem,
                    batch_index: 0,
                    ds_gem_packets: 10,
                    ds_gem_bytes: 8420,
                    ds_rx_eth_packets: 9,
                    ds_fwd_eth_packets: 8,
                    elapsed_secs: 5.0,
                    packets_per_sec: 2.0,
                    bytes_per_sec: 1684.0,
                })
                .collect(),
        }],
        wall_time_secs: 10.0,
        error: None,
        restore_error: None,
    }
}

fn mib_snapshot() -> MibTableSnapshot {
    MibTableSnapshot {
        query: MibQuery {
            selector: MibSelector::TableName("Ontg".into()),
            entity_id: None,
        },
        table_name: "Ontg".into(),
        entities: vec![gpwn_core::MibEntity {
            entity_id: 0,
            attributes: vec![
                gpwn_core::MibAttribute {
                    name: "VendorId".into(),
                    value: "RTKG".into(),
                },
                gpwn_core::MibAttribute {
                    name: "Version".into(),
                    value: "1".into(),
                },
            ],
            raw_lines: vec!["EntityID: 0x00".into(), "VendorId: RTKG".into()],
        }],
        raw_output: "XXXXXXXX\nOntg\nXXXXXXXX\nEntityID: 0x00\nVendorId: RTKG\n".into(),
        fetched_at: SystemTime::now(),
    }
}

#[test]
fn add_modal_builds_both_direction_request() {
    let modal = AddModal {
        scope: DirectionScope::Both,
        gem_ports: "10-12".into(),
        flow_id: "auto".into(),
        flow_type: FlowType::Ethernet,
        multicast: false,
        aes: true,
        focused: 0,
        error: None,
    };
    let request = modal.request().unwrap();
    assert_eq!(request.gem_ports, vec![10, 11, 12]);
    assert_eq!(request.scope, DirectionScope::Both);
}

#[test]
fn formats_rates() {
    assert_eq!(human_rate(999.0), "999");
    assert_eq!(human_rate(1_500.0), "1.5K");
    assert_eq!(human_rate(2_000_000.0), "2.0M");
}

#[test]
fn connection_screen_renders_narrow_terminal() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let form = ConnectionForm::from_args(Args {
        host: "192.168.69.1".into(),
        port: 22,
        user: "admin".into(),
        timeout: 10,
        poll_interval: 10,
        mock: true,
        mock_scenario: "healthy".into(),
    });
    terminal
        .draw(|frame| render_connection(frame, &form))
        .unwrap();
    let buffer = terminal.backend().buffer();
    let text = buffer
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(text.contains("Connect to ONU"));
    assert!(!text.contains("mock://"));
}

#[test]
fn activity_filter_is_direction_specific() {
    let sample = SampleView {
        counters: FlowCounters {
            flow_id: 1,
            ds_gem_packets: 10,
            ..Default::default()
        },
        interval: Some(Duration::from_secs(10)),
        sampled_at: Instant::now(),
    };
    assert!(activity_matches(
        ActivityFilter::Active,
        Pane::Downstream,
        Some(&sample)
    ));
    assert!(activity_matches(
        ActivityFilter::Idle,
        Pane::Upstream,
        Some(&sample)
    ));
}

#[test]
fn gem_search_switches_pane_and_mouse_wheel_moves_selection() {
    let mut app = test_app();
    app.snapshot = Some(test_snapshot());
    app.pane = Pane::Upstream;
    app.activity_filter = ActivityFilter::Idle;
    app.jump_to_gem_port(200);
    assert_eq!(app.pane, Pane::Downstream);
    assert_eq!(app.ds_selected, Some(2));
    assert_eq!(app.activity_filter, ActivityFilter::All);

    app.ds_selected = Some(1);
    app.show_connection = false;
    app.handle_mouse_scroll(10, 80, 1);
    assert_eq!(app.ds_selected, Some(2));
}

#[test]
fn filtering_and_row_changes_preserve_selected_flow_identity() {
    let mut app = test_app();
    app.snapshot = Some(test_snapshot());
    app.snapshot
        .as_mut()
        .unwrap()
        .downstream
        .push(gpwn_core::DownstreamFlow {
            flow_id: 3,
            gem_port: 300,
            flow_type: FlowType::Ethernet,
            multicast: false,
            aes: false,
        });
    app.ds_selected = Some(2);
    app.samples.insert(
        1,
        SampleView {
            counters: FlowCounters {
                flow_id: 1,
                ds_gem_packets: 10,
                ..Default::default()
            },
            interval: Some(Duration::from_secs(10)),
            sampled_at: Instant::now(),
        },
    );
    app.samples.insert(
        2,
        SampleView {
            counters: FlowCounters {
                flow_id: 2,
                ..Default::default()
            },
            interval: Some(Duration::from_secs(10)),
            sampled_at: Instant::now(),
        },
    );
    app.samples.insert(
        3,
        SampleView {
            counters: FlowCounters {
                flow_id: 3,
                ds_gem_packets: 20,
                ..Default::default()
            },
            interval: Some(Duration::from_secs(10)),
            sampled_at: Instant::now(),
        },
    );

    app.activity_filter = ActivityFilter::Active;
    app.reconcile_selections(false);
    assert_eq!(app.ds_selected, Some(3));
    assert_eq!(app.selected_flow_id(), Some(3));

    app.activity_filter = ActivityFilter::All;
    assert_eq!(app.selected_flow_id(), Some(3));

    app.snapshot.as_mut().unwrap().downstream.insert(
        0,
        gpwn_core::DownstreamFlow {
            flow_id: 0,
            gem_port: 50,
            flow_type: FlowType::Ethernet,
            multicast: false,
            aes: false,
        },
    );
    app.reconcile_selections(false);
    assert_eq!(app.ds_selected, Some(3));
}

#[test]
fn autoscan_page_renders_results_and_preserves_gem_selection() {
    let mut app = test_app();
    app.show_connection = false;
    app.page = Page::Autoscan;
    app.snapshot = Some(test_snapshot());
    app.autoscan.result = Some(scan_result(&[165, 256]));
    app.autoscan.selected_gem = Some(256);
    app.autoscan.show_all = true;
    app.move_autoscan_selection(-1);
    assert_eq!(app.autoscan.selected_gem, Some(165));

    let text = rendered(&mut app);
    assert!(text.contains("Autoscan results"));
    assert!(text.contains("[a] Add selected"));
}

fn test_capture_modal() -> CaptureModal {
    CaptureModal {
        interfaces: vec![
            InterfaceInfo {
                name: "en5".into(),
                friendly: Some("Ethernet".into()),
                addresses: vec!["192.168.69.2".into()],
                loopback: false,
            },
            InterfaceInfo {
                name: "lo0".into(),
                friendly: Some("Loopback".into()),
                addresses: vec!["127.0.0.1".into()],
                loopback: true,
            },
        ],
        selected: "en5".into(),
        show_all: false,
        directory: "./captures".into(),
        duration: "60".into(),
        filter: "not (host 192.168.69.1 and port 22)".into(),
        focused: 0,
        rate: Some(TrafficRate {
            packets_per_second: 1000.0,
            average_frame: 1468.0,
        }),
        free_space: Some(500_000_000_000),
        configured_flows: 128,
        error: None,
    }
}

fn test_capture_config(duration: Option<Duration>) -> CaptureConfig {
    CaptureConfig {
        interface: "en5".into(),
        output_dir: PathBuf::from("./captures"),
        duration,
        filter: None,
    }
}

fn rendered(app: &mut App) -> String {
    rendered_at(app, 140, 32)
}

fn rendered_at(app: &mut App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| app.render(frame)).unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}

/// `interval` is `None` for a flow read only once, which has nothing to
/// measure a rate against.
fn sample(flow_id: u8, interval: Option<Duration>, mut counters: FlowCounters) -> SampleView {
    counters.flow_id = flow_id;
    SampleView {
        counters,
        interval,
        sampled_at: Instant::now(),
    }
}

#[test]
fn capture_wizard_renders_fields_estimate_and_free_space() {
    let mut app = test_app();
    app.show_connection = false;
    app.snapshot = Some(test_snapshot());
    app.capture.modal = Some(test_capture_modal());

    let text = rendered(&mut app);
    assert!(text.contains("Start capture"));
    assert!(text.contains("en5 — Ethernet"));
    assert!(text.contains("./captures"));
    assert!(text.contains("not (host 192.168.69.1 and port 22)"));
    assert!(text.contains("Downstream flows configured: 128"));
    // 1000 pkt/s * (1468 + 32) * 60s = 90 MB.
    assert!(text.contains("Estimated size: 90.0M"));
    assert!(text.contains("Free space:"));
}

#[test]
fn wizard_warns_when_nothing_is_being_forwarded() {
    let mut app = test_app();
    app.show_connection = false;
    let mut modal = test_capture_modal();
    modal.rate = Some(TrafficRate {
        packets_per_second: 0.0,
        average_frame: 0.0,
    });
    app.capture.modal = Some(modal);

    assert!(rendered(&mut app).contains("listen-all may not be applied"));
}

#[test]
fn wizard_hides_loopback_until_asked_and_keeps_the_selection() {
    let mut modal = test_capture_modal();
    assert_eq!(modal.visible().count(), 1);
    assert_eq!(modal.current_interface().unwrap().name, "en5");

    // Selection is held by name, so widening the list cannot move it.
    modal.show_all = true;
    assert_eq!(modal.visible().count(), 2);
    assert_eq!(modal.current_interface().unwrap().name, "en5");

    modal.cycle_interface(1);
    assert_eq!(modal.current_interface().unwrap().name, "lo0");

    // Narrowing the list again falls back rather than selecting nothing.
    modal.show_all = false;
    assert_eq!(modal.current_interface().unwrap().name, "en5");
}

#[test]
fn wizard_duration_zero_means_until_stopped() {
    let mut modal = test_capture_modal();
    let sixty = modal.parsed_duration().unwrap();
    assert_eq!(sixty, Some(Duration::from_secs(60)));
    assert!(modal.estimate(sixty).is_some());

    modal.duration = "0".into();
    let unbounded = modal.parsed_duration().unwrap();
    assert_eq!(unbounded, None);
    // Nothing to size an open-ended capture against.
    assert_eq!(modal.estimate(unbounded), None);
    assert_eq!(modal.capacity_error(unbounded), None);

    modal.duration = "abc".into();
    assert!(modal.parsed_duration().is_err());
    assert!(modal.config().is_err());
}

#[test]
fn wizard_refuses_a_capture_larger_than_the_filesystem() {
    let mut modal = test_capture_modal();
    modal.free_space = Some(1_000_000);
    let duration = modal.parsed_duration().unwrap();
    let message = modal.capacity_error(duration).expect("should not fit");
    assert!(message.contains("exceeds"));

    // Unknown free space cannot refuse anything.
    modal.free_space = None;
    assert_eq!(modal.capacity_error(duration), None);
}

#[test]
fn recording_indicator_reports_elapsed_size_and_interface() {
    let mut app = test_app();
    app.show_connection = false;
    app.snapshot = Some(test_snapshot());
    app.handle_backend_event(BackendEvent::CaptureStarted {
        path: PathBuf::from("./captures/gpwn-capture-1.pcapng"),
        config: test_capture_config(Some(Duration::from_secs(60))),
    });
    app.handle_backend_event(BackendEvent::CaptureProgress { bytes: 2_500_000 });

    let text = rendered(&mut app);
    assert!(text.contains("● REC"));
    assert!(text.contains("/ 01:00"));
    assert!(text.contains("2.5M"));
    assert!(text.contains("en5"));
}

#[test]
fn capture_records_the_flow_table_and_restores_the_sampler() {
    let mut app = test_app();
    app.show_connection = false;
    app.snapshot = Some(test_snapshot());
    assert!(!app.sampling_paused);

    app.handle_backend_event(BackendEvent::CaptureStarted {
        path: PathBuf::from("./captures/gpwn-capture-1.pcapng"),
        config: test_capture_config(None),
    });
    // The sampler shares the captured link, so it pauses for the duration.
    assert!(app.sampling_paused);
    let active = app.capture.active.as_ref().unwrap();
    assert_eq!(active.downstream_at_start.len(), 2);
    assert!(active.line_at_start.is_some());

    app.handle_backend_event(BackendEvent::CaptureFailed {
        message: "dumpcap: no such interface".into(),
    });
    assert!(!app.sampling_paused);
    assert!(app.capture.active.is_none());
    assert!(
        app.logs
            .iter()
            .any(|line| line.contains("no such interface"))
    );
}

#[test]
fn quitting_stops_a_running_capture_before_exiting() {
    let mut app = test_app();
    app.show_connection = false;
    app.handle_backend_event(BackendEvent::CaptureStarted {
        path: PathBuf::from("./captures/gpwn-capture-1.pcapng"),
        config: test_capture_config(None),
    });

    app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
    assert!(!app.should_quit, "quit must wait for the capture to stop");
    assert!(app.quit_after_capture);

    // Pressing again gives up waiting rather than trapping the user.
    app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
    assert!(app.should_quit);
}

#[test]
fn capture_stop_event_completes_a_pending_quit() {
    let mut app = test_app();
    app.show_connection = false;
    app.handle_backend_event(BackendEvent::CaptureStarted {
        path: PathBuf::from("./captures/gpwn-capture-1.pcapng"),
        config: test_capture_config(None),
    });
    app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));

    app.handle_backend_event(BackendEvent::CaptureStopped(CaptureSummary {
        path: PathBuf::from("./captures/gpwn-capture-1.pcapng"),
        bytes: 4096,
        duration: Duration::from_secs(3),
        stop_reason: StopReason::Manual,
    }));
    assert!(app.should_quit);
}

#[test]
fn estimate_rate_uses_forwarded_rather_than_gem_packets() {
    let mut app = test_app();
    app.snapshot = Some(test_snapshot());
    // Flow 1 receives far more on the GEM side than it forwards, which is
    // what an ONU still filtering downstream traffic looks like.
    app.samples.insert(
        1,
        sample(
            1,
            Some(Duration::from_secs(2)),
            FlowCounters {
                ds_gem_packets: 1000,
                ds_gem_bytes: 1_500_000,
                ds_fwd_eth_packets: 100,
                ..Default::default()
            },
        ),
    );
    let rate = app.downstream_rate().unwrap();
    // 100 forwarded packets over a 2s interval — flow 2 is configured but
    // unsampled, so it contributes nothing.
    assert_eq!(rate.packets_per_second, 50.0);
    assert_eq!(rate.average_frame, 1500.0);
}

#[test]
fn no_rate_without_a_completed_sampling_interval() {
    let mut app = test_app();
    app.snapshot = Some(test_snapshot());
    assert!(app.downstream_rate().is_none());

    // First read of a flow has nothing to measure against.
    app.samples.insert(
        1,
        sample(
            1,
            None,
            FlowCounters {
                ds_fwd_eth_packets: 10,
                ..Default::default()
            },
        ),
    );
    assert!(app.downstream_rate().is_none());
}

/// Feed the app real worker events until `done` is satisfied.
async fn pump_until(
    app: &mut App,
    events: &mut mpsc::Receiver<BackendEvent>,
    done: impl Fn(&App) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !done(app) {
        assert!(Instant::now() < deadline, "worker event never arrived");
        match tokio::time::timeout(Duration::from_millis(250), events.recv()).await {
            Ok(Some(event)) => app.handle_backend_event(event),
            Ok(None) => panic!("capture worker stopped"),
            Err(_) => {}
        }
    }
}

/// Drives the whole capture path in mock mode against the real worker and a
/// real `dumpcap`: key events in, pcapng and sidecar out. Needs packet
/// privileges, so it is excluded from the default run.
#[tokio::test]
#[ignore = "requires packet capture privileges"]
async fn mock_mode_capture_writes_a_pcap_and_a_sidecar() {
    let directory = std::env::temp_dir().join("gpwn-tui-capture-e2e");
    let _ = std::fs::remove_dir_all(&directory);

    let (high_tx, _high_rx) = mpsc::channel(8);
    let (sample_tx, _sample_rx) = mpsc::channel(8);
    let (capture_tx, capture_rx) = mpsc::channel(8);
    let (event_tx, mut events) = mpsc::channel(64);
    let worker = tokio::spawn(capture_worker(capture_rx, event_tx));

    let mut app = test_app();
    app.high_tx = high_tx;
    app.sample_tx = sample_tx;
    app.capture_tx = capture_tx;
    app.show_connection = false;
    app.snapshot = Some(test_snapshot());

    app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
    let modal = app.capture.modal.as_mut().expect("wizard should open");
    // Record on loopback rather than whatever real NIC sorts first.
    modal.show_all = true;
    let loopback = modal
        .visible()
        .find(|interface| interface.loopback)
        .expect("a loopback interface")
        .name
        .clone();
    modal.selected = loopback;
    modal.directory = directory.to_string_lossy().into_owned();
    modal.duration = "0".into();
    // Padded on purpose: the sidecar must record the filter as `dumpcap`
    // received it, not the raw text the wizard was holding.
    modal.filter = "  not port 22  ".into();

    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    pump_until(&mut app, &mut events, |app| app.capture.active.is_some()).await;
    assert!(app.sampling_paused, "sampler pauses while recording");
    assert!(app.capture.modal.is_none(), "wizard closes once recording");

    tokio::time::sleep(Duration::from_millis(600)).await;
    app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
    pump_until(&mut app, &mut events, |app| app.capture.active.is_none()).await;
    assert!(!app.sampling_paused, "sampler resumes afterwards");

    let captures: Vec<_> = std::fs::read_dir(&directory)
        .expect("output directory")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    let pcap = captures
        .iter()
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "pcapng")
        })
        .expect("a pcapng");
    let sidecar = captures
        .iter()
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .expect("a sidecar");
    assert_eq!(pcap.with_extension("json"), *sidecar);

    let written = std::fs::read(pcap).unwrap();
    assert_eq!(&written[..4], &[0x0a, 0x0d, 0x0d, 0x0a], "finalized pcapng");

    let recorded: serde_json::Value =
        serde_json::from_slice(&std::fs::read(sidecar).unwrap()).expect("valid sidecar JSON");
    assert_eq!(recorded["schema_version"], 1);
    assert_eq!(recorded["stop_reason"], "manual");
    assert_eq!(recorded["filter"], "not port 22");
    assert_eq!(
        recorded["pcap"],
        pcap.file_name().unwrap().to_string_lossy().as_ref()
    );
    // The flow table is the only record of what the ONU was forwarding.
    let flows = recorded["downstream_at_start"].as_array().unwrap();
    assert_eq!(flows.len(), 2);
    assert_eq!(flows[0]["gem_port"], 100);
    assert!(recorded["line"]["onu_state"].is_string());

    let _ = std::fs::remove_dir_all(&directory);
    drop(app);
    let _ = worker.await;
}

#[test]
fn control_r_is_ignored_while_another_modal_holds_focus() {
    let mut app = test_app();
    app.show_connection = false;
    app.snapshot = Some(test_snapshot());
    app.add_modal = Some(AddModal::default());

    app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
    assert!(app.capture.modal.is_none());
    assert!(app.add_modal.is_some());
}

#[test]
fn arrow_keys_navigate_live_autoscan_results() {
    let mut app = test_app();
    app.show_connection = false;
    app.page = Page::Autoscan;
    app.autoscan.running = true;
    app.autoscan.live_activities = scan_result(&[165, 256]).batches[0].activities.clone();
    app.autoscan.selected_gem = Some(165);

    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    assert_eq!(app.autoscan.selected_gem, Some(256));
    app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
    assert_eq!(app.autoscan.selected_gem, Some(165));
}

#[test]
fn monitor_titles_show_visible_and_total_flow_counts() {
    let mut app = test_app();
    app.show_connection = false;
    app.snapshot = Some(test_snapshot());

    let text = rendered(&mut app);
    assert!(text.contains("Downstream [all] — 2/2 flows"));
}

#[test]
fn insufficient_apply_capacity_requires_subset_selection() {
    let mut app = test_app();
    app.show_connection = false;
    app.page = Page::Autoscan;
    let mut snapshot = test_snapshot();
    snapshot.downstream = (0..127)
        .map(|flow_id| gpwn_core::DownstreamFlow {
            flow_id,
            gem_port: flow_id as u16,
            flow_type: FlowType::Ethernet,
            multicast: false,
            aes: false,
        })
        .collect();
    app.snapshot = Some(snapshot);
    app.autoscan.result = Some(scan_result(&[1000, 1001]));
    app.prepare_apply_active();
    assert!(app.autoscan.capacity_selecting);
    assert_eq!(app.autoscan.apply_selected.len(), 1);
}

#[test]
fn selected_active_gem_can_be_applied_individually() {
    let mut app = test_app();
    app.show_connection = false;
    app.page = Page::Autoscan;
    app.snapshot = Some(test_snapshot());
    app.autoscan.result = Some(scan_result(&[1000, 1001]));
    app.autoscan.selected_gem = Some(1001);

    app.prepare_apply_selected();
    assert!(matches!(
        app.confirm,
        Some(ConfirmAction::ApplyActive(ref gems)) if gems == &[1001]
    ));
}

#[test]
fn mib_lookup_accepts_class_and_entity_ids() {
    let mut app = test_app();
    app.mib.catalog = vec![MibTableDescriptor {
        internal_id: 1,
        name: "Ontg".into(),
    }];
    assert_eq!(
        app.parse_mib_lookup("256,0x0000").unwrap(),
        MibQuery {
            selector: MibSelector::ClassId(256),
            entity_id: Some(0),
        }
    );
    assert_eq!(
        app.parse_mib_lookup("ontg").unwrap().selector,
        MibSelector::ClassId(256)
    );
}

#[test]
fn mib_page_renders_and_filters_without_changing_visible_identity() {
    let mut app = test_app();
    app.show_connection = false;
    app.page = Page::Mib;
    app.mib.catalog_loaded = true;
    app.mib.catalog = vec![
        MibTableDescriptor {
            internal_id: 1,
            name: "Ontg".into(),
        },
        MibTableDescriptor {
            internal_id: 20,
            name: "GemPortCtp".into(),
        },
    ];
    app.mib.selected_table = Some(20);
    let snapshot = mib_snapshot();
    app.mib.active_query = Some(snapshot.query.clone());
    app.mib.snapshots.insert(snapshot.query.clone(), snapshot);
    app.mib.selected_entity = Some(0);

    app.mib.table_filter = "gem".into();
    let visible = app.mib_visible_table_ids();
    app.mib.selected_table = app
        .mib
        .selected_table
        .filter(|id| visible.contains(id))
        .or_else(|| visible.first().copied());
    assert_eq!(app.mib.selected_table, Some(20));

    let text = rendered(&mut app);
    assert!(text.contains("OMCI MIB"));
    assert!(text.contains("GemPortCtp"));
    assert!(text.contains("VendorId"));
    assert!(text.contains("RTKG"));
}

#[test]
fn mib_narrow_page_shows_only_focused_pane() {
    let mut app = test_app();
    app.show_connection = false;
    app.page = Page::Mib;
    app.mib.pane = MibPane::Attributes;
    let snapshot = mib_snapshot();
    app.mib.active_query = Some(snapshot.query.clone());
    app.mib.snapshots.insert(snapshot.query.clone(), snapshot);
    app.mib.selected_entity = Some(0);

    let text = rendered_at(&mut app, 80, 24);
    assert!(text.contains("Attributes"));
    assert!(text.contains("VendorId"));
}
