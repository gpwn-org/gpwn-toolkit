use super::*;
use std::path::Path;

fn analyze(values: &[(&str, &str)]) -> CaptureModel {
    let mut all = vec![
        ("frame.number", "1"),
        ("frame.time_epoch", "100.0"),
        ("frame.len", "128"),
        ("frame.protocols", "eth:ip:udp"),
        ("eth.src", "00:11:22:33:44:55"),
        ("eth.dst", "66:77:88:99:aa:bb"),
    ];
    all.extend_from_slice(values);
    let mut analyzer = Analyzer::default();
    let mut model = CaptureModel::new(Path::new("fixture.pcap"), false);
    analyzer.consume(Packet::fixture(&all), &mut model);
    analyzer.publish(&mut model);
    model
}

fn has(values: &[(&str, &str)], kind: &str) {
    assert!(
        analyze(values)
            .events
            .iter()
            .any(|event| event.kind == kind),
        "missing {kind}"
    );
}

#[test]
fn downstream_gtp_keeps_outer_gpon_nodes_and_attaches_mobile_ue() {
    let model = analyze(&[
        ("frame.protocols", "eth:ip:gtp:eth:ip:dns"),
        ("eth.src", "00:00:00:00:00:01|00:00:00:00:00:03"),
        ("eth.dst", "00:00:00:00:00:02|00:00:00:00:00:04"),
        ("ip.src", "1.1.1.1|10.0.0.1"),
        ("ip.dst", "2.2.2.2|10.0.0.2"),
        ("gtp.teid", "0x1234"),
        ("dns.qry.name", "example.com"),
        ("dns.flags.response", "1"),
    ]);
    assert!(
        model
            .nodes
            .iter()
            .any(|node| node.mac == "00:00:00:00:00:01" && node.ips.contains("1.1.1.1"))
    );
    let receiver = model
        .nodes
        .iter()
        .find(|node| node.mac == "00:00:00:00:00:02")
        .unwrap();
    assert!(receiver.gtp_receiver);
    assert_eq!(
        receiver.ips.iter().cloned().collect::<Vec<_>>(),
        ["2.2.2.2"]
    );
    assert_eq!(
        receiver.mobile_ues["10.0.0.2"]
            .teids
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        ["0x1234"]
    );
    assert!(
        !model
            .nodes
            .iter()
            .any(|node| node.mac == "00:00:00:00:00:04" || node.mac == "ip:10.0.0.2")
    );
    let event = model
        .events
        .iter()
        .find(|event| event.kind == "dns_response")
        .unwrap();
    assert_eq!(event.node, "00:00:00:00:00:02");
    assert_eq!(event.details["source_ips"], "1.1.1.1, 10.0.0.1");
}

#[test]
fn direct_gtp_attributes_inner_client_to_receiving_mac() {
    let model = analyze(&[
        ("frame.protocols", "eth:ip:udp:gtp:ip:dns"),
        ("ip.src", "172.16.0.1|8.8.8.8"),
        ("ip.dst", "172.16.0.2|10.23.4.5"),
        ("gtp.teid", "0x9876"),
        ("dns.qry.name", "example.com"),
        ("dns.flags.response", "1"),
    ]);
    let event = model
        .events
        .iter()
        .find(|event| event.kind == "dns_response")
        .unwrap();
    assert_eq!(event.node, "66:77:88:99:aa:bb");
    assert_eq!(event.peer.as_deref(), Some("00:11:22:33:44:55"));
    let receiver = model
        .nodes
        .iter()
        .find(|node| node.mac == "66:77:88:99:aa:bb")
        .unwrap();
    assert!(receiver.gtp_receiver);
    assert!(receiver.ips.contains("172.16.0.2"));
    assert_eq!(receiver.mobile_ues["10.23.4.5"].packet_count, 1);
    assert!(!model.nodes.iter().any(|node| node.mac == "ip:10.23.4.5"));
}

#[test]
fn nested_gtp_still_uses_outer_gpon_mac() {
    let model = analyze(&[
        ("frame.protocols", "eth:ip:udp:gtp:gre:eth:pppoe:ppp:ip"),
        ("eth.src", "00:00:00:00:00:01|00:00:00:00:00:03"),
        ("eth.dst", "00:00:00:00:00:02|00:00:00:00:00:04"),
        ("ip.src", "172.16.0.1|10.0.0.1"),
        ("ip.dst", "172.16.0.2|10.0.0.2"),
    ]);
    assert!(
        model
            .nodes
            .iter()
            .any(|node| node.mac == "00:00:00:00:00:01")
    );
    let receiver = model
        .nodes
        .iter()
        .find(|node| node.mac == "00:00:00:00:00:02")
        .unwrap();
    assert!(receiver.gtp_receiver);
    assert!(receiver.mobile_ues.contains_key("10.0.0.2"));
    assert!(
        !model
            .nodes
            .iter()
            .any(|node| node.mac == "00:00:00:00:00:04" || node.mac == "ip:10.0.0.1")
    );
}

#[test]
fn detector_matrix() {
    let cases: &[(&str, &[(&str, &str)])] = &[
        (
            "dns_response",
            &[
                ("frame.protocols", "eth:ip:udp:dns"),
                ("dns.flags.response", "1"),
                ("dns.qry.name", "example.com"),
                ("dns.a", "1.2.3.4"),
            ],
        ),
        (
            "tls_sni",
            &[
                ("frame.protocols", "eth:ip:tcp:tls"),
                ("tls.handshake.type", "1"),
                ("tls.handshake.extensions_server_name", "example.com"),
            ],
        ),
        (
            "tls_certificate",
            &[
                ("frame.protocols", "eth:ip:tcp:tls"),
                ("tls.handshake.type", "11"),
                ("x509ce.dNSName", "example.com"),
            ],
        ),
        (
            "http_response",
            &[
                ("frame.protocols", "eth:ip:tcp:http"),
                ("http.response.code", "200"),
                ("http.content_type", "application/json"),
            ],
        ),
        (
            "mqtt_message",
            &[
                ("frame.protocols", "eth:ip:tcp:mqtt"),
                ("mqtt.topic", "jobs/1"),
                ("mqtt.msg", "7b226f6b223a747275657d"),
            ],
        ),
        (
            "sip_call_started",
            &[
                ("frame.protocols", "eth:ip:udp:sip"),
                ("sip.Method", "INVITE"),
                ("sip.from.user", "1001"),
                ("sip.to.user", "1002"),
            ],
        ),
        (
            "s1ap_procedure",
            &[
                ("frame.protocols", "eth:ip:sctp:s1ap"),
                ("s1ap.procedureCode", "10"),
            ],
        ),
        (
            "x2ap_procedure",
            &[
                ("frame.protocols", "eth:ip:sctp:x2ap"),
                ("x2ap.procedureCode", "5"),
            ],
        ),
        (
            "ngap_procedure",
            &[
                ("frame.protocols", "eth:ip:sctp:ngap"),
                ("ngap.procedureCode", "15"),
            ],
        ),
        (
            "xnap_procedure",
            &[
                ("frame.protocols", "eth:ip:sctp:xnap"),
                ("xnap.procedureCode", "20"),
            ],
        ),
        (
            "nas_control",
            &[
                ("frame.protocols", "eth:ip:sctp:nas-5gs"),
                ("nas-5gs.mm.message_type", "0x41"),
            ],
        ),
        (
            "rtp_stream",
            &[
                ("frame.protocols", "eth:ip:udp:rtp"),
                ("rtp.ssrc", "0x1234"),
            ],
        ),
        (
            "rtcp_report",
            &[
                ("frame.protocols", "eth:ip:udp:rtcp"),
                ("rtcp.senderssrc", "0x1234"),
                ("rtcp.ssrc.jitter", "12"),
            ],
        ),
        (
            "snmp_activity",
            &[
                ("frame.protocols", "eth:ip:udp:snmp"),
                ("snmp.community", "public"),
                ("snmp.name", "1.3.6.1"),
            ],
        ),
        (
            "stun_activity",
            &[
                ("frame.protocols", "eth:ip:udp:stun"),
                ("stun.type", "0x0001"),
                ("stun.att.software", "test"),
            ],
        ),
        (
            "ntp_activity",
            &[
                ("frame.protocols", "eth:ip:udp:ntp"),
                ("ntp.stratum", "1"),
                ("ntp.refid", "474f4f47"),
            ],
        ),
        (
            "ftps_negotiation",
            &[
                ("frame.protocols", "eth:ip:tcp:ftp"),
                ("ftp.request.command", "AUTH"),
                ("ftp.request.arg", "TLS"),
            ],
        ),
        (
            "dhcpv6_activity",
            &[
                ("frame.protocols", "eth:ipv6:udp:dhcpv6"),
                ("dhcpv6.msgtype", "1"),
            ],
        ),
        (
            "dhcp_identity",
            &[
                ("frame.protocols", "eth:ip:udp:dhcp"),
                ("dhcp.option.hostname", "subscriber-cpe"),
            ],
        ),
        (
            "address_claimed",
            &[
                ("frame.protocols", "eth:arp"),
                ("arp.src.proto_ipv4", "10.0.0.2"),
            ],
        ),
        (
            "mdns_activity",
            &[
                ("frame.protocols", "eth:ip:udp:mdns"),
                ("dns.qry.name", "printer.local"),
            ],
        ),
        ("llmnr_activity", &[("frame.protocols", "eth:ip:udp:llmnr")]),
        ("ssdp_activity", &[("frame.protocols", "eth:ip:udp:ssdp")]),
        (
            "encrypted_protocol",
            &[("frame.protocols", "eth:ip:udp:quic")],
        ),
        (
            "tunnel_observed",
            &[
                ("frame.protocols", "eth:ip:gtp:eth:ip"),
                ("gtp.teid", "0x123"),
            ],
        ),
    ];
    for (kind, values) in cases {
        has(values, kind);
    }
}

#[test]
fn mqtt_hex_is_decoded_and_ntp_refid_is_readable() {
    let model = analyze(&[
        ("frame.protocols", "eth:ip:tcp:mqtt:ntp"),
        ("mqtt.topic", "a"),
        ("mqtt.msg", "7b2261223a317d"),
        ("ntp.stratum", "1"),
        ("ntp.refid", "474f4f47"),
    ]);
    assert_eq!(
        model
            .events
            .iter()
            .find(|e| e.kind == "mqtt_message")
            .unwrap()
            .details["messages"],
        "{\"a\":1}"
    );
    assert_eq!(
        model
            .events
            .iter()
            .find(|e| e.kind == "ntp_activity")
            .unwrap()
            .details["reference_id"],
        "GOOG (474f4f47)"
    );
}

#[test]
fn sip_and_cellular_identity_metadata_survives() {
    let sip = analyze(&[
        ("frame.protocols", "eth:ip:udp:sip"),
        ("sip.Method", "REGISTER"),
        (
            "sip.From",
            "<sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>",
        ),
        ("sip.from.user", "001010000000001"),
        ("sip.from.host", "ims.mnc001.mcc001.3gppnetwork.org"),
        ("sip.Contact", "<sip:a@b>;pn-prid=token-123"),
    ]);
    let event = sip
        .events
        .iter()
        .find(|e| e.kind == "sip_registered")
        .unwrap();
    assert_eq!(event.details["from"], "001010000000001");
    assert_eq!(event.details["push_token"], "token-123");
    let cell = analyze(&[
        ("frame.protocols", "eth:ip:sctp:s1ap:nas-eps"),
        ("s1ap.procedureCode", "10"),
        ("s1ap.m_TMSI", "0x12345678"),
        ("s1ap.MME_UE_S1AP_ID", "77"),
        ("s1ap.TAC", "0x002a"),
        ("nas-eps.emm.mme_code", "4"),
        ("e212.mcc", "001"),
        ("e212.mnc", "01"),
    ]);
    let event = cell
        .events
        .iter()
        .find(|e| e.kind == "s1ap_procedure")
        .unwrap();
    assert_eq!(event.details["s1ap_m_tmsi"], "0x12345678");
    assert_eq!(event.details["mcc"], "001");
}

#[test]
fn rejects_invalid_and_group_macs() {
    assert!(normalize_mac("not-a-mac").is_none());
    assert!(is_group_mac("01:00:5e:00:00:fb"));
    assert!(!is_group_mac("00:11:22:33:44:55"));
}
