use crate::fields;
use crate::model::{CaptureModel, Edge, Event, MobileUeSession, Node};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

mod application;
mod cellular;
mod infrastructure;
mod tunnels;

const MAX_DETAIL: usize = 64 * 1024;

#[derive(Clone, Debug)]
/// A decoded row from tshark's tab-separated field output.
///
/// Columns follow [`crate::fields::FIELDS`]. Repeated field occurrences remain
/// ordered and are available through [`Packet::all`].
pub struct Packet {
    values: Vec<Vec<String>>,
}

impl Packet {
    /// Parses one tshark TSV row.
    ///
    /// Returns `None` when `frame.time_epoch` is absent or is not a number.
    /// Missing trailing columns are treated as empty fields.
    pub fn from_tsv(line: &str) -> Option<Self> {
        let mut columns = line.split('\t').map(split_values).collect::<Vec<_>>();
        columns.resize_with(fields::FIELDS.len(), Vec::new);
        columns[fields::index("frame.time_epoch")]
            .first()
            .and_then(|value| value.parse::<f64>().ok())?;
        Some(Self { values: columns })
    }

    #[cfg(test)]
    pub fn fixture(values: &[(&str, &str)]) -> Self {
        let mut columns = vec![Vec::new(); fields::FIELDS.len()];
        for (name, value) in values {
            columns[fields::index(name)] = split_values(value);
        }
        Self { values: columns }
    }

    /// Returns every occurrence of a field in capture order.
    ///
    /// # Panics
    ///
    /// Panics when `name` is not part of [`crate::fields::FIELDS`].
    pub fn all(&self, name: &str) -> &[String] {
        &self.values[fields::index(name)]
    }

    /// Returns the first occurrence of `name`, or an empty string when absent.
    pub fn first(&self, name: &str) -> &str {
        self.all(name)
            .first()
            .map(String::as_str)
            .unwrap_or_default()
    }

    /// Returns the last occurrence of `name`, or an empty string when absent.
    pub fn last(&self, name: &str) -> &str {
        self.all(name)
            .last()
            .map(String::as_str)
            .unwrap_or_default()
    }

    /// Reports whether `frame.protocols` contains `layer` (case-insensitively).
    pub fn has_layer(&self, layer: &str) -> bool {
        self.first("frame.protocols")
            .split(':')
            .any(|value| value.eq_ignore_ascii_case(layer))
    }

    fn frame(&self) -> u64 {
        self.first("frame.number").parse().unwrap_or_default()
    }

    fn timestamp(&self) -> f64 {
        self.first("frame.time_epoch").parse().unwrap_or_default()
    }

    fn length(&self) -> u64 {
        self.first("frame.len").parse().unwrap_or_default()
    }

    fn source(&self) -> Option<String> {
        if self.has_layer("gtp") {
            return self.outer_endpoint("eth.src", "ip.src", "ipv6.src");
        }
        self.endpoint("eth.src", "ip.src", "ipv6.src")
    }

    fn target(&self) -> Option<String> {
        let endpoint = if self.has_layer("gtp") {
            self.outer_endpoint("eth.dst", "ip.dst", "ipv6.dst")
        } else {
            self.endpoint("eth.dst", "ip.dst", "ipv6.dst")
        };
        endpoint.filter(|id| id.starts_with("ip:") || !is_group_mac(id))
    }

    fn outer_endpoint(&self, ethernet: &str, ipv4: &str, ipv6: &str) -> Option<String> {
        normalize_mac(self.first(ethernet)).or_else(|| {
            let value = value_or(self.first(ipv4), self.first(ipv6));
            (!value.is_empty()).then(|| format!("ip:{value}"))
        })
    }

    fn endpoint(&self, ethernet: &str, ipv4: &str, ipv6: &str) -> Option<String> {
        let macs = self.all(ethernet);
        normalize_mac(macs.last().map(String::as_str).unwrap_or_default()).or_else(|| {
            let value = value_or(self.last(ipv4), self.last(ipv6));
            (!value.is_empty()).then(|| format!("ip:{value}"))
        })
    }

    fn outer_ips(&self, ipv4: &str, ipv6: &str) -> (Vec<String>, Vec<String>) {
        let before_gtp = self
            .first("frame.protocols")
            .split(':')
            .take_while(|layer| !layer.eq_ignore_ascii_case("gtp"))
            .collect::<Vec<_>>();
        let outer_is_v6 = before_gtp
            .iter()
            .any(|layer| layer.eq_ignore_ascii_case("ipv6"));
        let outer_is_v4 = before_gtp
            .iter()
            .any(|layer| layer.eq_ignore_ascii_case("ip"));
        (
            outer_is_v4
                .then(|| self.first(ipv4).to_owned())
                .filter(|value| !value.is_empty())
                .into_iter()
                .collect(),
            outer_is_v6
                .then(|| self.first(ipv6).to_owned())
                .filter(|value| !value.is_empty())
                .into_iter()
                .collect(),
        )
    }

    fn inner_gtp_destination(&self) -> Option<String> {
        if !self.has_layer("gtp") {
            return None;
        }
        let after_gtp = self
            .first("frame.protocols")
            .split(':')
            .skip_while(|layer| !layer.eq_ignore_ascii_case("gtp"))
            .skip(1);
        for layer in after_gtp {
            if layer.eq_ignore_ascii_case("ip") {
                return self.all("ip.dst").last().cloned();
            }
            if layer.eq_ignore_ascii_case("ipv6") {
                return self.all("ipv6.dst").last().cloned();
            }
        }
        None
    }
}

fn split_values(input: &str) -> Vec<String> {
    if input.is_empty() {
        return Vec::new();
    }
    input.split('|').map(unescape_tshark).collect()
}

fn unescape_tshark(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        match chars.next() {
            Some('n') => output.push('\n'),
            Some('r') => output.push('\r'),
            Some('t') => output.push('\t'),
            Some('\\') => output.push('\\'),
            Some(other) => {
                output.push('\\');
                output.push(other);
            }
            None => output.push('\\'),
        }
    }
    output
}

#[derive(Default)]
/// Incrementally derives endpoints, flows, protocol events, and GTP sessions.
///
/// An analyzer retains aggregation state across packets. Use one instance per
/// capture and periodically call [`Analyzer::publish`] when readers need a
/// consistent snapshot.
pub struct Analyzer {
    origin: Option<f64>,
    pub(super) nodes: HashMap<String, Node>,
    edges: HashMap<(String, String), Edge>,
    events: Vec<Event>,
    seen: HashSet<String>,
}

impl Analyzer {
    /// Parses and consumes one tshark TSV row.
    ///
    /// Malformed rows are ignored, matching [`Packet::from_tsv`].
    pub fn consume_line(&mut self, line: &str, model: &mut CaptureModel) {
        if let Some(packet) = Packet::from_tsv(line) {
            self.consume(packet, model);
        }
    }

    /// Consumes a decoded packet and updates capture-level counters immediately.
    ///
    /// Derived nodes, edges, and events are copied to `model` by
    /// [`Analyzer::publish`].
    pub fn consume(&mut self, packet: Packet, model: &mut CaptureModel) {
        let absolute = packet.timestamp();
        let origin = *self.origin.get_or_insert(absolute);
        let time = (absolute - origin).max(0.0);
        let frame = packet.frame();
        let bytes = packet.length();
        let source = packet.source();
        let target = packet.target();
        let is_gtp = packet.has_layer("gtp");
        let protocol = application_protocol(&packet);

        model.packet_count += 1;
        model.first_timestamp.get_or_insert(absolute);
        model.last_timestamp = Some(absolute);
        model.duration = time;

        let source_new = source
            .as_deref()
            .is_some_and(|node| !self.nodes.contains_key(node));
        let target_new = target
            .as_deref()
            .is_some_and(|node| !self.nodes.contains_key(node));
        if let Some(node) = source.as_deref() {
            let (source_ipv4, source_ipv6) = if is_gtp {
                packet.outer_ips("ip.src", "ipv6.src")
            } else {
                (
                    packet.all("ip.src").to_vec(),
                    packet.all("ipv6.src").to_vec(),
                )
            };
            self.touch_node(
                node,
                time,
                bytes,
                &protocol,
                &source_ipv4,
                &source_ipv6,
                if is_gtp {
                    packet.first("eth.src.oui_resolved")
                } else {
                    packet.last("eth.src.oui_resolved")
                },
            );
        }
        if let Some(node) = target.as_deref() {
            let (target_ipv4, target_ipv6) = if is_gtp {
                packet.outer_ips("ip.dst", "ipv6.dst")
            } else {
                (
                    packet.all("ip.dst").to_vec(),
                    packet.all("ipv6.dst").to_vec(),
                )
            };
            self.touch_node(
                node,
                time,
                bytes,
                &protocol,
                &target_ipv4,
                &target_ipv6,
                if is_gtp {
                    packet.first("eth.dst.oui_resolved")
                } else {
                    packet.last("eth.dst.oui_resolved")
                },
            );
            if is_gtp {
                self.observe_gtp_receiver(node, &packet, time, bytes);
            }
        }
        if let (Some(source), Some(target)) = (source.as_deref(), target.as_deref()) {
            let key = ordered_pair(source, target);
            let edge = self.edges.entry(key.clone()).or_insert_with(|| Edge {
                source: key.0,
                target: key.1,
                protocols: BTreeSet::new(),
                first_seen: time,
                last_seen: time,
                packet_count: 0,
                byte_count: 0,
            });
            edge.last_seen = time;
            edge.packet_count += 1;
            edge.byte_count += bytes;
            edge.protocols.insert(protocol.clone());
        }

        let Some(default_node) = (if is_gtp {
            target.as_deref().or(source.as_deref())
        } else {
            source.as_deref().or(target.as_deref())
        }) else {
            return;
        };
        let default_peer = if source.as_deref() == Some(default_node) {
            target.clone()
        } else {
            source.clone()
        };
        let mut base = BTreeMap::from([("frame".to_owned(), frame.to_string())]);
        add_repeated(&mut base, "ethernet_sources", packet.all("eth.src"));
        add_repeated(&mut base, "ethernet_destinations", packet.all("eth.dst"));
        add_repeated(&mut base, "source_ips", packet.all("ip.src"));
        add_repeated(&mut base, "source_ipv6", packet.all("ipv6.src"));
        add_repeated(&mut base, "destination_ips", packet.all("ip.dst"));
        add_repeated(&mut base, "destination_ipv6", packet.all("ipv6.dst"));
        add_repeated(&mut base, "vlans", packet.all("vlan.id"));
        add_repeated(&mut base, "gtp_teids", packet.all("gtp.teid"));
        add_repeated(&mut base, "gtp_message_types", packet.all("gtp.message"));
        add_repeated(&mut base, "gre_keys", packet.all("gre.key"));
        add_repeated(&mut base, "pppoe_sessions", packet.all("pppoe.session_id"));
        if !packet.first("frame.protocols").is_empty() {
            base.insert("layers".into(), packet.first("frame.protocols").to_owned());
        }

        if source_new && let Some(node) = source.as_deref() {
            self.emit_once(
                format!("{node}:discovered"),
                frame,
                time,
                node,
                target.clone(),
                "device_discovered",
                "info",
                &protocol,
                "Device appeared",
                format!("First traffic observed from {node}."),
                base.clone(),
            );
        }
        if target_new && let Some(node) = target.as_deref() {
            self.emit_once(
                format!("{node}:discovered"),
                frame,
                time,
                node,
                source.clone(),
                "device_discovered",
                "info",
                &protocol,
                "Device appeared",
                format!("First traffic observed from {node}."),
                base.clone(),
            );
        }

        self.tunnel_events(
            &packet,
            frame,
            time,
            default_node,
            default_peer.clone(),
            &base,
        );
        self.dns_events(
            &packet,
            frame,
            time,
            source.as_deref(),
            target.as_deref(),
            &base,
        );
        self.tls_events(
            &packet,
            frame,
            time,
            source.as_deref(),
            target.as_deref(),
            &base,
        );
        self.http_events(
            &packet,
            frame,
            time,
            source.as_deref(),
            target.as_deref(),
            &base,
        );
        self.mqtt_events(
            &packet,
            frame,
            time,
            default_node,
            default_peer.clone(),
            &base,
        );
        self.sip_events(
            &packet,
            frame,
            time,
            default_node,
            default_peer.clone(),
            &base,
        );
        self.cellular_events(
            &packet,
            frame,
            time,
            default_node,
            default_peer.clone(),
            &base,
        );
        self.media_events(
            &packet,
            frame,
            time,
            default_node,
            default_peer.clone(),
            &base,
        );
        self.management_events(
            &packet,
            frame,
            time,
            default_node,
            default_peer.clone(),
            &base,
        );
        self.discovery_events(
            &packet,
            frame,
            time,
            default_node,
            default_peer.clone(),
            &base,
        );
        self.encrypted_events(&packet, frame, time, default_node, default_peer, &base);
    }

    #[allow(clippy::too_many_arguments)]
    fn touch_node(
        &mut self,
        id: &str,
        time: f64,
        bytes: u64,
        protocol: &str,
        ipv4: &[String],
        ipv6: &[String],
        manufacturer: &str,
    ) {
        let node = self.nodes.entry(id.to_owned()).or_insert_with(|| Node {
            mac: id.to_owned(),
            manufacturers: BTreeSet::new(),
            ips: BTreeSet::new(),
            hostnames: BTreeSet::new(),
            protocols: BTreeSet::new(),
            first_seen: time,
            last_seen: time,
            packet_count: 0,
            byte_count: 0,
            event_count: 0,
            gtp_receiver: false,
            gtp_first_seen: None,
            mobile_ues: BTreeMap::new(),
        });
        node.last_seen = time;
        node.packet_count += 1;
        node.byte_count += bytes;
        node.protocols.insert(protocol.to_owned());
        node.ips.extend(ipv4.iter().cloned());
        node.ips.extend(ipv6.iter().cloned());
        if !manufacturer.is_empty() && manufacturer != "Private" {
            node.manufacturers.insert(manufacturer.to_owned());
        }
    }

    fn observe_gtp_receiver(&mut self, receiver: &str, packet: &Packet, time: f64, bytes: u64) {
        let Some(node) = self.nodes.get_mut(receiver) else {
            return;
        };
        node.gtp_receiver = true;
        node.gtp_first_seen.get_or_insert(time);
        let Some(ip) = packet.inner_gtp_destination() else {
            return;
        };
        let session = node
            .mobile_ues
            .entry(ip.clone())
            .or_insert_with(|| MobileUeSession {
                ip,
                teids: BTreeSet::new(),
                first_seen: time,
                last_seen: time,
                packet_count: 0,
                byte_count: 0,
            });
        session.last_seen = time;
        session.packet_count += 1;
        session.byte_count += bytes;
        session.teids.extend(packet.all("gtp.teid").iter().cloned());
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn emit(
        &mut self,
        frame: u64,
        time: f64,
        node: &str,
        peer: Option<String>,
        kind: &str,
        severity: &str,
        protocol: &str,
        title: impl Into<String>,
        summary: impl Into<String>,
        details: BTreeMap<String, String>,
    ) {
        if let Some(node) = self.nodes.get_mut(node) {
            node.event_count += 1;
        }
        self.events.push(Event {
            id: self.events.len() as u64 + 1,
            time,
            frame,
            node: node.to_owned(),
            peer,
            kind: kind.to_owned(),
            severity: severity.to_owned(),
            protocol: protocol.to_owned(),
            title: title.into(),
            summary: summary.into(),
            details,
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn emit_once(
        &mut self,
        key: String,
        frame: u64,
        time: f64,
        node: &str,
        peer: Option<String>,
        kind: &str,
        severity: &str,
        protocol: &str,
        title: impl Into<String>,
        summary: impl Into<String>,
        details: BTreeMap<String, String>,
    ) {
        if self.seen.insert(key) {
            self.emit(
                frame, time, node, peer, kind, severity, protocol, title, summary, details,
            );
        }
    }

    /// Replaces the model's derived nodes, edges, and events with a stable snapshot.
    pub fn publish(&self, model: &mut CaptureModel) {
        model.nodes = self.nodes.values().cloned().collect();
        model.nodes.sort_by(|a, b| a.mac.cmp(&b.mac));
        model.edges = self.edges.values().cloned().collect();
        model
            .edges
            .sort_by(|a, b| (&a.source, &a.target).cmp(&(&b.source, &b.target)));
        model.events = self.events.clone();
    }
}

fn application_protocol(packet: &Packet) -> String {
    packet
        .first("frame.protocols")
        .split(':')
        .next_back()
        .unwrap_or("eth")
        .to_uppercase()
}

pub(super) fn insert_value(details: &mut BTreeMap<String, String>, key: &str, value: &str) {
    if !value.is_empty() {
        details.insert(key.to_owned(), truncate(value));
    }
}

pub(super) fn add_repeated(details: &mut BTreeMap<String, String>, key: &str, values: &[String]) {
    if !values.is_empty() {
        details.insert(key.to_owned(), truncate(&values.join(", ")));
    }
}

pub(super) fn add_cellular_details(details: &mut BTreeMap<String, String>, packet: &Packet) {
    for (key, field) in [
        ("s1ap_m_tmsi", "s1ap.m_TMSI"),
        ("mme_ue_s1ap_ids", "s1ap.MME_UE_S1AP_ID"),
        ("enb_ue_s1ap_ids", "s1ap.ENB_UE_S1AP_ID"),
        ("s1ap_tac", "s1ap.TAC"),
        ("s1ap_plmn", "s1ap.PLMNidentity"),
        ("enb_ids", "s1ap.eNB_ID"),
        ("cell_ids", "s1ap.cell_ID"),
        ("amf_ue_ngap_ids", "ngap.AMF_UE_NGAP_ID"),
        ("ran_ue_ngap_ids", "ngap.RAN_UE_NGAP_ID"),
        ("ngap_5g_tmsi", "ngap.fiveG_TMSI"),
        ("ngap_tac", "ngap.TAC"),
        ("ngap_plmn", "ngap.PLMNIdentity"),
        ("nas_eps_message_type", "nas-eps.nas_msg_emm_type"),
        ("mme_code", "nas-eps.emm.mme_code"),
        ("nas_eps_m_tmsi", "nas-eps.emm.m_tmsi"),
        ("nas_eps_tac", "nas-eps.emm.tai_tac"),
        ("nas_5gs_mm_message_type", "nas-5gs.mm.message_type"),
        ("nas_5gs_sm_message_type", "nas-5gs.sm.message_type"),
        ("amf_region_id", "nas-5gs.amf_region_id"),
        ("amf_set_id", "nas-5gs.amf_set_id"),
        ("nas_5g_tmsi", "nas-5gs.5g_tmsi"),
        ("nas_5gs_tac", "nas-5gs.tac"),
        ("mcc", "e212.mcc"),
        ("mnc", "e212.mnc"),
    ] {
        add_repeated(details, key, packet.all(field));
    }
}

pub(super) fn truncate(value: &str) -> String {
    if value.len() <= MAX_DETAIL {
        return value.to_owned();
    }
    let mut end = MAX_DETAIL;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

pub(super) fn decode_hex_or_text(value: &str) -> String {
    let compact = value.replace(':', "");
    if compact.len() >= 2
        && compact.len().is_multiple_of(2)
        && compact.bytes().all(|b| b.is_ascii_hexdigit())
    {
        let bytes = compact
            .as_bytes()
            .chunks_exact(2)
            .filter_map(|pair| {
                let text = std::str::from_utf8(pair).ok()?;
                u8::from_str_radix(text, 16).ok()
            })
            .collect::<Vec<_>>();
        String::from_utf8(bytes).unwrap_or_else(|_| value.to_owned())
    } else {
        value.to_owned()
    }
}

pub(super) fn decode_ntp_refid(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let raw = value.trim_start_matches("0x").replace(':', "");
    if raw.len() == 8 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        let decoded = decode_hex_or_text(&raw);
        if decoded.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            return format!("{decoded} ({value})");
        }
    }
    value.to_owned()
}

pub(super) fn parameter_value<'a>(input: &'a str, name: &str) -> Option<&'a str> {
    input.split(';').skip(1).find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim_matches('"'))
    })
}

/// Normalizes a colon-separated MAC address to lowercase.
///
/// Returns `None` for malformed or non-canonical input.
pub fn normalize_mac(value: &str) -> Option<String> {
    let mac = value.trim().to_ascii_lowercase();
    (mac.len() == 17
        && mac.chars().enumerate().all(|(i, c)| {
            if [2, 5, 8, 11, 14].contains(&i) {
                c == ':'
            } else {
                c.is_ascii_hexdigit()
            }
        }))
    .then_some(mac)
}

/// Returns whether a canonical MAC address is broadcast or multicast.
pub fn is_group_mac(mac: &str) -> bool {
    mac == "ff:ff:ff:ff:ff:ff"
        || u8::from_str_radix(mac.get(0..2).unwrap_or_default(), 16)
            .is_ok_and(|first| first & 1 == 1)
}

fn ordered_pair(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.into(), b.into())
    } else {
        (b.into(), a.into())
    }
}
pub(super) fn value_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() { fallback } else { value }
}
pub(super) fn party_suffix(from: &str, to: &str) -> String {
    if !from.is_empty() && !to.is_empty() {
        format!(" · {from} → {to}")
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests;
