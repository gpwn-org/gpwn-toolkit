use super::*;

impl Analyzer {
    pub(super) fn management_events(
        &mut self,
        p: &Packet,
        frame: u64,
        time: f64,
        node: &str,
        peer: Option<String>,
        base: &BTreeMap<String, String>,
    ) {
        if !p.all("snmp.community").is_empty() || p.has_layer("snmp") {
            let mut details = base.clone();
            for (key, field) in [
                ("community", "snmp.community"),
                ("version", "snmp.version"),
                ("request_id", "snmp.request_id"),
                ("oids", "snmp.name"),
                ("integer_values", "snmp.value.int"),
                ("octet_values", "snmp.value.octets"),
                ("oid_values", "snmp.value.oid"),
                ("ip_values", "snmp.value.ipv4"),
            ] {
                add_repeated(&mut details, key, p.all(field));
            }
            let community = value_or(p.last("snmp.community"), "unknown community");
            self.emit(
                frame,
                time,
                node,
                peer.clone(),
                "snmp_activity",
                "important",
                "SNMP",
                format!("SNMP {community}"),
                "SNMP management traffic was visible.",
                details,
            );
        }
        if !p.all("stun.type").is_empty() || p.has_layer("stun") {
            let mut details = base.clone();
            for (key, field) in [
                ("type", "stun.type"),
                ("class", "stun.type.class"),
                ("method", "stun.type.method"),
                ("software", "stun.att.software"),
                ("realm", "stun.att.realm"),
                ("username", "stun.att.username"),
                ("values", "stun.value"),
            ] {
                add_repeated(&mut details, key, p.all(field));
            }
            self.emit(
                frame,
                time,
                node,
                peer.clone(),
                "stun_activity",
                "notable",
                "STUN",
                "STUN/TURN activity",
                "NAT traversal metadata was observed.",
                details,
            );
        }
        if !p.all("ntp.stratum").is_empty() || p.has_layer("ntp") {
            let mut details = base.clone();
            insert_value(&mut details, "stratum", p.last("ntp.stratum"));
            let refid = decode_ntp_refid(p.last("ntp.refid"));
            if !refid.is_empty() {
                details.insert("reference_id".into(), refid);
            }
            self.emit(
                frame,
                time,
                node,
                peer.clone(),
                "ntp_activity",
                "info",
                "NTP",
                "NTP time service",
                "NTP timing metadata was observed.",
                details,
            );
        }
        if !p.all("ftp.request.command").is_empty() || !p.all("ftp.response.code").is_empty() {
            let mut details = base.clone();
            for (key, field) in [
                ("command", "ftp.request.command"),
                ("argument", "ftp.request.arg"),
                ("response_code", "ftp.response.code"),
                ("response", "ftp.response.arg"),
            ] {
                add_repeated(&mut details, key, p.all(field));
            }
            let auth_tls = p
                .all("ftp.request.command")
                .iter()
                .any(|v| v.eq_ignore_ascii_case("AUTH"))
                && p.all("ftp.request.arg")
                    .iter()
                    .any(|v| v.eq_ignore_ascii_case("TLS"));
            self.emit(
                frame,
                time,
                node,
                peer,
                if auth_tls {
                    "ftps_negotiation"
                } else {
                    "ftp_activity"
                },
                "notable",
                "FTP",
                if auth_tls {
                    "FTP upgraded to TLS"
                } else {
                    "FTP metadata"
                },
                "FTP control-channel metadata was observed.",
                details,
            );
        }
    }

    pub(super) fn discovery_events(
        &mut self,
        p: &Packet,
        frame: u64,
        time: f64,
        node: &str,
        peer: Option<String>,
        base: &BTreeMap<String, String>,
    ) {
        for address in p.all("arp.src.proto_ipv4") {
            if let Some(entity) = self.nodes.get_mut(node) {
                entity.ips.insert(address.clone());
            }
            let mut details = base.clone();
            details.insert("address".into(), address.clone());
            self.emit_once(
                format!("{node}:arp:{address}"),
                frame,
                time,
                node,
                peer.clone(),
                "address_claimed",
                "info",
                "ARP",
                format!("Claimed {address}"),
                "An endpoint announced an IPv4 address using ARP.",
                details,
            );
        }
        if !p.all("dhcp.option.hostname").is_empty() {
            if let Some(entity) = self.nodes.get_mut(node) {
                entity
                    .hostnames
                    .extend(p.all("dhcp.option.hostname").iter().cloned());
            }
            let mut details = base.clone();
            add_repeated(&mut details, "hostnames", p.all("dhcp.option.hostname"));
            add_repeated(
                &mut details,
                "requested_ips",
                p.all("dhcp.option.requested_ip_address"),
            );
            self.emit(
                frame,
                time,
                node,
                peer.clone(),
                "dhcp_identity",
                "notable",
                "DHCP",
                "DHCP identity",
                "DHCP identity metadata was observed.",
                details,
            );
        }
        if !p.all("dhcpv6.msgtype").is_empty() || p.has_layer("dhcpv6") {
            let mut details = base.clone();
            add_repeated(&mut details, "message_types", p.all("dhcpv6.msgtype"));
            add_repeated(
                &mut details,
                "client_domains",
                p.all("dhcpv6.client_domain"),
            );
            self.emit(
                frame,
                time,
                node,
                peer.clone(),
                "dhcpv6_activity",
                "info",
                "DHCPv6",
                "DHCPv6 discovery",
                "DHCPv6 metadata was observed.",
                details,
            );
        }
        for (layer, kind, title) in [
            ("mdns", "mdns_activity", "mDNS discovery"),
            ("llmnr", "llmnr_activity", "LLMNR discovery"),
            ("ssdp", "ssdp_activity", "SSDP discovery"),
        ] {
            if p.has_layer(layer) {
                let mut details = base.clone();
                add_repeated(&mut details, "names", p.all("dns.qry.name"));
                self.emit(
                    frame,
                    time,
                    node,
                    peer.clone(),
                    kind,
                    "info",
                    &layer.to_uppercase(),
                    title,
                    "Local service discovery traffic was observed.",
                    details,
                );
            }
        }
    }

    pub(super) fn encrypted_events(
        &mut self,
        p: &Packet,
        frame: u64,
        time: f64,
        node: &str,
        peer: Option<String>,
        base: &BTreeMap<String, String>,
    ) {
        for (layer, label) in [
            ("quic", "QUIC"),
            ("gquic", "gQUIC"),
            ("dtls", "DTLS"),
            ("esp", "IPsec ESP"),
            ("wireguard", "WireGuard"),
            ("openvpn", "OpenVPN"),
            ("isakmp", "IKE/ISAKMP"),
            ("srtp", "SRTP"),
            ("btdht", "BitTorrent DHT"),
        ] {
            if p.has_layer(layer) {
                let mut details = base.clone();
                details.insert("encrypted_protocol".into(), label.into());
                self.emit_once(format!("{node}:encrypted:{layer}"), frame, time, node, peer.clone(), "encrypted_protocol", "info", label,
                    format!("{label} observed"), "Encrypted protocol presence was identified; payload contents were not inspected.", details);
            }
        }
    }
}
