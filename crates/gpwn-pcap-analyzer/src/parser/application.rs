use super::*;

impl Analyzer {
    pub(super) fn dns_events(
        &mut self,
        p: &Packet,
        frame: u64,
        time: f64,
        source: Option<&str>,
        target: Option<&str>,
        base: &BTreeMap<String, String>,
    ) {
        let names = p.all("dns.qry.name");
        if names.is_empty() {
            return;
        }
        let response = p
            .all("dns.flags.response")
            .iter()
            .any(|value| value == "1" || value.eq_ignore_ascii_case("true"));
        let (node, peer) = if response {
            (target.or(source), source.map(str::to_owned))
        } else {
            (source.or(target), target.map(str::to_owned))
        };
        let Some(node) = node else { return };
        let mut details = base.clone();
        add_repeated(&mut details, "names", names);
        add_repeated(&mut details, "answers_ipv4", p.all("dns.a"));
        add_repeated(&mut details, "answers_ipv6", p.all("dns.aaaa"));
        add_repeated(&mut details, "cnames", p.all("dns.cname"));
        add_repeated(&mut details, "ttl", p.all("dns.resp.ttl"));
        insert_value(&mut details, "rcode", p.last("dns.flags.rcode"));
        let name = names.last().map(String::as_str).unwrap_or("DNS name");
        let (kind, title, summary) = if response {
            (
                "dns_response",
                format!("DNS response for {name}"),
                format!("Received DNS results for {name}."),
            )
        } else {
            (
                "dns_query",
                format!("Looked up {name}"),
                format!("Queried DNS for {name}."),
            )
        };
        self.emit(
            frame, time, node, peer, kind, "info", "DNS", title, summary, details,
        );
    }

    pub(super) fn tls_events(
        &mut self,
        p: &Packet,
        frame: u64,
        time: f64,
        source: Option<&str>,
        target: Option<&str>,
        base: &BTreeMap<String, String>,
    ) {
        for name in p.all("tls.handshake.extensions_server_name") {
            let Some(node) = source.or(target) else {
                continue;
            };
            let mut details = base.clone();
            details.insert("server_name".into(), name.clone());
            self.emit(
                frame,
                time,
                node,
                target.map(str::to_owned),
                "tls_sni",
                "notable",
                "TLS",
                format!("TLS SNI {name}"),
                format!("A TLS ClientHello named {name}."),
                details,
            );
        }
        let certificate = p
            .all("tls.handshake.type")
            .iter()
            .any(|value| value == "11");
        if certificate {
            let Some(node) = target.or(source) else {
                return;
            };
            let mut details = base.clone();
            add_repeated(&mut details, "subject_names", p.all("x509ce.dNSName"));
            add_repeated(&mut details, "subject_values", p.all("x509sat.uTF8String"));
            add_repeated(&mut details, "serial_numbers", p.all("x509af.serialNumber"));
            let display = p.last("x509ce.dNSName");
            self.emit(
                frame,
                time,
                node,
                source.map(str::to_owned),
                "tls_certificate",
                "notable",
                "TLS",
                if display.is_empty() {
                    "TLS server certificate".into()
                } else {
                    format!("Certificate for {display}")
                },
                "A TLS server certificate was visible in the handshake.",
                details,
            );
        }
    }

    pub(super) fn http_events(
        &mut self,
        p: &Packet,
        frame: u64,
        time: f64,
        source: Option<&str>,
        target: Option<&str>,
        base: &BTreeMap<String, String>,
    ) {
        let method = p.last("http.request.method");
        let status = p.last("http.response.code");
        if method.is_empty() && status.is_empty() && !p.has_layer("http") {
            return;
        }
        let response = !status.is_empty();
        let Some(node) = (if response {
            target.or(source)
        } else {
            source.or(target)
        }) else {
            return;
        };
        let peer = if response { source } else { target }.map(str::to_owned);
        let mut details = base.clone();
        for (key, field) in [
            ("host", "http.host"),
            ("method", "http.request.method"),
            ("uri", "http.request.uri"),
            ("status", "http.response.code"),
            ("content_type", "http.content_type"),
            ("content_length", "http.content_length"),
            ("server", "http.server"),
            ("user_agent", "http.user_agent"),
        ] {
            insert_value(&mut details, key, p.last(field));
        }
        let host = value_or(p.last("http.host"), "HTTP peer");
        let (kind, title) = if response {
            (
                "http_response",
                format!("HTTP {} from {host}", value_or(status, "response")),
            )
        } else {
            (
                "http_request",
                format!("{} {host}", value_or(method, "HTTP")),
            )
        };
        self.emit(
            frame,
            time,
            node,
            peer,
            kind,
            "notable",
            "HTTP",
            title,
            if response {
                "Received a plaintext HTTP response."
            } else {
                "Sent a plaintext HTTP request."
            },
            details,
        );
    }

    pub(super) fn mqtt_events(
        &mut self,
        p: &Packet,
        frame: u64,
        time: f64,
        node: &str,
        peer: Option<String>,
        base: &BTreeMap<String, String>,
    ) {
        if p.all("mqtt.topic").is_empty() && p.all("mqtt.msg").is_empty() && !p.has_layer("mqtt") {
            return;
        }
        let mut details = base.clone();
        add_repeated(&mut details, "topics", p.all("mqtt.topic"));
        insert_value(&mut details, "qos", p.last("mqtt.qos"));
        insert_value(&mut details, "retain", p.last("mqtt.retain"));
        insert_value(&mut details, "client_id", p.last("mqtt.clientid"));
        let messages = p
            .all("mqtt.msg")
            .iter()
            .map(|raw| decode_hex_or_text(raw))
            .collect::<Vec<_>>();
        if !messages.is_empty() {
            details.insert("messages".into(), truncate(&messages.join("\n")));
        }
        let topic = value_or(p.last("mqtt.topic"), "MQTT");
        self.emit(
            frame,
            time,
            node,
            peer,
            "mqtt_message",
            "important",
            "MQTT",
            format!("MQTT {topic}"),
            "An MQTT topic or payload was visible in plaintext.",
            details,
        );
    }

    pub(super) fn sip_events(
        &mut self,
        p: &Packet,
        frame: u64,
        time: f64,
        node: &str,
        peer: Option<String>,
        base: &BTreeMap<String, String>,
    ) {
        let method = p.last("sip.Method");
        let status = p.last("sip.Status-Code");
        if method.is_empty() && status.is_empty() {
            return;
        }
        let mut details = base.clone();
        for (key, field) in [
            ("method", "sip.Method"),
            ("status", "sip.Status-Code"),
            ("from_raw", "sip.From"),
            ("to_raw", "sip.To"),
            ("from", "sip.from.user"),
            ("from_host", "sip.from.host"),
            ("to", "sip.to.user"),
            ("to_host", "sip.to.host"),
            ("asserted_identity", "sip.P-Asserted-Identity"),
            ("asserted_identity_host", "sip.pai.host"),
            ("call_id", "sip.Call-ID"),
            ("contact", "sip.Contact"),
            ("contact_host", "sip.contact.host"),
            ("media_address", "sdp.connection_info.address"),
            ("media_port", "sdp.media.port"),
        ] {
            insert_value(&mut details, key, p.last(field));
        }
        if let Some(token) = parameter_value(p.last("sip.Contact"), "pn-prid") {
            details.insert("push_token".into(), truncate(token));
        }
        let (kind, severity, title) = match method {
            "INVITE" => (
                "sip_call_started",
                "important",
                format!(
                    "SIP call{}",
                    party_suffix(p.last("sip.from.user"), p.last("sip.to.user"))
                ),
            ),
            "BYE" => ("sip_call_ended", "notable", "SIP call ended".into()),
            "REGISTER" => ("sip_registered", "notable", "SIP registration".into()),
            _ if !status.is_empty() => ("sip_response", "info", format!("SIP response {status}")),
            _ => ("sip_activity", "info", format!("SIP {method}")),
        };
        self.emit(
            frame,
            time,
            node,
            peer,
            kind,
            severity,
            "SIP",
            title,
            "Visible SIP/IMS signalling activity.",
            details,
        );
    }
}
