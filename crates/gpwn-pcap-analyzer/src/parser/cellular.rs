use super::*;

impl Analyzer {
    pub(super) fn cellular_events(
        &mut self,
        p: &Packet,
        frame: u64,
        time: f64,
        node: &str,
        peer: Option<String>,
        base: &BTreeMap<String, String>,
    ) {
        for (field, protocol, kind) in [
            ("s1ap.procedureCode", "S1AP", "s1ap_procedure"),
            ("x2ap.procedureCode", "X2AP", "x2ap_procedure"),
            ("ngap.procedureCode", "NGAP", "ngap_procedure"),
            ("xnap.procedureCode", "XnAP", "xnap_procedure"),
        ] {
            for procedure in p.all(field) {
                let mut details = base.clone();
                details.insert("procedure_code".into(), procedure.clone());
                add_cellular_details(&mut details, p);
                self.emit(
                    frame,
                    time,
                    node,
                    peer.clone(),
                    kind,
                    "important",
                    protocol,
                    format!("{protocol} procedure {procedure}"),
                    "Cellular control-plane signalling was observed.",
                    details,
                );
            }
        }
        let nas_fields = [
            "nas-eps.nas_msg_emm_type",
            "nas-5gs.mm.message_type",
            "nas-5gs.sm.message_type",
        ];
        let has_nas = nas_fields.iter().any(|field| !p.all(field).is_empty());
        let has_procedure = [
            "s1ap.procedureCode",
            "x2ap.procedureCode",
            "ngap.procedureCode",
            "xnap.procedureCode",
        ]
        .iter()
        .any(|field| !p.all(field).is_empty());
        if has_nas && !has_procedure {
            let mut details = base.clone();
            add_cellular_details(&mut details, p);
            self.emit(
                frame,
                time,
                node,
                peer,
                "nas_control",
                "important",
                "NAS",
                "Cellular NAS message",
                "Visible LTE/5G NAS control metadata was observed.",
                details,
            );
        }
    }

    pub(super) fn media_events(
        &mut self,
        p: &Packet,
        frame: u64,
        time: f64,
        node: &str,
        peer: Option<String>,
        base: &BTreeMap<String, String>,
    ) {
        for ssrc in p.all("rtp.ssrc") {
            let mut details = base.clone();
            details.insert("ssrc".into(), ssrc.clone());
            insert_value(&mut details, "payload_type", p.last("rtp.p_type"));
            self.emit_once(
                format!("{node}:rtp:{ssrc}"),
                frame,
                time,
                node,
                peer.clone(),
                "rtp_stream",
                "notable",
                "RTP",
                "RTP media stream",
                format!("Observed RTP SSRC {ssrc}."),
                details,
            );
        }
        if p.has_layer("rtcp") {
            let mut details = base.clone();
            for (key, field) in [
                ("sender_ssrc", "rtcp.senderssrc"),
                ("media_ssrc", "rtcp.mediassrc"),
                ("fraction_lost", "rtcp.ssrc.fraction"),
                ("jitter", "rtcp.ssrc.jitter"),
                ("sdes", "rtcp.sdes.text"),
            ] {
                add_repeated(&mut details, key, p.all(field));
            }
            self.emit(
                frame,
                time,
                node,
                peer,
                "rtcp_report",
                "notable",
                "RTCP",
                "RTCP quality report",
                "An RTCP control or quality report was observed.",
                details,
            );
        }
    }
}
