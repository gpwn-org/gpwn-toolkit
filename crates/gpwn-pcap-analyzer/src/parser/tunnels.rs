use super::*;

impl Analyzer {
    pub(super) fn tunnel_events(
        &mut self,
        p: &Packet,
        frame: u64,
        time: f64,
        node: &str,
        peer: Option<String>,
        base: &BTreeMap<String, String>,
    ) {
        for vlan in p.all("vlan.id") {
            let mut details = base.clone();
            details.insert("vlan".into(), vlan.clone());
            self.emit_once(
                format!("{node}:vlan:{vlan}"),
                frame,
                time,
                node,
                peer.clone(),
                "vlan_seen",
                "info",
                "VLAN",
                format!("Seen on VLAN {vlan}"),
                "Observed tagged subscriber or infrastructure traffic.",
                details,
            );
        }
        for (field, layer, label) in [
            ("gtp.teid", "GTP", "GTP tunnel"),
            ("gre.key", "GRE", "GRE tunnel"),
            ("pppoe.session_id", "PPPoE", "PPPoE session"),
        ] {
            for id in p.all(field) {
                let mut details = base.clone();
                details.insert("tunnel_id".into(), id.clone());
                self.emit_once(
                    format!("{node}:{layer}:{id}"),
                    frame,
                    time,
                    node,
                    peer.clone(),
                    "tunnel_observed",
                    "info",
                    layer,
                    label,
                    format!("Observed {label} identifier {id}."),
                    details,
                );
            }
        }
    }
}
