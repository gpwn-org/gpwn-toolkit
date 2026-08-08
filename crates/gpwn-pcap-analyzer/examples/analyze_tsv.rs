use gpwn_pcap_analyzer::{
    fields::{self, FIELDS},
    model::CaptureModel,
    parser::Analyzer,
};
use std::path::Path;

fn main() {
    // The analyzer accepts the same ordered TSV schema produced by
    // `pipeline::tshark_command`, which makes it easy to embed downstream of a
    // custom tshark process or replay saved field rows.
    let mut columns = vec![String::new(); FIELDS.len()];
    for (name, value) in [
        ("frame.number", "1"),
        ("frame.time_epoch", "1723000000.125"),
        ("frame.len", "128"),
        ("frame.protocols", "eth:ip:udp:dns"),
        ("eth.src", "00:11:22:33:44:55"),
        ("eth.dst", "66:77:88:99:aa:bb"),
        ("dns.qry.name", "example.com"),
    ] {
        columns[fields::index(name)] = value.to_owned();
    }

    let mut analyzer = Analyzer::default();
    let mut model = CaptureModel::new(Path::new("example.pcap"), false);
    analyzer.consume_line(&columns.join("\t"), &mut model);
    analyzer.publish(&mut model);

    println!(
        "{} packets, {} events",
        model.packet_count,
        model.events.len()
    );
    for event in model.events {
        println!("{}: {}", event.protocol, event.title);
    }
}
