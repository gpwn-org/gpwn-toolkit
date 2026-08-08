//! List interfaces that `dumpcap` can capture on the current host.

fn main() -> gpwn_core::Result<()> {
    for interface in gpwn_capture::interfaces()? {
        println!("{}", interface.label());
    }
    Ok(())
}
