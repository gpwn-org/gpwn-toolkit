//! Validate an autoscan configuration and inspect its non-overlapping batches.

use gpwn_scan::AutoscanConfig;

fn main() -> gpwn_core::Result<()> {
    let config = AutoscanConfig {
        gem_start: 100,
        gem_end: 355,
        batch_size: 64,
        observation_secs: 2.0,
        aes: false,
    };
    config.validate()?;
    for (index, (start, end)) in config.batches().into_iter().enumerate() {
        println!("batch {}: GEM {start}..={end}", index + 1);
    }
    Ok(())
}
