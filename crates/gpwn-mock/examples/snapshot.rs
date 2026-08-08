//! Fetch a deterministic ONU snapshot with no device or network access.

use gpwn_core::OnuBackend;
use gpwn_mock::{MockBackend, MockScenario};

#[tokio::main]
async fn main() -> gpwn_core::Result<()> {
    let mut backend = MockBackend::new(MockScenario::Healthy);
    backend.connect().await?;
    let snapshot = backend.fetch_snapshot().await?;
    println!(
        "state={} downstream={} upstream={}",
        snapshot.line.onu_state,
        snapshot.downstream.len(),
        snapshot.upstream.len()
    );
    backend.disconnect().await
}
