//! Connect to an ONU in an explicitly authorized test deployment and print a
//! read-only snapshot.

use gpwn_core::OnuBackend;
use gpwn_ssh::{ConnectionConfig, LiveBackend};

#[tokio::main]
async fn main() -> gpwn_core::Result<()> {
    let password = std::env::var("GPWN_PASSWORD")
        .map_err(|_| gpwn_core::Error::Validation("set GPWN_PASSWORD".into()))?;
    let mut backend = LiveBackend::new(ConnectionConfig {
        password,
        ..ConnectionConfig::default()
    });
    let connection = backend.connect().await?;
    println!("connected to {}", connection.endpoint);
    let snapshot = backend.fetch_snapshot().await?;
    println!("ONU state: {}", snapshot.line.onu_state);
    backend.disconnect().await
}
