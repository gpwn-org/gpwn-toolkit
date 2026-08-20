//! Connect to an ONU in an explicitly authorized test deployment and print a
//! read-only snapshot.

use gpwn_core::OnuBackend;
use gpwn_ssh::{ConnectionConfig, LiveBackend};

#[tokio::main]
async fn main() -> gpwn_core::Result<()> {
    let defaults = ConnectionConfig::default();

    let host = std::env::var("GPWN_HOST").unwrap_or_else(|_| defaults.host);
    let username = std::env::var("GPWN_USERNAME").unwrap_or_else(|_| defaults.username);
    let password = std::env::var("GPWN_PASSWORD")
        .map_err(|_| gpwn_core::Error::Validation("set GPWN_PASSWORD".into()))?;

    println!("connecting to {}@{} ...", &username, &host);

    let mut backend = LiveBackend::new(ConnectionConfig {
        username,
        password,
        host,
        ..ConnectionConfig::default()
    });

    let connection = backend.connect().await?;
    println!("connected to {}", connection.endpoint);
    let snapshot = backend.fetch_snapshot().await?;
    println!("ONU state: {}", snapshot.line.onu_state);
    backend.disconnect().await
}
