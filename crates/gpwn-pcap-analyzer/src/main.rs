use anyhow::{Context, Result, bail};
use axum::{Router, routing::get};
use clap::Parser;
use gpwn_pcap_analyzer::api::{self, AppState};
use gpwn_pcap_analyzer::favicon::FaviconCache;
use gpwn_pcap_analyzer::model::CaptureModel;
use gpwn_pcap_analyzer::pipeline;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, atomic::AtomicBool};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

#[derive(Parser, Debug)]
#[command(about = "Read-only PCAP/PCAPNG analyzer and local web API", version)]
struct Args {
    /// A single PCAP or PCAPNG file. Reports and prior analysis are never read.
    #[arg(value_name = "PCAP")]
    pcap: PathBuf,
    /// Keep one file descriptor and one tshark process open as the file grows.
    #[arg(long)]
    follow: bool,
    #[arg(long, default_value = "127.0.0.1:8799")]
    listen: SocketAddr,
    /// Analyze, write the backwards-compatible model JSON, then exit.
    #[arg(long, value_name = "PATH")]
    export_json: Option<PathBuf>,
    /// Periodically persist the derived model. The PCAP remains the only input.
    #[arg(long, value_name = "PATH")]
    index_json: Option<PathBuf>,
    /// Export reassembled plaintext HTTP objects here and serve them through the API.
    #[arg(long, value_name = "DIR")]
    artifact_dir: Option<PathBuf>,
    /// Favicon URL template; `{domain}` is replaced with the registrable domain.
    #[arg(
        long,
        default_value = "https://icons.duckduckgo.com/ip3/{domain}.ico",
        hide = true
    )]
    favicon_upstream: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if !args.pcap.exists() && !args.follow {
        bail!("{} does not exist", args.pcap.display());
    }
    if args.pcap.exists() && !args.pcap.is_file() {
        bail!("{} is not a single capture file", args.pcap.display());
    }
    let shared = Arc::new(RwLock::new(CaptureModel::new(&args.pcap, args.follow)));
    let artifacts_complete = Arc::new(AtomicBool::new(args.artifact_dir.is_none()));

    if let Some(output) = args.export_json {
        if args.follow {
            bail!("--export-json cannot be combined with --follow");
        }
        pipeline::analyze(
            args.pcap,
            false,
            args.artifact_dir,
            args.index_json,
            Arc::clone(&shared),
            Arc::clone(&artifacts_complete),
        )
        .await?;
        let json = serde_json::to_vec_pretty(&*shared.read().await)?;
        std::fs::write(&output, json).with_context(|| format!("writing {}", output.display()))?;
        println!("{}", output.display());
        return Ok(());
    }

    let analyze_path = args.pcap.clone();
    let analyze_shared = Arc::clone(&shared);
    let analyze_artifacts_complete = Arc::clone(&artifacts_complete);
    let artifact_dir = args.artifact_dir.clone();
    tokio::spawn(async move {
        if let Err(error) = pipeline::analyze(
            analyze_path,
            args.follow,
            artifact_dir,
            args.index_json,
            Arc::clone(&analyze_shared),
            analyze_artifacts_complete,
        )
        .await
        {
            eprintln!("analysis stopped: {error:#}");
            analyze_shared.write().await.status = "error".to_owned();
        }
    });

    let state = AppState {
        model: shared,
        favicon: FaviconCache::new(args.favicon_upstream),
        artifact_dir: args.artifact_dir.clone(),
        artifacts_complete,
    };
    let app = Router::new()
        .route("/api/model", get(api::model))
        .route("/api/overview", get(api::overview))
        .route("/api/events", get(api::events))
        .route("/api/event-kinds", get(api::event_kinds))
        .route("/api/artifacts", get(api::artifacts))
        .route("/api/artifacts/files/{*path}", get(api::serve_artifact))
        .route("/api/favicon/{domain}", get(api::favicon))
        .route("/api/health", get(api::health));
    let app = app.layer(CorsLayer::permissive()).with_state(state);
    println!("GPWN analyzer API: http://{}", args.listen);
    axum::serve(tokio::net::TcpListener::bind(args.listen).await?, app).await?;
    Ok(())
}
