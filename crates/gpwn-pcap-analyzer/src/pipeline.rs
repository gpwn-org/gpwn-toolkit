use crate::fields::FIELDS;
use crate::model::CaptureModel;
use crate::parser::Analyzer;
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::RwLock;

/// Builds the tshark field-extraction command used by [`analyze`].
///
/// When `follow` is true, tshark reads a growing capture from standard input.
/// `artifact_dir` enables inline HTTP object export for that streaming mode.
pub fn tshark_command(input: &Path, follow: bool, artifact_dir: Option<&Path>) -> Command {
    let mut command = Command::new("tshark");
    command.arg("-l").arg("-n");
    if follow {
        command.arg("-r").arg("-");
    } else {
        command.arg("-r").arg(input);
    }
    command
        .arg("-o")
        .arg("tcp.desegment_tcp_streams:TRUE")
        .arg("-o")
        .arg("http.desegment_body:TRUE");
    if let Some(directory) = artifact_dir {
        command
            .arg("--export-objects")
            .arg(format!("http,{}", directory.display()));
    }
    command
        .arg("-T")
        .arg("fields")
        .arg("-E")
        .arg("separator=/t")
        .arg("-E")
        .arg("aggregator=|")
        .arg("-E")
        .arg("occurrence=a")
        .arg("-E")
        .arg("escape=y")
        .arg("-E")
        .arg("quote=n");
    for field in FIELDS {
        command.arg("-e").arg(field);
    }
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if follow {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    command
}

/// Runs object export in its own fast pass for completed captures. TShark only
/// writes `--export-objects` results when that pass finishes; coupling it to
/// the much heavier field-analysis pass therefore keeps Media empty for the
/// entire analysis of a large capture.
pub fn artifact_command(input: &Path, directory: &Path) -> Command {
    let mut command = Command::new("tshark");
    command
        .arg("-n")
        .arg("-r")
        .arg(input)
        .arg("-q")
        .arg("-o")
        .arg("tcp.desegment_tcp_streams:TRUE")
        .arg("-o")
        .arg("http.desegment_body:TRUE");
    for protocol in ["http", "tftp", "imf", "ftp-data"] {
        command
            .arg("--export-objects")
            .arg(format!("{protocol},{}", directory.display()));
    }
    command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    command
}

async fn export_artifacts(input: PathBuf, directory: PathBuf) -> Result<()> {
    let output = artifact_command(&input, &directory)
        .output()
        .await
        .context("starting tshark artifact exporter")?;
    if !output.status.success() {
        bail!(
            "tshark artifact export failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Opens `path` once and retains both that descriptor and its cursor while the
/// capture grows. Temporary EOF is not treated as file completion.
pub async fn feed_growing_file(path: PathBuf, mut stdin: tokio::process::ChildStdin) -> Result<()> {
    let mut file = loop {
        match tokio::fs::File::open(&path).await {
            Ok(file) => break file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(error) => return Err(error).with_context(|| format!("opening {}", path.display())),
        }
    };
    let mut buffer = vec![0_u8; 256 * 1024];
    loop {
        match file.read(&mut buffer).await? {
            0 => tokio::time::sleep(Duration::from_millis(100)).await,
            count => stdin.write_all(&buffer[..count]).await?,
        }
    }
}

/// Analyzes a completed or growing capture into a shared model.
///
/// The function owns the tshark child process until it exits. In follow mode,
/// `path` is tailed through one persistent file descriptor. When requested,
/// completed captures export artifacts in a parallel tshark pass and
/// `artifacts_complete` becomes true after that pass succeeds.
pub async fn analyze(
    path: PathBuf,
    follow: bool,
    artifact_dir: Option<PathBuf>,
    index_json: Option<PathBuf>,
    shared: Arc<RwLock<CaptureModel>>,
    artifacts_complete: Arc<AtomicBool>,
) -> Result<()> {
    artifacts_complete.store(artifact_dir.is_none(), Ordering::Release);
    if let Some(directory) = artifact_dir.as_deref() {
        tokio::fs::create_dir_all(directory)
            .await
            .with_context(|| format!("creating artifact directory {}", directory.display()))?;
    }
    let artifact_task = if follow {
        None
    } else {
        artifact_dir.clone().map(|directory| {
            let input = path.clone();
            let complete = Arc::clone(&artifacts_complete);
            tokio::spawn(async move {
                let result = export_artifacts(input, directory).await;
                if result.is_ok() {
                    complete.store(true, Ordering::Release);
                }
                result
            })
        })
    };
    // A growing stdin stream must retain export in the same process so it sees
    // every byte. Completed files use the parallel exporter above.
    let inline_artifact_dir = follow.then_some(artifact_dir.as_deref()).flatten();
    let mut child = tshark_command(&path, follow, inline_artifact_dir)
        .spawn()
        .context("starting tshark; install Wireshark and ensure tshark is on PATH")?;
    if follow {
        let stdin = child.stdin.take().context("opening tshark stdin")?;
        tokio::spawn(async move {
            if let Err(error) = feed_growing_file(path, stdin).await {
                eprintln!("PCAP follower stopped: {error:#}");
            }
        });
    }
    let analysis_result = consume_tshark(&mut child, follow, index_json, shared).await;
    if let Some(task) = artifact_task {
        task.await.context("joining tshark artifact exporter")??;
    } else if analysis_result.is_ok() {
        // In follow mode tshark flushes its inline exporter when the stream ends.
        artifacts_complete.store(true, Ordering::Release);
    }
    analysis_result
}

async fn consume_tshark(
    child: &mut Child,
    follow: bool,
    index_json: Option<PathBuf>,
    shared: Arc<RwLock<CaptureModel>>,
) -> Result<()> {
    let stdout = child.stdout.take().context("opening tshark stdout")?;
    let stderr = child.stderr.take().context("opening tshark stderr")?;
    let stderr_task = tokio::spawn(async move {
        let mut text = String::new();
        BufReader::new(stderr).read_to_string(&mut text).await.ok();
        text
    });
    let mut lines = BufReader::new(stdout).lines();
    let mut analyzer = Analyzer::default();
    let mut pending = 0_usize;
    let mut publish_tick = tokio::time::interval(Duration::from_millis(300));
    let mut persist_tick = tokio::time::interval(Duration::from_secs(10));
    persist_tick.tick().await;
    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line? else { break };
                let mut model = shared.write().await;
                analyzer.consume_line(&line, &mut model);
                model.status = if follow { "following" } else { "loading" }.to_owned();
                pending += 1;
                if pending >= 2048 { pending = 0; tokio::task::yield_now().await; }
            }
            _ = publish_tick.tick() => {
                let mut model = shared.write().await;
                analyzer.publish(&mut model);
                model.status = if follow { "following" } else { "loading" }.to_owned();
            }
            _ = persist_tick.tick(), if index_json.is_some() => {
                {
                    let mut model = shared.write().await;
                    analyzer.publish(&mut model);
                }
                persist_snapshot(index_json.as_deref().expect("guarded"), &shared).await?;
            }
        }
    }
    let status = child.wait().await?;
    let stderr = stderr_task.await.unwrap_or_default();
    if !status.success() {
        bail!("tshark failed: {}", stderr.trim());
    }
    {
        let mut model = shared.write().await;
        analyzer.publish(&mut model);
        model.status = "ready".to_owned();
    }
    if let Some(path) = index_json.as_deref() {
        persist_snapshot(path, &shared).await?;
    }
    Ok(())
}

async fn persist_snapshot(path: &Path, shared: &Arc<RwLock<CaptureModel>>) -> Result<()> {
    let bytes = serde_json::to_vec(&*shared.read().await)?;
    if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temporary = path.with_extension("gpwn-tmp");
    tokio::fs::write(&temporary, bytes).await?;
    tokio::fs::rename(&temporary, path).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn dns_pcap() -> Vec<u8> {
        let dns: Vec<u8> = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x01,
            0x02, 0x03, 0x04,
        ];
        let udp_len = 8 + dns.len();
        let ip_len = 20 + udp_len;
        let mut packet = vec![
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
        ];
        packet.extend_from_slice(&[
            0x45,
            0,
            (ip_len >> 8) as u8,
            ip_len as u8,
            0,
            1,
            0,
            0,
            64,
            17,
            0,
            0,
            8,
            8,
            8,
            8,
            10,
            0,
            0,
            2,
        ]);
        packet.extend_from_slice(&[0, 53, 0xc0, 0x00, (udp_len >> 8) as u8, udp_len as u8, 0, 0]);
        packet.extend_from_slice(&dns);
        let mut pcap = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0,
            0,
        ];
        pcap.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
        let len = packet.len() as u32;
        pcap.extend_from_slice(&len.to_le_bytes());
        pcap.extend_from_slice(&len.to_le_bytes());
        pcap.extend_from_slice(&packet);
        pcap
    }

    fn http_png_pcap() -> Vec<u8> {
        let body = b"\x89PNG\r\n\x1a\n";
        let mut payload =
            b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 8\r\n\r\n".to_vec();
        payload.extend_from_slice(body);
        let tcp_len = 20 + payload.len();
        let ip_len = 20 + tcp_len;
        let mut packet = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        ];
        packet.extend_from_slice(&[
            0x45,
            0,
            (ip_len >> 8) as u8,
            ip_len as u8,
            0,
            1,
            0,
            0,
            64,
            6,
            0,
            0,
            192,
            0,
            2,
            1,
            192,
            0,
            2,
            2,
        ]);
        packet.extend_from_slice(&[
            0, 80, 0xc0, 0x00, 0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0,
        ]);
        packet.extend_from_slice(&payload);
        let mut pcap = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0,
            0,
        ];
        pcap.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
        let len = packet.len() as u32;
        pcap.extend_from_slice(&len.to_le_bytes());
        pcap.extend_from_slice(&len.to_le_bytes());
        pcap.extend_from_slice(&packet);
        pcap
    }

    #[tokio::test]
    async fn tiny_pcap_runs_through_real_tshark() {
        if Command::new("tshark")
            .arg("-v")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .is_err()
        {
            return;
        }
        let directory =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/gpwn-pcap-analyzer-tests");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("dns-response.pcap");
        fs::write(&path, dns_pcap()).unwrap();
        let shared = Arc::new(RwLock::new(CaptureModel::new(&path, false)));
        analyze(
            path,
            false,
            None,
            None,
            Arc::clone(&shared),
            Arc::new(AtomicBool::new(true)),
        )
        .await
        .unwrap();
        let model = shared.read().await;
        assert_eq!(model.packet_count, 1);
        assert!(
            model
                .events
                .iter()
                .any(|event| event.kind == "dns_response")
        );
    }

    #[tokio::test]
    async fn tiny_pcap_runs_through_streaming_tshark_stdin() {
        if Command::new("tshark")
            .arg("-v")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .is_err()
        {
            return;
        }
        let mut child = tshark_command(Path::new("ignored.pcap"), true, None)
            .spawn()
            .unwrap();
        let bytes = dns_pcap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(&bytes[..24]).await.unwrap();
        stdin.write_all(&bytes[24..]).await.unwrap();
        stdin.shutdown().await.unwrap();
        drop(stdin);
        let stdout = child.stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();
        let mut analyzer = Analyzer::default();
        let mut model = CaptureModel::new(Path::new("stream.pcap"), true);
        while let Some(line) = lines.next_line().await.unwrap() {
            analyzer.consume_line(&line, &mut model);
        }
        assert!(child.wait().await.unwrap().success());
        analyzer.publish(&mut model);
        assert!(
            model
                .events
                .iter()
                .any(|event| event.kind == "dns_response")
        );
    }

    #[tokio::test]
    async fn completed_capture_exports_http_media_in_parallel() {
        if Command::new("tshark")
            .arg("-v")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .is_err()
        {
            return;
        }
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/gpwn-pcap-analyzer-tests/http-artifact");
        let artifact_dir = root.join("objects");
        fs::remove_dir_all(&root).ok();
        fs::create_dir_all(&root).unwrap();
        let path = root.join("http-image.pcap");
        fs::write(&path, http_png_pcap()).unwrap();
        let shared = Arc::new(RwLock::new(CaptureModel::new(&path, false)));
        let complete = Arc::new(AtomicBool::new(false));
        analyze(
            path,
            false,
            Some(artifact_dir.clone()),
            None,
            shared,
            Arc::clone(&complete),
        )
        .await
        .unwrap();
        assert!(complete.load(Ordering::Acquire));
        let recovered = fs::read_dir(artifact_dir)
            .unwrap()
            .flatten()
            .filter_map(|entry| fs::read(entry.path()).ok())
            .collect::<Vec<_>>();
        assert!(recovered.iter().any(|bytes| bytes == b"\x89PNG\r\n\x1a\n"));
    }

    #[test]
    fn follow_command_reads_stdin_and_requests_all_occurrences() {
        let command = tshark_command(Path::new("ignored.pcap"), true, None);
        let args = command
            .as_std()
            .get_args()
            .map(|s| s.to_string_lossy())
            .collect::<Vec<_>>();
        assert!(args.windows(2).any(|pair| pair == ["-r", "-"]));
        assert!(args.iter().any(|arg| arg == "occurrence=a"));
    }

    #[test]
    fn artifact_command_exports_each_supported_object_protocol() {
        let command = artifact_command(Path::new("capture.pcap"), Path::new("objects"));
        let args = command
            .as_std()
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        for protocol in ["http", "tftp", "imf", "ftp-data"] {
            assert!(args.iter().any(|arg| arg == &format!("{protocol},objects")));
        }
    }
}
