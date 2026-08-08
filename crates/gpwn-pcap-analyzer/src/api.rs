use crate::favicon::FaviconCache;
use crate::model::{Artifact, ArtifactPage, CaptureModel, EventPage};
use axum::Json;
use axum::body::Body;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode, header};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::RwLock;
use tokio_util::io::ReaderStream;

#[derive(Clone)]
/// Shared state supplied to all analyzer HTTP handlers.
pub struct AppState {
    /// Latest published capture model.
    pub model: Arc<RwLock<CaptureModel>>,
    /// In-memory cache and upstream client for domain icons.
    pub favicon: FaviconCache,
    /// Root containing tshark-exported objects, when object export is enabled.
    pub artifact_dir: Option<PathBuf>,
    /// Whether artifact extraction has completed successfully.
    pub artifacts_complete: Arc<AtomicBool>,
}

#[derive(Debug, Default, Deserialize)]
/// Filtering and pagination parameters accepted by the events endpoint.
pub struct EventQuery {
    /// Number of matching events to skip.
    pub offset: Option<usize>,
    /// Maximum number of events to return, clamped to `1..=1000`.
    pub limit: Option<usize>,
    /// Exact event-kind filter.
    pub kind: Option<String>,
    /// Case-insensitive protocol-name filter.
    pub protocol: Option<String>,
    /// Case-insensitive text search over event metadata and details.
    pub q: Option<String>,
    /// Inclusive minimum capture-relative event time.
    pub from: Option<f64>,
    /// Inclusive maximum capture-relative event time.
    pub to: Option<f64>,
}

/// Returns the complete current capture model.
pub async fn model(State(state): State<AppState>) -> Json<CaptureModel> {
    Json(state.model.read().await.clone())
}

/// Return graph and capture metadata without cloning the potentially enormous event list.
/// Events remain available through the bounded, filterable `/api/events` endpoint.
pub async fn overview(State(state): State<AppState>) -> Json<CaptureModel> {
    let model = state.model.read().await;
    Json(CaptureModel {
        source: model.source.clone(),
        mode: model.mode.clone(),
        status: model.status.clone(),
        packet_count: model.packet_count,
        first_timestamp: model.first_timestamp,
        last_timestamp: model.last_timestamp,
        duration: model.duration,
        nodes: model.nodes.clone(),
        edges: model.edges.clone(),
        events: Vec::new(),
    })
}

/// Returns a bounded, optionally filtered page of protocol events.
pub async fn events(
    State(state): State<AppState>,
    Query(query): Query<EventQuery>,
) -> Json<EventPage> {
    let offset = query.offset.unwrap_or_default();
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let needle = query.q.as_deref().map(str::to_ascii_lowercase);
    let model = state.model.read().await;
    let filtered = model
        .events
        .iter()
        .filter(|event| {
            query.kind.as_deref().is_none_or(|kind| event.kind == kind)
                && query
                    .protocol
                    .as_deref()
                    .is_none_or(|protocol| event.protocol.eq_ignore_ascii_case(protocol))
                && query.from.is_none_or(|from| event.time >= from)
                && query.to.is_none_or(|to| event.time <= to)
                && needle.as_deref().is_none_or(|needle| {
                    event.title.to_ascii_lowercase().contains(needle)
                        || event.summary.to_ascii_lowercase().contains(needle)
                        || event.node.to_ascii_lowercase().contains(needle)
                        || event
                            .peer
                            .as_deref()
                            .unwrap_or_default()
                            .to_ascii_lowercase()
                            .contains(needle)
                        || event.details.iter().any(|(key, value)| {
                            key.to_ascii_lowercase().contains(needle)
                                || value.to_ascii_lowercase().contains(needle)
                        })
                })
        })
        .collect::<Vec<_>>();
    Json(EventPage {
        items: filtered
            .iter()
            .skip(offset)
            .take(limit)
            .map(|event| (*event).clone())
            .collect(),
        total: filtered.len(),
        offset,
        limit,
    })
}

#[derive(Debug, Serialize)]
/// Counts of published events grouped by event kind.
pub struct EventKinds {
    /// Mapping from stable event-kind identifier to occurrence count.
    pub kinds: BTreeMap<String, usize>,
}

/// Returns event counts grouped by kind.
pub async fn event_kinds(State(state): State<AppState>) -> Json<EventKinds> {
    let mut kinds = BTreeMap::new();
    for event in &state.model.read().await.events {
        *kinds.entry(event.kind.clone()).or_default() += 1;
    }
    Json(EventKinds { kinds })
}

/// Returns a cached favicon or generated fallback for a validated domain.
pub async fn favicon(
    State(state): State<AppState>,
    AxumPath(domain): AxumPath<String>,
) -> Response<Body> {
    state.favicon.response(&domain).await
}

#[derive(Debug, Default, Deserialize)]
/// Pagination parameters accepted by the artifacts endpoint.
pub struct ArtifactQuery {
    /// Number of sorted artifacts to skip.
    pub offset: Option<usize>,
    /// Maximum number of artifacts to return, clamped to `1..=1000`.
    pub limit: Option<usize>,
    /// Broad media category: visible, image, video, audio, text, archive, or other.
    pub category: Option<String>,
}

/// Scans the configured export directory and returns a page of artifacts.
pub async fn artifacts(
    State(state): State<AppState>,
    Query(query): Query<ArtifactQuery>,
) -> Json<ArtifactPage> {
    let offset = query.offset.unwrap_or_default();
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let mut all_items = state
        .artifact_dir
        .as_deref()
        .map(scan_artifacts)
        .unwrap_or_default();
    all_items.sort_by(|a, b| a.name.cmp(&b.name));
    let mut counts = BTreeMap::new();
    for item in &all_items {
        *counts
            .entry(artifact_category(&item.media_type).to_string())
            .or_default() += 1;
        if item.media_type != "application/octet-stream" {
            *counts.entry("visible".to_string()).or_default() += 1;
        }
    }
    let items: Vec<_> = match query.category.as_deref() {
        Some("visible") => all_items
            .into_iter()
            .filter(|item| item.media_type != "application/octet-stream")
            .collect(),
        Some(category @ ("image" | "video" | "audio" | "text" | "archive" | "other")) => all_items
            .into_iter()
            .filter(|item| artifact_category(&item.media_type) == category)
            .collect(),
        _ => all_items,
    };
    let total = items.len();
    Json(ArtifactPage {
        items: items.into_iter().skip(offset).take(limit).collect(),
        total,
        offset,
        limit,
        complete: state.artifacts_complete.load(Ordering::Acquire),
        counts,
    })
}

fn artifact_category(media_type: &str) -> &'static str {
    let media = media_type.to_ascii_lowercase();
    if media.starts_with("image/") && !media.contains("svg") {
        "image"
    } else if media.starts_with("video/") {
        "video"
    } else if media.starts_with("audio/") {
        "audio"
    } else if media.starts_with("text/")
        || matches!(
            media.as_str(),
            "application/json"
                | "application/xml"
                | "application/x-pem-file"
                | "application/pkix-cert"
        )
    {
        "text"
    } else if ["zip", "gzip", "xz", "cab", "tar", "rar", "7z"]
        .iter()
        .any(|needle| media.contains(needle))
    {
        "archive"
    } else {
        "other"
    }
}

/// Streams one exported artifact, including support for single byte ranges.
///
/// Requested paths are canonicalized beneath the configured artifact root.
/// Active content is forced to download with a safe media type.
pub async fn serve_artifact(
    State(state): State<AppState>,
    AxumPath(requested): AxumPath<String>,
    request_headers: HeaderMap,
) -> Response<Body> {
    let Some(root) = state.artifact_dir.as_deref() else {
        return status_response(StatusCode::NOT_FOUND);
    };
    let Some(path) = safe_artifact_path(root, &requested).await else {
        return status_response(StatusCode::NOT_FOUND);
    };
    let Ok(metadata) = tokio::fs::metadata(&path).await else {
        return status_response(StatusCode::NOT_FOUND);
    };
    if !metadata.is_file() {
        return status_response(StatusCode::NOT_FOUND);
    }
    let size = metadata.len();
    let range = match request_headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
    {
        Some(value) => match parse_range(value, size) {
            Some(range) => Some(range),
            None => {
                let mut response = status_response(StatusCode::RANGE_NOT_SATISFIABLE);
                response.headers_mut().insert(
                    header::CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes */{size}")).expect("valid range"),
                );
                return response;
            }
        },
        None => None,
    };
    let Ok(mut file) = tokio::fs::File::open(&path).await else {
        return status_response(StatusCode::NOT_FOUND);
    };
    let (start, end, status) = range.map_or(
        (0, size.saturating_sub(1), StatusCode::OK),
        |(start, end)| (start, end, StatusCode::PARTIAL_CONTENT),
    );
    if file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
        return status_response(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let length = if size == 0 { 0 } else { end - start + 1 };
    let stream = ReaderStream::new(file.take(length));
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(safe_media_type(&path)),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&length.to_string()).expect("valid length"),
    );
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artifact")
        .replace(['"', '\r', '\n'], "_");
    let disposition = if is_safe_inline_media(&path) {
        format!("inline; filename=\"{filename}\"")
    } else {
        format!("attachment; filename=\"{filename}\"")
    };
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition)
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    if status == StatusCode::PARTIAL_CONTENT {
        headers.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {start}-{end}/{size}")).expect("valid range"),
        );
    }
    response
}

async fn safe_artifact_path(root: &Path, requested: &str) -> Option<PathBuf> {
    let relative = Path::new(requested);
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return None;
    }
    let root = tokio::fs::canonicalize(root).await.ok()?;
    let path = tokio::fs::canonicalize(root.join(relative)).await.ok()?;
    path.starts_with(&root).then_some(path)
}

fn parse_range(value: &str, size: u64) -> Option<(u64, u64)> {
    let range = value.strip_prefix("bytes=")?;
    if range.contains(',') || size == 0 {
        return None;
    }
    let (start, end) = range.split_once('-')?;
    if start.is_empty() {
        let suffix = end.parse::<u64>().ok()?.min(size);
        if suffix == 0 {
            return None;
        }
        return Some((size - suffix, size - 1));
    }
    let start = start.parse::<u64>().ok()?;
    if start >= size {
        return None;
    }
    let end = if end.is_empty() {
        size - 1
    } else {
        end.parse::<u64>().ok()?.min(size - 1)
    };
    (start <= end).then_some((start, end))
}

fn status_response(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

fn scan_artifacts(root: &Path) -> Vec<Artifact> {
    let mut result = Vec::new();
    scan_directory(root, root, &mut result);
    result
}

fn scan_directory(root: &Path, directory: &Path, result: &mut Vec<Artifact>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            scan_directory(root, &path, result);
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        let id = relative.to_string_lossy().replace('\\', "/");
        result.push(Artifact {
            id: id.clone(),
            name: entry.file_name().to_string_lossy().into_owned(),
            size: metadata.len(),
            media_type: media_type(&path).into(),
            url: format!("/api/artifacts/files/{}", percent_encode_path(&id)),
        });
    }
}

fn percent_encode_path(path: &str) -> String {
    let mut output = String::new();
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            output.push(byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn media_type(path: &Path) -> &'static str {
    let from_extension = match path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "jpg" | "jpeg" | "jfif" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "bmp" => "image/bmp",
        "ico" => "image/x-icon",
        "svg" => "image/svg+xml",
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "avi" => "video/x-msvideo",
        "ts" | "mpegts" => "video/mp2t",
        "mp3" => "audio/mpeg",
        "aac" => "audio/aac",
        "wav" => "audio/wav",
        "ogg" | "oga" => "audio/ogg",
        "json" => "application/json",
        "txt" | "log" => "text/plain",
        "html" | "htm" => "text/plain",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "xz" => "application/x-xz",
        "cab" => "application/vnd.ms-cab-compressed",
        _ => "application/octet-stream",
    };
    if from_extension == "application/octet-stream" {
        sniff_media_type(path).unwrap_or(from_extension)
    } else {
        from_extension
    }
}

fn sniff_media_type(path: &Path) -> Option<&'static str> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path).ok()?;
    let mut bytes = [0_u8; 512];
    let count = file.read(&mut bytes).ok()?;
    let bytes = &bytes[..count];
    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        return Some("image/jpeg");
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("image/png");
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some("image/gif");
    }
    if bytes.starts_with(b"BM") {
        return Some("image/bmp");
    }
    if bytes.starts_with(&[0, 0, 1, 0]) {
        return Some("image/x-icon");
    }
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" {
        return match &bytes[8..12] {
            b"WEBP" => Some("image/webp"),
            b"WAVE" => Some("audio/wav"),
            b"AVI " => Some("video/x-msvideo"),
            _ => None,
        };
    }
    if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" {
        return match &bytes[8..12] {
            b"avif" | b"avis" => Some("image/avif"),
            _ => Some("video/mp4"),
        };
    }
    if bytes.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]) {
        return Some("video/webm");
    }
    if bytes.starts_with(b"OggS") {
        return Some("audio/ogg");
    }
    if bytes
        .get(..2)
        .is_some_and(|head| head[0] == 0xff && matches!(head[1] & 0xf6, 0xf0 | 0xf2))
    {
        return Some("audio/aac");
    }
    if bytes.starts_with(b"ID3")
        || bytes
            .get(..2)
            .is_some_and(|head| head[0] == 0xff && head[1] & 0xe0 == 0xe0)
    {
        return Some("audio/mpeg");
    }
    if bytes.len() > 376 && bytes[0] == 0x47 && bytes[188] == 0x47 && bytes[376] == 0x47 {
        return Some("video/mp2t");
    }
    if bytes.starts_with(b"%PDF-") {
        return Some("application/pdf");
    }
    if bytes.starts_with(b"PK\x03\x04") {
        return Some("application/zip");
    }
    None
}

fn is_active_content(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "html" | "htm" | "xhtml" | "svg" | "js" | "mjs" | "xml"
    )
}

fn safe_media_type(path: &Path) -> &'static str {
    if is_active_content(path) {
        "text/plain; charset=utf-8"
    } else {
        media_type(path)
    }
}

fn is_safe_inline_media(path: &Path) -> bool {
    matches!(safe_media_type(path), value if value.starts_with("image/") || value.starts_with("audio/") || value.starts_with("video/"))
}

/// Returns the constant health-check response `ok`.
pub async fn health() -> &'static str {
    "ok"
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use std::fs;

    fn test_state(root: PathBuf) -> AppState {
        AppState {
            model: Arc::new(RwLock::new(CaptureModel::new(
                Path::new("fixture.pcap"),
                false,
            ))),
            favicon: FaviconCache::new("https://invalid.example/{domain}".into()),
            artifact_dir: Some(root),
            artifacts_complete: Arc::new(AtomicBool::new(true)),
        }
    }

    #[tokio::test]
    async fn overview_omits_the_unbounded_event_payload() {
        let state = test_state(PathBuf::new());
        state.model.write().await.events.push(crate::model::Event {
            id: 1,
            time: 0.0,
            frame: 1,
            node: "00:11:22:33:44:55".into(),
            peer: None,
            kind: "device_discovered".into(),
            severity: "info".into(),
            protocol: "Ethernet".into(),
            title: "Device appeared".into(),
            summary: "Observed".into(),
            details: BTreeMap::new(),
        });
        let Json(result) = overview(State(state)).await;
        assert_eq!(result.source, "fixture.pcap");
        assert!(result.events.is_empty());
    }
    #[test]
    fn captured_html_is_not_marked_renderable() {
        assert_eq!(media_type(Path::new("captured.html")), "text/plain");
    }
    #[test]
    fn artifact_paths_are_encoded() {
        assert_eq!(percent_encode_path("a folder/x.png"), "a%20folder/x.png");
    }

    #[test]
    fn extensionless_exported_objects_are_sniffed() {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/gpwn-artifact-api/sniff");
        fs::create_dir_all(&root).unwrap();
        let jpeg = root.join("image-resource");
        fs::write(
            &jpeg,
            [0xff, 0xd8, 0xff, 0xe0, 0, 16, b'J', b'F', b'I', b'F'],
        )
        .unwrap();
        let png = root.join("object8.image%2fpng");
        fs::write(&png, b"\x89PNG\r\n\x1a\nrest").unwrap();
        assert_eq!(media_type(&jpeg), "image/jpeg");
        assert_eq!(media_type(&png), "image/png");
        assert!(is_safe_inline_media(&jpeg));
        assert!(is_safe_inline_media(&png));
    }

    #[tokio::test]
    async fn artifact_pagination_is_bounded_and_sorted() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/gpwn-artifact-api/pagination");
        fs::create_dir_all(&root).unwrap();
        for name in ["c.png", "a.png", "b.png"] {
            fs::write(root.join(name), b"x").unwrap();
        }
        let Json(page) = artifacts(
            State(test_state(root.clone())),
            Query(ArtifactQuery {
                offset: Some(1),
                limit: Some(1),
                category: None,
            }),
        )
        .await;
        assert_eq!(page.total, 3);
        assert_eq!(page.offset, 1);
        assert_eq!(page.limit, 1);
        assert_eq!(page.items[0].name, "b.png");
    }

    #[tokio::test]
    async fn artifact_categories_filter_before_pagination() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/gpwn-artifact-api/categories");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("photo.png"), b"\x89PNG\r\n\x1a\nrest").unwrap();
        fs::write(root.join("payload.bin"), b"opaque").unwrap();
        let Json(page) = artifacts(
            State(test_state(root)),
            Query(ArtifactQuery {
                offset: None,
                limit: Some(10),
                category: Some("visible".into()),
            }),
        )
        .await;
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].media_type, "image/png");
        assert_eq!(page.counts.get("other"), Some(&1));
    }

    #[tokio::test]
    async fn artifact_traversal_is_rejected() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/gpwn-artifact-api/traversal");
        fs::create_dir_all(&root).unwrap();
        let response = serve_artifact(
            State(test_state(root.clone())),
            AxumPath("../secret".into()),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        #[cfg(unix)]
        {
            let outside = root.with_file_name("outside.txt");
            fs::write(&outside, b"secret").unwrap();
            let link = root.join("escape.txt");
            let _ = fs::remove_file(&link);
            std::os::unix::fs::symlink(&outside, &link).unwrap();
            let response = serve_artifact(
                State(test_state(root)),
                AxumPath("escape.txt".into()),
                HeaderMap::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn active_artifact_is_plain_attachment_with_nosniff() {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/gpwn-artifact-api/active");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("captured.html"), b"<script>alert(1)</script>").unwrap();
        let response = serve_artifact(
            State(test_state(root)),
            AxumPath("captured.html".into()),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        assert!(
            response.headers()[header::CONTENT_DISPOSITION]
                .to_str()
                .unwrap()
                .starts_with("attachment")
        );
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(
            &to_bytes(response.into_body(), 1024).await.unwrap()[..],
            b"<script>alert(1)</script>"
        );
    }

    #[tokio::test]
    async fn media_artifact_supports_byte_ranges() {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/gpwn-artifact-api/range");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("clip.mp4"), b"0123456789").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=2-5"));
        let response = serve_artifact(
            State(test_state(root)),
            AxumPath("clip.mp4".into()),
            headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes 2-5/10");
        assert_eq!(response.headers()[header::CONTENT_TYPE], "video/mp4");
        assert_eq!(
            &to_bytes(response.into_body(), 1024).await.unwrap()[..],
            b"2345"
        );
    }
}
