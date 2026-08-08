use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode, header};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::sync::RwLock;

const MAX_ICON_BYTES: usize = 256 * 1024;

#[derive(Clone)]
/// Fetches and caches small, validated raster favicons by registrable domain.
///
/// Failed fetches receive a generated SVG fallback cached for five minutes;
/// successful images are cached for 24 hours.
pub struct FaviconCache {
    upstream: Arc<str>,
    entries: Arc<RwLock<HashMap<String, CachedIcon>>>,
}

#[derive(Clone)]
struct CachedIcon {
    bytes: Vec<u8>,
    media_type: &'static str,
    expires: Instant,
}

impl FaviconCache {
    /// Creates an empty cache using an upstream URL or URL template.
    ///
    /// If `upstream` contains `{domain}`, that placeholder is replaced.
    /// Otherwise `/{domain}.ico` is appended to the URL.
    pub fn new(upstream: String) -> Self {
        Self {
            upstream: upstream.into(),
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns an HTTP image response for `requested`.
    ///
    /// Invalid hostnames receive `400 Bad Request`; valid hostnames return a
    /// validated cached image or a generated SVG fallback.
    pub async fn response(&self, requested: &str) -> Response<Body> {
        let Some(domain) = registrable_domain(requested) else {
            return response(StatusCode::BAD_REQUEST, "image/svg+xml", fallback_svg("?"));
        };
        if let Some(icon) = self
            .entries
            .read()
            .await
            .get(&domain)
            .filter(|icon| icon.expires > Instant::now())
            .cloned()
        {
            return response(StatusCode::OK, icon.media_type, icon.bytes);
        }
        let fetched = self.fetch(&domain).await;
        let icon = match fetched {
            Some((bytes, media_type)) => CachedIcon {
                bytes,
                media_type,
                expires: Instant::now() + Duration::from_secs(24 * 60 * 60),
            },
            None => CachedIcon {
                bytes: fallback_svg(&domain),
                media_type: "image/svg+xml",
                expires: Instant::now() + Duration::from_secs(5 * 60),
            },
        };
        self.entries.write().await.insert(domain, icon.clone());
        response(StatusCode::OK, icon.media_type, icon.bytes)
    }

    async fn fetch(&self, domain: &str) -> Option<(Vec<u8>, &'static str)> {
        let url = if self.upstream.contains("{domain}") {
            self.upstream.replace("{domain}", domain)
        } else {
            format!("{}/{domain}.ico", self.upstream.trim_end_matches('/'))
        };
        let output = Command::new("curl")
            .arg("--silent")
            .arg("--show-error")
            .arg("--fail")
            .arg("--location")
            .arg("--max-redirs")
            .arg("2")
            .arg("--connect-timeout")
            .arg("3")
            .arg("--max-time")
            .arg("5")
            .arg("--max-filesize")
            .arg(MAX_ICON_BYTES.to_string())
            .arg("--proto")
            .arg("=http,https")
            .arg(&url)
            .output()
            .await
            .ok()?;
        if !output.status.success()
            || output.stdout.is_empty()
            || output.stdout.len() > MAX_ICON_BYTES
        {
            return None;
        }
        let media_type = image_type(&output.stdout)?;
        Some((output.stdout, media_type))
    }
}

fn response(status: StatusCode, media_type: &'static str, bytes: Vec<u8>) -> Response<Body> {
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(media_type));
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn image_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0, 0, 1, 0]) {
        Some("image/x-icon")
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        Some("image/webp")
    } else {
        None
    }
}

/// Reduces a validated hostname to its registrable-domain approximation.
///
/// IP addresses and malformed DNS names return `None`. A small built-in list
/// handles common multi-label public suffixes used by captured subscriber
/// traffic; other names retain their final two labels.
pub fn registrable_domain(input: &str) -> Option<String> {
    let host = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.len() > 253 || host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let labels = host.split('.').collect::<Vec<_>>();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return None;
    }
    let suffix2 = labels[labels.len() - 2..].join(".");
    let common_second_level = [
        "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.in", "firm.in", "net.in", "org.in",
        "co.jp", "com.br", "com.cn",
    ];
    let count = if common_second_level.contains(&suffix2.as_str()) {
        3
    } else {
        2
    };
    if labels.len() < count {
        return None;
    }
    Some(labels[labels.len() - count..].join("."))
}

fn fallback_svg(domain: &str) -> Vec<u8> {
    let letter = domain
        .chars()
        .find(|c| c.is_ascii_alphanumeric())
        .unwrap_or('?')
        .to_ascii_uppercase();
    format!(r##"<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#243047"/><text x="16" y="22" text-anchor="middle" font-family="sans-serif" font-size="18" fill="white">{letter}</text></svg>"##).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn base_domain_normalizes_hosts_and_common_country_suffixes() {
        assert_eq!(
            registrable_domain("img.cdn.Example.COM."),
            Some("example.com".into())
        );
        assert_eq!(
            registrable_domain("a.b.example.co.in"),
            Some("example.co.in".into())
        );
        assert_eq!(registrable_domain("127.0.0.1"), None);
        assert_eq!(registrable_domain("bad_domain.example"), None);
    }

    #[test]
    fn only_known_raster_formats_are_accepted_from_remote() {
        assert_eq!(image_type(b"\x00\x00\x01\x00rest"), Some("image/x-icon"));
        assert_eq!(image_type(b"<svg><script/>"), None);
        assert_eq!(image_type(b"html"), None);
    }

    #[tokio::test]
    async fn successful_remote_icon_is_cached() {
        if Command::new("curl")
            .arg("--version")
            .output()
            .await
            .is_err()
        {
            return;
        }
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            // Some hermetic test sandboxes prohibit even loopback listeners.
            return;
        };
        let address = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let server_count = Arc::clone(&count);
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                server_count.fetch_add(1, Ordering::SeqCst);
                let mut request = [0_u8; 1024];
                let _ = socket.read(&mut request).await;
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n\x00\x00\x01\x00test").await.unwrap();
            }
        });
        let cache = FaviconCache::new(format!("http://{address}/{{domain}}.ico"));
        assert_eq!(
            cache.response("cdn.example.com").await.status(),
            StatusCode::OK
        );
        assert_eq!(
            cache.response("www.example.com").await.status(),
            StatusCode::OK
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
        server.abort();
    }
}
