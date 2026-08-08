const DEFAULT_ANALYZER_UPSTREAM = "http://127.0.0.1:8799";
const PROXY_PREFIX = "/analyzer-api";

const requestHeadersToStrip = [
  "connection",
  "content-length",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

const responseHeadersToStrip = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

function upstreamUrl(request: Request) {
  const incoming = new URL(request.url);
  const upstream = (
    process.env.ANALYZER_UPSTREAM_URL ?? DEFAULT_ANALYZER_UPSTREAM
  ).replace(/\/$/, "");
  const path = incoming.pathname.startsWith(PROXY_PREFIX)
    ? incoming.pathname.slice(PROXY_PREFIX.length)
    : incoming.pathname;
  return new URL(`${upstream}${path || "/"}${incoming.search}`);
}

async function proxyAnalyzer(request: Request) {
  const headers = new Headers(request.headers);
  for (const name of requestHeadersToStrip) headers.delete(name);

  try {
    const response = await fetch(upstreamUrl(request), {
      method: request.method,
      headers,
      redirect: "manual",
    });
    const responseHeaders = new Headers(response.headers);
    for (const name of responseHeadersToStrip) responseHeaders.delete(name);
    return new Response(request.method === "HEAD" ? null : response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
    });
  } catch {
    return Response.json(
      { error: "Local analyzer is unavailable" },
      { status: 502 },
    );
  }
}

export const GET = proxyAnalyzer;
export const HEAD = proxyAnalyzer;
