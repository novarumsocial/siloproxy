use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue, CONNECTION, HOST, TE, TRAILER, TRANSFER_ENCODING, UPGRADE};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpListener;

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;
type ProxyClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Incoming>;

// hop-by-hop only. Host is rewritten to the upstream host: SigV4 signs the
// Host header, so it must match what the service validates against.
const HOP_BY_HOP: [HeaderName; 5] = [CONNECTION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE];

fn bad_gateway() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Full::new(Bytes::new()).map_err(|never| match never {}).boxed())
        .unwrap()
}

fn keep_end_to_end(headers: &mut hyper::HeaderMap) {
    let keep: Vec<(HeaderName, HeaderValue)> = headers
        .iter()
        .filter(|(name, _)| !HOP_BY_HOP.contains(name))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    headers.clear();
    headers.extend(keep);
}

fn unauthorized() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Full::new(Bytes::new()).map_err(|never| match never {}).boxed())
        .unwrap()
}

async fn proxy(
    req: Request<Incoming>,
    client: ProxyClient,
    upstream: Arc<str>,
    upstream_host: Arc<str>,
    bucket: Option<Arc<str>>,
) -> Result<Response<BoxBody>, hyper_util::client::legacy::Error> {
    let path = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
    if let Some(bucket) = &bucket {
        if path != format!("/{bucket}") && !path.starts_with(&format!("/{bucket}/")) {
            eprintln!("blocked: path outside bucket {bucket}: {path}");
            return Ok(unauthorized());
        }
    }
    let target: Uri = match format!("{upstream}{path}").parse() {
        Ok(u) => u,
        Err(_) => return Ok(bad_gateway()),
    };

    let (mut parts, body) = req.into_parts();
    parts.uri = target.clone();
    keep_end_to_end(&mut parts.headers);
    // SigV4 signs the Host header. Rotate it to the upstream host so the
    // signed value matches the host the service validates against.
    parts
        .headers
        .insert(HOST, HeaderValue::from_str(&upstream_host).unwrap());
    let req = Request::from_parts(parts, body);

    let resp = match client.request(req).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("upstream error: {e}");
            return Ok(bad_gateway());
        }
    };
    let (mut parts, body) = resp.into_parts();
    keep_end_to_end(&mut parts.headers);
    Ok(Response::from_parts(parts, body.boxed()))
}

#[tokio::main]
async fn main() {
    let bind = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let upstream: Arc<str> = std::env::var("UPSTREAM")
        .unwrap_or_else(|_| "https://onsilo.dev".to_string())
        .trim_end_matches('/')
        .to_string()
        .into();
    let upstream_host: Arc<str> = upstream
        .rsplit("://")
        .next()
        .unwrap_or(&upstream)
        .into();
    let bucket: Option<Arc<str>> = std::env::var("BUCKET").ok().map(Arc::from);

    let mut http = HttpConnector::new();
    http.enforce_http(false); // scheme is the HttpsConnector's job, not the inner connector's
    http.set_connect_timeout(Some(Duration::from_secs(5)));
    let tls = HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("failed to load native root certs")
        .https_only()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);
    let client: ProxyClient = Client::builder(TokioExecutor::new()).build(tls);

    let listener = TcpListener::bind(&bind).await.expect("failed to bind");
    eprintln!("siloproxy listening on {bind} -> {upstream}");

    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let _ = stream.set_nodelay(true);
        let client = client.clone();
        let upstream = upstream.clone();
        let upstream_host = upstream_host.clone();
        let bucket = bucket.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                proxy(req, client.clone(), upstream.clone(), upstream_host.clone(), bucket.clone())
            });
            let mut builder = Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(30));
            if let Err(e) = builder.serve_connection(TokioIo::new(stream), svc).await
            {
                eprintln!("conn error: {e}");
            }
        });
    }
}