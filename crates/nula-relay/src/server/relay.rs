//! Public [`MockRelay`] handle and accept-loop driver.
//!
//! The handle is `Arc`-cheap to clone; every clone shares state.
//! Dropping the last clone fires the relay-wide shutdown channel,
//! which makes the accept loop and every per-connection actor exit
//! gracefully.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use nula_core::nips::nip11::{NIP11_MEDIA_TYPE, RelayInformation, RelayLimitation};
use nula_core::nips::{nip86, nip98};
use nula_core::types::Url;
use nula_core::{RelayUrl, Timestamp};
use nula_storage::NostrDatabase;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use crate::server::connection::{ConnectionContext, handle_connection};
use crate::server::error::Error;
use crate::server::management::ManagementState;
use crate::server::options::MockRelayOptions;
use crate::server::policy::{QueryPolicy, WritePolicy};

/// In-process Nostr relay used as a test fixture.
///
/// Construct via [`crate::server::MockRelayBuilder`]. The handle clones
/// cheaply; the last clone going out of scope shuts the relay down.
#[derive(Debug, Clone)]
pub struct MockRelay {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    url: RelayUrl,
    addr: SocketAddr,
    storage: Arc<dyn NostrDatabase>,
    /// NIP-86 moderation store, present when the management API is
    /// enabled. Shared with the write policy and the HTTP handler.
    management: Option<Arc<ManagementState>>,
    shutdown_tx: broadcast::Sender<()>,
    /// Set once and never replaced. Held inside an `Option` so
    /// `Inner::Drop` can `take()` it and join the accept loop.
    accept_handle: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Best-effort signal: the accept loop holds its own copy of
        // the receiver, so a `send` after the loop is gone is fine.
        self.shutdown_tx.send(()).ok();
        // We cannot await the JoinHandle from a non-async drop, but
        // `tokio::task::JoinHandle::abort()` is sync-callable and
        // ensures the task is reaped.
        if let Ok(mut guard) = self.accept_handle.try_lock()
            && let Some(handle) = guard.take()
        {
            handle.abort();
        }
    }
}

impl MockRelay {
    /// Build a relay against the supplied collaborators and start
    /// listening.
    ///
    /// Most callers should reach for [`crate::server::MockRelayBuilder`]
    /// instead — this is the low-level entry point used by the
    /// builder under the hood.
    ///
    /// # Errors
    ///
    /// [`Error::Bind`] when the listening socket cannot be opened.
    pub async fn start(
        options: MockRelayOptions,
        storage: Arc<dyn NostrDatabase>,
        write_policy: Arc<dyn WritePolicy>,
        query_policy: Arc<dyn QueryPolicy>,
        relay_info: RelayInformation,
        management: Option<Arc<ManagementState>>,
    ) -> Result<Self, Error> {
        let listener = TcpListener::bind(options.bind_addr)
            .await
            .map_err(|source| Error::Bind {
                addr: options.bind_addr,
                source,
            })?;
        let local_addr = listener.local_addr().map_err(|source| Error::Bind {
            addr: options.bind_addr,
            source,
        })?;
        let url_str = format!("ws://{local_addr}");
        let url = RelayUrl::parse(&url_str).map_err(|_| Error::Bind {
            addr: local_addr,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the bound socket address could not be rendered as a relay url",
            ),
        })?;

        let (shutdown_tx, _) = broadcast::channel(1);
        // 4096 in-flight live events. Slow connections drop with
        // `Lagged` rather than back-pressure the publish path.
        let (live_tx, _) = broadcast::channel(4096);

        let ctx = ConnectionContext {
            storage: Arc::clone(&storage),
            write_policy,
            query_policy,
            // Placeholder; `handle_connection` overwrites this with the
            // real accepted-socket address for each connection.
            peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            relay_url: url.clone(),
            nip42_mode: options.nip42_mode,
            min_pow: options.min_pow,
            max_subid_length: options.max_subid_length,
            max_filter_limit: options.max_filter_limit,
            max_active_subscriptions: options.max_active_subscriptions,
            default_filter_limit: options.default_filter_limit,
            rate_limit: options.rate_limit,
            unresponsive: options.unresponsive,
            send_random_events: options.send_random_events,
            broadcast: live_tx,
        };

        let relay_info = Arc::new(relay_info);
        let accept_loop = spawn_accept_loop(
            listener,
            ctx,
            options.max_connections,
            relay_info,
            management.clone(),
            shutdown_tx.clone(),
        );

        Ok(Self {
            inner: Arc::new(Inner {
                url,
                addr: local_addr,
                storage,
                management,
                shutdown_tx,
                accept_handle: tokio::sync::Mutex::new(Some(accept_loop)),
            }),
        })
    }

    /// The relay's url (e.g. `ws://127.0.0.1:54321`).
    #[must_use]
    pub fn url(&self) -> &RelayUrl {
        &self.inner.url
    }

    /// The bound socket address.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.inner.addr
    }

    /// The event store every connection routes EVENTs into.
    #[must_use]
    pub fn database(&self) -> &Arc<dyn NostrDatabase> {
        &self.inner.storage
    }

    /// The shared NIP-86 management state, when the management API is
    /// enabled (`None` otherwise). Lets tests and admins inspect or
    /// mutate the moderation store directly.
    #[must_use]
    pub fn management(&self) -> Option<&Arc<ManagementState>> {
        self.inner.management.as_ref()
    }

    /// Trigger a graceful shutdown.
    ///
    /// Idempotent: subsequent calls are no-ops. Existing connections
    /// see the shutdown signal on their next `select!` poll and
    /// exit; the accept loop refuses new connections.
    pub fn shutdown(&self) {
        self.inner.shutdown_tx.send(()).ok();
    }
}

fn spawn_accept_loop(
    listener: TcpListener,
    ctx: ConnectionContext,
    max_connections: Option<usize>,
    relay_info: Arc<RelayInformation>,
    management: Option<Arc<ManagementState>>,
    shutdown_tx: broadcast::Sender<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut shutdown = shutdown_tx.subscribe();
        let active = Arc::new(AtomicUsize::new(0));
        loop {
            tokio::select! {
                _ = shutdown.recv() => break,
                accept = listener.accept() => {
                    let Ok((stream, peer)) = accept else { continue };
                    // Connection cap: drop the socket before the
                    // WebSocket handshake when already at capacity.
                    if let Some(max) = max_connections
                        && active.load(Ordering::Acquire) >= max
                    {
                        drop(stream);
                        continue;
                    }
                    active.fetch_add(1, Ordering::AcqRel);
                    let ctx = ctx.clone();
                    let conn_shutdown = shutdown_tx.subscribe();
                    let active = Arc::clone(&active);
                    let relay_info = Arc::clone(&relay_info);
                    let management = management.clone();
                    tokio::spawn(async move {
                        // RAII: free the slot when this connection task
                        // ends, however it exits.
                        let _guard = ConnectionGuard(active);
                        serve_connection(
                            stream,
                            peer,
                            ctx,
                            &relay_info,
                            management.as_ref(),
                            conn_shutdown,
                        )
                        .await;
                    });
                }
            }
        }
    })
}

/// How an accepted socket should be handled, decided by peeking the
/// request head without consuming it.
enum RequestKind {
    /// WebSocket upgrade — the Nostr relay protocol.
    WebSocket,
    /// Plain HTTP `GET` — serve the NIP-11 relay information document.
    Nip11,
    /// HTTP `POST` — a NIP-86 management request.
    Management,
}

/// Route an accepted socket: serve NIP-11 for a plain `GET`, dispatch a
/// NIP-86 management `POST`, or upgrade to a WebSocket. The request head
/// is `peek`-ed (not consumed) so a WebSocket handshake survives for
/// `accept_async`; the HTTP branches re-read the stream from the start.
async fn serve_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    ctx: ConnectionContext,
    relay_info: &RelayInformation,
    management: Option<&Arc<ManagementState>>,
    conn_shutdown: broadcast::Receiver<()>,
) {
    match classify_request(&stream).await {
        RequestKind::Nip11 => {
            let body = build_relay_info_json(relay_info, management);
            serve_nip11(&mut stream, &body).await;
        }
        RequestKind::Management => handle_management_post(&mut stream, management).await,
        RequestKind::WebSocket => {
            let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                return;
            };
            handle_connection(ws, peer, ctx, conn_shutdown).await;
        }
    }
}

/// Peek the request head and classify it. A `POST` is a NIP-86
/// management request; a `GET` carrying `Upgrade: websocket` (or an
/// as-yet-incomplete head) is a WebSocket handshake; any other `GET`
/// is a NIP-11 query.
async fn classify_request(stream: &TcpStream) -> RequestKind {
    let mut buf = [0u8; 4096];
    let Ok(n) = stream.peek(&mut buf).await else {
        return RequestKind::WebSocket;
    };
    let Some(bytes) = buf.get(..n) else {
        return RequestKind::WebSocket;
    };
    let head = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    if head.starts_with("post ") {
        return RequestKind::Management;
    }
    if head.contains("upgrade: websocket") {
        return RequestKind::WebSocket;
    }
    if head.starts_with("get ") && head.contains("\r\n\r\n") {
        return RequestKind::Nip11;
    }
    // Incomplete or unknown head: default to the WebSocket path.
    RequestKind::WebSocket
}

/// Render the relay information document, overlaying any live NIP-86
/// metadata (`name` / `description` / `icon`) and advertising NIP-86
/// when the management API is enabled.
fn build_relay_info_json(
    base: &RelayInformation,
    management: Option<&Arc<ManagementState>>,
) -> String {
    let mut info = base.clone();
    if let Some(mgmt) = management {
        mgmt.apply_to(&mut info);
        if !info.supported_nips.contains(&86) {
            info.supported_nips.push(86);
            info.supported_nips.sort_unstable();
        }
    }
    serde_json::to_string(&info).unwrap_or_else(|_| "{}".to_owned())
}

/// Write the NIP-11 document as an `application/nostr+json` HTTP
/// response, then close cleanly. CORS is wide open so browser clients
/// can read the document cross-origin.
async fn serve_nip11(stream: &mut TcpStream, body: &str) {
    // `classify_request` only peeked the request, so the bytes are
    // still in the RX buffer. Closing a socket with unconsumed RX data
    // makes the OS emit RST (which races the client reading our
    // response), so drain the head first and then send a clean FIN.
    drain_request_head(stream).await;

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: {NIP11_MEDIA_TYPE}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET\r\n\
         Access-Control-Allow-Headers: *\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    );
    stream.write_all(response.as_bytes()).await.ok();
    stream.flush().await.ok();
    stream.shutdown().await.ok();
}

/// Read and discard the peeked HTTP request bytes so the socket has no
/// unconsumed RX data at close. The request head is small and fully
/// buffered (the caller already saw the blank-line terminator), so a
/// single short read drains it; the `< buf.len()` break avoids waiting
/// on a client that has moved on to reading the response.
async fn drain_request_head(stream: &mut TcpStream) {
    let mut buf = [0u8; 1024];
    let mut drained = 0usize;
    loop {
        match stream.read(&mut buf).await {
            Ok(n) if n == buf.len() && drained < 8192 => drained += n,
            _ => break,
        }
    }
}

/// Maximum bytes accepted for a management request's header block.
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
/// Maximum bytes accepted for a management request body.
const MAX_HTTP_BODY_BYTES: usize = 64 * 1024;

/// A minimally-parsed HTTP/1.1 request — enough for the NIP-86
/// management endpoint (method, path, lowercased headers, body).
struct HttpRequest {
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpRequest {
    /// Look up a header by its lowercased name.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// Read and parse a full HTTP/1.1 request (request line + headers +
/// `Content-Length` body). Returns `None` on malformed input or when a
/// size bound is exceeded.
async fn read_http_request(stream: &mut TcpStream) -> Option<HttpRequest> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(chunk.get(..n)?);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_HTTP_HEADER_BYTES {
            return None;
        }
    };

    let head = std::str::from_utf8(buf.get(..header_end)?).ok()?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let _method = request_line.next()?;
    let path = request_line.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        })
        .collect();

    let content_length: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    if content_length > MAX_HTTP_BODY_BYTES {
        return None;
    }

    let body_start = header_end + 4;
    let mut body = buf.get(body_start..).unwrap_or_default().to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(chunk.get(..n)?);
    }
    body.truncate(content_length);
    Some(HttpRequest {
        path,
        headers,
        body,
    })
}

/// Handle a NIP-86 management `POST`: authorize via NIP-98, dispatch the
/// request to the [`ManagementState`], and reply with the JSON response.
async fn handle_management_post(stream: &mut TcpStream, management: Option<&Arc<ManagementState>>) {
    let Some(request) = read_http_request(stream).await else {
        write_management_error(stream, 400, "malformed request").await;
        return;
    };
    let Some(mgmt) = management else {
        write_management_error(stream, 404, "management api is not enabled").await;
        return;
    };
    let content_type = request.header("content-type").unwrap_or_default();
    if !content_type.starts_with(nip86::CONTENT_TYPE) {
        write_management_error(stream, 415, "expected application/nostr+json+rpc").await;
        return;
    }
    if let Err(reason) = authorize_management(&request, mgmt) {
        write_management_error(stream, 401, &reason).await;
        return;
    }
    let response = match serde_json::from_slice::<nip86::Request>(&request.body) {
        Ok(rpc) => mgmt.handle_request(&rpc),
        Err(e) => nip86::Response::err(format!("invalid request body: {e}")),
    };
    let body = serde_json::to_string(&response)
        .unwrap_or_else(|_| r#"{"error":"response serialization failed"}"#.to_owned());
    write_http_response(stream, 200, nip86::CONTENT_TYPE, body.as_bytes()).await;
}

/// Verify NIP-98 authorization for a management request and confirm the
/// signer is a configured admin.
fn authorize_management(request: &HttpRequest, mgmt: &ManagementState) -> Result<(), String> {
    let header = request
        .header("authorization")
        .ok_or("missing Authorization header")?;
    let event = nip98::parse_authorization_header(header).map_err(|e| e.to_string())?;
    event
        .verify()
        .map_err(|e| format!("invalid auth event: {e}"))?;
    let bundle = nip98::HttpAuthRequest::from_event(&event).map_err(|e| e.to_string())?;
    let host = request.header("host").ok_or("missing Host header")?;
    let url = Url::parse(format!("http://{host}{}", request.path)).map_err(|e| e.to_string())?;
    let now = Timestamp::now().map_err(|e| e.to_string())?;
    bundle
        .validate(
            event.created_at,
            now,
            nip98::DEFAULT_TIMESTAMP_SKEW_SECS,
            &url,
            &nip98::HttpMethod::Post,
            Some(&request.body),
        )
        .map_err(|e| e.to_string())?;
    if !mgmt.is_admin(&event.pubkey) {
        return Err("pubkey is not authorized to manage this relay".to_owned());
    }
    Ok(())
}

/// Write a simple HTTP response and close cleanly.
async fn write_http_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
    let reason = match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        415 => "Unsupported Media Type",
        _ => "OK",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        len = body.len(),
    );
    stream.write_all(header.as_bytes()).await.ok();
    stream.write_all(body).await.ok();
    stream.flush().await.ok();
    stream.shutdown().await.ok();
}

/// Write a NIP-86 error [`Response`] with the given HTTP status.
async fn write_management_error(stream: &mut TcpStream, status: u16, message: &str) {
    let body = serde_json::to_string(&nip86::Response::err(message))
        .unwrap_or_else(|_| r#"{"error":"unauthorized"}"#.to_owned());
    write_http_response(stream, status, nip86::CONTENT_TYPE, body.as_bytes()).await;
}

/// Derive a default [`RelayInformation`] from the configured options.
/// Advertises only the limits the relay actually enforces plus the set
/// of NIPs this server speaks. Overridden by
/// [`crate::server::MockRelayBuilder::relay_info`].
pub(crate) fn derive_relay_info(
    options: &MockRelayOptions,
    restricted_writes: bool,
) -> RelayInformation {
    let mut supported_nips = vec![1, 9, 11, 40, 45, 77];
    if options.nip42_mode.is_enabled() {
        supported_nips.push(42);
    }
    if options.min_pow.is_some() {
        supported_nips.push(13);
    }
    supported_nips.sort_unstable();

    let limitation = RelayLimitation {
        max_subscriptions: options
            .max_active_subscriptions
            .and_then(|n| u32::try_from(n).ok()),
        max_limit: options.max_filter_limit.and_then(|n| u32::try_from(n).ok()),
        max_subid_length: options.max_subid_length.and_then(|n| u32::try_from(n).ok()),
        default_limit: options
            .default_filter_limit
            .and_then(|n| u32::try_from(n).ok()),
        min_pow_difficulty: options.min_pow,
        auth_required: options.nip42_mode.is_enabled().then_some(true),
        restricted_writes: restricted_writes.then_some(true),
        ..RelayLimitation::default()
    };

    RelayInformation {
        name: Some("nula MockRelay".to_owned()),
        description: Some(
            "In-process programmable Nostr relay (nula-relay server feature).".to_owned(),
        ),
        software: Url::parse("https://github.com/qntx/nula").ok(),
        version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        supported_nips,
        limitation: Some(limitation),
        ..RelayInformation::default()
    }
}

/// Decrements the active-connection counter on drop, so the
/// `max_connections` cap recovers a slot whenever a connection closes,
/// errors, or is aborted.
struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
