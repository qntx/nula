//! `DefaultTransport` — `tokio-tungstenite`-backed implementation of
//! [`crate::transport::WebSocketTransport`].

use futures::stream::StreamExt;
use nula_core::RelayUrl;
use nula_core::boxed::BoxFuture;
use tokio_tungstenite::connect_async_with_config;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::transport::default::convert::{from_tungstenite, from_tungstenite_error};
use crate::transport::default::sink::TransportSink;
use crate::transport::error::Error;
use crate::transport::mode::ConnectionMode;
use crate::transport::ws::{WebSocketSink, WebSocketStream, WebSocketTransport};

/// Builder for [`DefaultTransport`].
///
/// Every option mirrors a [`tokio_tungstenite::tungstenite::protocol::WebSocketConfig`]
/// knob and is forwarded verbatim. The defaults are the tungstenite
/// defaults; override them only when the relay you are talking to
/// demands a different setting.
#[derive(Debug, Default, Clone, Copy)]
#[must_use]
pub struct DefaultTransportBuilder {
    max_frame_size: Option<usize>,
    max_message_size: Option<usize>,
    accept_unmasked_frames: bool,
}

impl DefaultTransportBuilder {
    /// Construct a builder with tungstenite's stock defaults.
    pub const fn new() -> Self {
        Self {
            max_frame_size: None,
            max_message_size: None,
            accept_unmasked_frames: false,
        }
    }

    /// Maximum size of a single WebSocket frame in bytes. `None` keeps
    /// the tungstenite default (~16 MiB at the time of writing).
    pub const fn max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = Some(size);
        self
    }

    /// Maximum total size of a logical message (sum across frames) in
    /// bytes. `None` keeps the tungstenite default (~64 MiB at the
    /// time of writing).
    pub const fn max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = Some(size);
        self
    }

    /// Whether the server should accept frames the client sent without
    /// masking. RFC 6455 requires masking from clients; some embedded
    /// relays violate the spec. Off by default.
    pub const fn accept_unmasked_frames(mut self, accept: bool) -> Self {
        self.accept_unmasked_frames = accept;
        self
    }

    /// Finalise the builder.
    #[must_use]
    pub const fn build(self) -> DefaultTransport {
        DefaultTransport { config: self }
    }
}

/// Default [`WebSocketTransport`] backed by `tokio-tungstenite` with
/// rustls + webpki-roots for TLS.
///
/// # Example
///
/// ```rust,no_run
/// use nula_core::RelayUrl;
/// use nula_relay::transport::default::DefaultTransport;
/// use nula_relay::transport::{ConnectionMode, IntoWebSocketTransport, WebSocketTransport};
///
/// # async fn doc() -> Result<(), Box<dyn std::error::Error>> {
/// let transport = DefaultTransport::new();
/// let url = RelayUrl::parse("wss://relay.damus.io")?;
/// let (_sink, _stream) = transport.connect(&url, &ConnectionMode::Direct).await?;
/// # Ok(()) }
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultTransport {
    config: DefaultTransportBuilder,
}

impl DefaultTransport {
    /// Construct a transport with tungstenite's stock defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            config: DefaultTransportBuilder::new(),
        }
    }

    /// Begin configuring a transport. Calls return `Self` so options
    /// chain.
    pub const fn builder() -> DefaultTransportBuilder {
        DefaultTransportBuilder::new()
    }
}

impl WebSocketTransport for DefaultTransport {
    fn supports_ping(&self) -> bool {
        true
    }

    fn connect<'a>(
        &'a self,
        url: &'a RelayUrl,
        mode: &'a ConnectionMode,
    ) -> BoxFuture<'a, Result<(WebSocketSink, WebSocketStream), Error>> {
        #[cfg(feature = "tracing")]
        let span = tracing::info_span!(
            "nula_relay.transport.default.connect",
            nostr.relay.url = %url.as_str(),
        );
        let fut = async move {
            // `ConnectionMode` is `#[non_exhaustive]`; today the only
            // variant is `Direct`. The match is exhaustive at the
            // language level but we still guard against future
            // additions that this transport does not support.
            match *mode {
                ConnectionMode::Direct => {}
            }

            let config = self
                .config
                .max_frame_size
                .map_or_else(WebSocketConfig::default, |size| {
                    WebSocketConfig::default().max_frame_size(Some(size))
                });
            let config = self
                .config
                .max_message_size
                .map_or(config, |size| config.max_message_size(Some(size)));
            let config = config.accept_unmasked_frames(self.config.accept_unmasked_frames);

            let (ws, _resp) = connect_async_with_config(url.as_str(), Some(config), false)
                .await
                .map_err(from_tungstenite_error)?;

            let (tx, rx) = ws.split();

            let sink: WebSocketSink = Box::pin(TransportSink::new(tx));
            let stream: WebSocketStream = Box::pin(rx.map(|frame| {
                frame
                    .map_err(from_tungstenite_error)
                    .and_then(from_tungstenite)
            }));

            Ok((sink, stream))
        };

        #[cfg(feature = "tracing")]
        let fut = tracing::Instrument::instrument(fut, span);

        Box::pin(fut)
    }
}
