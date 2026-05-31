//! NIP-07 `window.nostr` browser-extension signer.
//!
//! [`BrowserSigner`] implements [`nula_core::NostrSigner`] by delegating to a
//! NIP-07 browser extension (Alby, nos2x, …) exposed on the page as the
//! global `window.nostr` object:
//!
//! | `NostrSigner` method | `window.nostr` call            |
//! | -------------------- | ------------------------------ |
//! | `get_public_key`     | `getPublicKey()`               |
//! | `sign_event`         | `signEvent(event)`             |
//! | `nip04_encrypt`      | `nip04.encrypt(pubkey, text)`  |
//! | `nip04_decrypt`      | `nip04.decrypt(pubkey, text)`  |
//! | `nip44_encrypt`      | `nip44.encrypt(pubkey, text)`  |
//! | `nip44_decrypt`      | `nip44.decrypt(pubkey, text)`  |
//!
//! # No `unsafe`
//!
//! Unlike a `#[wasm_bindgen] extern "C"` binding (which generates an
//! `unsafe` FFI shim), this crate reaches `window.nostr` dynamically through
//! the safe [`js_sys::Reflect`] / [`js_sys::Function`] / [`js_sys::JSON`]
//! surface. The whole crate therefore keeps `#![forbid(unsafe_code)]`, in
//! line with the rest of the nula workspace.
//!
//! # Statelessness
//!
//! [`BrowserSigner`] holds no JavaScript handles — every call re-reads
//! `window.nostr` — so it is a zero-sized `Send + Sync` type and satisfies
//! `NostrSigner: Send + Sync` without any `unsafe impl`. The futures it
//! returns *do* hold `!Send` `JsValue`s, which is why
//! [`nula_core::signer::SignerFuture`] drops its `Send` bound on `wasm32`.
//!
//! # Hardening
//!
//! [`BrowserSigner::sign_event`] re-verifies the event returned by the
//! extension with [`Event::verify`] (id + Schnorr signature) and rejects any
//! event whose `pubkey` differs from the unsigned author, so a buggy or
//! hostile extension cannot smuggle back a malformed or mis-attributed event.
//!
//! # Usage
//!
//! ```ignore
//! use nula_core::NostrSigner;
//! use nula_signer_browser::BrowserSigner;
//!
//! let signer = BrowserSigner::new();
//! let pubkey = signer.get_public_key().await?;
//! ```
//!
//! This crate compiles only for `wasm32`; on every other target it is empty.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/nula-signer-browser")]
#![cfg(target_arch = "wasm32")]
#![forbid(unsafe_code)]
#![allow(
    clippy::future_not_send,
    reason = "NIP-07 calls hold JsValue/Promise across await points; these are \
              !Send by design and `SignerFuture` drops its Send bound on wasm32"
)]
#![allow(
    clippy::multiple_crate_versions,
    reason = "two getrandom majors coexist: 0.4 (direct, via nula-core) and 0.3 \
              (transitive, via secp256k1's `rand`); both get the wasm_js backend"
)]

// `getrandom` is pulled in only to enable its `wasm_js` backend feature for
// the two majors in the dependency tree; neither is referenced directly.
use getrandom as _;
use getrandom_v04 as _;
use js_sys::{Array, Function, JSON, Promise, Reflect};
use nula_core::event::{Event, UnsignedEvent};
use nula_core::key::PublicKey;
use nula_core::signer::{NostrSigner, SignerError, SignerFuture, boxed_signer_future};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

/// A NIP-07 `window.nostr` signer.
///
/// Zero-sized and stateless: construct with [`BrowserSigner::new`] and store
/// it behind `Arc<dyn NostrSigner>` like any other signer. See the
/// [crate-level docs](crate) for the method mapping and hardening notes.
#[derive(Debug, Clone, Copy, Default)]
pub struct BrowserSigner;

impl BrowserSigner {
    /// Construct a signer bound to the page's `window.nostr`.
    ///
    /// No work happens here — `window.nostr` is resolved lazily on each
    /// call, so constructing a signer before an extension has injected
    /// itself is fine.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl NostrSigner for BrowserSigner {
    fn get_public_key(&self) -> SignerFuture<'_, Result<PublicKey, SignerError>> {
        boxed_signer_future(async {
            let nostr = nostr_handle()?;
            let value = await_method(&nostr, "getPublicKey", &[]).await?;
            let hex = value
                .as_string()
                .ok_or_else(|| SignerError::backend(BrowserError::NonString("getPublicKey")))?;
            PublicKey::parse(&hex).map_err(SignerError::backend)
        })
    }

    fn sign_event(&self, unsigned: UnsignedEvent) -> SignerFuture<'_, Result<Event, SignerError>> {
        boxed_signer_future(async move {
            let nostr = nostr_handle()?;
            let request_json = serde_json::to_string(&unsigned).map_err(SignerError::backend)?;
            let request = JSON::parse(&request_json)
                .map_err(|err| SignerError::backend(BrowserError::Js(stringify_js(&err))))?;
            let signed = await_method(&nostr, "signEvent", &[request]).await?;
            let signed_json = JSON::stringify(&signed)
                .ok()
                .and_then(|json| json.as_string())
                .ok_or_else(|| SignerError::backend(BrowserError::NonString("signEvent")))?;
            let event: Event = serde_json::from_str(&signed_json).map_err(SignerError::backend)?;
            // Harden against a buggy/hostile extension: the returned event
            // must be self-consistent (id + signature) and attributed to the
            // author we asked to sign for.
            event.verify().map_err(SignerError::backend)?;
            if event.pubkey != unsigned.pubkey {
                return Err(SignerError::rejected(
                    "NIP-07 signer returned an event signed by a different public key",
                ));
            }
            Ok(event)
        })
    }

    fn nip04_encrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        plaintext: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        boxed_signer_future(cipher_call(
            "nip04",
            "encrypt",
            "nip04_encrypt",
            peer,
            plaintext,
        ))
    }

    fn nip04_decrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        ciphertext: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        boxed_signer_future(cipher_call(
            "nip04",
            "decrypt",
            "nip04_decrypt",
            peer,
            ciphertext,
        ))
    }

    fn nip44_encrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        plaintext: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        boxed_signer_future(cipher_call(
            "nip44",
            "encrypt",
            "nip44_encrypt",
            peer,
            plaintext,
        ))
    }

    fn nip44_decrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        payload: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        boxed_signer_future(cipher_call(
            "nip44",
            "decrypt",
            "nip44_decrypt",
            peer,
            payload,
        ))
    }
}

/// Resolve the global `window.nostr` object, erroring when no NIP-07
/// extension is present.
fn nostr_handle() -> Result<JsValue, SignerError> {
    let global = js_sys::global();
    let nostr = Reflect::get(&global, &JsValue::from_str("nostr"))
        .map_err(|err| SignerError::backend(BrowserError::Js(stringify_js(&err))))?;
    if nostr.is_undefined() || nostr.is_null() {
        return Err(SignerError::backend(BrowserError::NoExtension));
    }
    Ok(nostr)
}

/// Resolve a `window.nostr.<namespace>` capability object (`nip04` /
/// `nip44`), mapping a missing namespace to [`SignerError::Unsupported`].
fn cipher_namespace(nostr: &JsValue, namespace: &'static str) -> Result<JsValue, SignerError> {
    let value = Reflect::get(nostr, &JsValue::from_str(namespace))
        .map_err(|err| SignerError::backend(BrowserError::Js(stringify_js(&err))))?;
    if value.is_undefined() || value.is_null() {
        return Err(SignerError::Unsupported(namespace));
    }
    Ok(value)
}

/// Shared body for the four `nipNN_{encrypt,decrypt}` methods.
async fn cipher_call(
    namespace: &'static str,
    js_op: &'static str,
    label: &'static str,
    peer: &PublicKey,
    text: &str,
) -> Result<String, SignerError> {
    let nostr = nostr_handle()?;
    let capability = cipher_namespace(&nostr, namespace)?;
    let value = await_method(
        &capability,
        js_op,
        &[JsValue::from_str(&peer.to_hex()), JsValue::from_str(text)],
    )
    .await?;
    value
        .as_string()
        .ok_or_else(|| SignerError::backend(BrowserError::NonString(label)))
}

/// Look up `target[method]`, call it with `args`, and await the returned
/// `Promise`.
///
/// A rejected promise becomes [`SignerError::Rejected`] (the conventional
/// signal for a user denying a NIP-07 prompt); structural failures (missing
/// method, non-promise return) become [`SignerError::Backend`].
async fn await_method(
    target: &JsValue,
    method: &'static str,
    args: &[JsValue],
) -> Result<JsValue, SignerError> {
    let function: Function = Reflect::get(target, &JsValue::from_str(method))
        .ok()
        .and_then(|value| value.dyn_into::<Function>().ok())
        .ok_or_else(|| SignerError::backend(BrowserError::NotCallable(method)))?;

    let array = Array::new();
    for arg in args {
        array.push(arg);
    }

    let promise: Promise = function
        .apply(target, &array)
        .map_err(|err| SignerError::backend(BrowserError::Js(stringify_js(&err))))?
        .dyn_into::<Promise>()
        .map_err(|_| SignerError::backend(BrowserError::NotPromise(method)))?;

    JsFuture::from(promise)
        .await
        .map_err(|err| SignerError::rejected(stringify_js(&err)))
}

/// Best-effort conversion of an arbitrary `JsValue` to a display string for
/// error messages: native string, else JSON, else the `Debug` form.
fn stringify_js(value: &JsValue) -> String {
    if let Some(text) = value.as_string() {
        return text;
    }
    JSON::stringify(value)
        .ok()
        .and_then(|json| json.as_string())
        .unwrap_or_else(|| format!("{value:?}"))
}

/// Structural failures of the `window.nostr` bridge.
///
/// User-facing rejections (denied prompts) are reported as
/// [`SignerError::Rejected`] instead; this enum covers the cases where the
/// bridge itself is missing or malformed.
#[derive(Debug, thiserror::Error)]
enum BrowserError {
    #[error(
        "window.nostr is unavailable - is a NIP-07 extension (Alby, nos2x, ...) installed and enabled?"
    )]
    NoExtension,
    #[error("window.nostr.{0} is not callable")]
    NotCallable(&'static str),
    #[error("NIP-07 method `{0}` did not return a Promise")]
    NotPromise(&'static str),
    #[error("NIP-07 method `{0}` returned a non-string value")]
    NonString(&'static str),
    #[error("NIP-07 bridge error: {0}")]
    Js(String),
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    // Compile-time proof of the central design claim: a stateless browser
    // signer satisfies `NostrSigner` (which requires `Send + Sync + Debug`)
    // with no `unsafe impl`.
    const _: () = {
        const fn assert_is_signer<T: NostrSigner>() {}
        assert_is_signer::<BrowserSigner>();
    };

    #[wasm_bindgen_test]
    fn constructs_without_touching_window() {
        // `new` must not read `window.nostr`, so this succeeds even with no
        // extension present in the test runner.
        let _signer = BrowserSigner::new();
    }
}
