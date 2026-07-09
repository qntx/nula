//! [NIP-90] Data Vending Machine — typed event bundles for the
//! customer / service-provider interaction.
//!
//! NIP-90 reserves the kind range `5000..=7000` for the data vending
//! machine (DVM) marketplace:
//!
//! | Range       | Role                                              |
//! |-------------|---------------------------------------------------|
//! | `5000-5999` | [`JobRequest`] — customer asks for compute        |
//! | `6000-6999` | [`JobResult`] — service provider returns output   |
//! | `7000`      | [`JobFeedback`] — service provider status update  |
//!
//! Result kind is always `1000` higher than the request kind: a
//! `kind:5001` translation request gets a `kind:6001` translation
//! result. The mapping is enforced by [`result_kind_for`] /
//! [`request_kind_for`] / [`is_job_request_kind`] /
//! [`is_job_result_kind`].
//!
//! # Why a typed module
//!
//! Upstream `rust-nostr` ships nothing for NIP-90. We model:
//!
//! 1. [`JobInput`] — typed enum for the four `i`-tag input kinds
//!    (`url` / `event` / `job` / `text`) with optional relay hint
//!    and downstream marker.
//! 2. [`JobParam`] — key/value parameter rows.
//! 3. [`JobRequest`] / [`JobResult`] / [`JobFeedback`] — the three
//!    typed bundles, each with a `to_event` / `from_event` round
//!    trip.
//! 4. [`Amount`] — millisat payment hint with an optional bolt11
//!    invoice.
//! 5. [`FeedbackStatus`] — typed kind-7000 status enum with the
//!    five spec values plus a `Custom(String)` escape hatch.
//!
//! The module is intentionally agnostic about encryption: when
//! callers want to keep `i` / `param` rows secret per spec
//! §"Encrypted Params", they encrypt the payload with NIP-04 (or
//! NIP-44) themselves, stash the ciphertext in `.content`, and tag
//! the event with `Tag::custom("encrypted")`.
//! The typed bundles never auto-encrypt or decrypt so they stay
//! usable from `--no-default-features` builds.
//!
//! [NIP-90]: https://github.com/nostr-protocol/nips/blob/master/90.md

#![expect(
    clippy::excessive_nesting,
    reason = "the per-tag match-on-name dispatch pattern in `from_event` keeps the wire-format-to-field mapping at the surface; flattening obscures it"
)]

use thiserror::Error;

use crate::event::{
    Alphabet, Event, EventBuilder, EventBuilderError, EventId, EventIdError, Kind, SingleLetterTag,
    Tag, TagError, TagKind,
};
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{RelayUrl, RelayUrlError};

/// `kind: 7000` — job feedback event.
pub const KIND_JOB_FEEDBACK: Kind = Kind::new(7_000);
/// Lower bound of the job-request kind range.
pub const JOB_REQUEST_RANGE_START: u16 = 5_000;
/// Upper bound (inclusive) of the job-request kind range.
pub const JOB_REQUEST_RANGE_END: u16 = 5_999;
/// Lower bound of the job-result kind range.
pub const JOB_RESULT_RANGE_START: u16 = 6_000;
/// Upper bound (inclusive) of the job-result kind range.
pub const JOB_RESULT_RANGE_END: u16 = 6_999;
/// Offset spec mandates between a request kind and its result kind.
pub const REQUEST_TO_RESULT_OFFSET: u16 = 1_000;

mod tag_names {
    pub(super) const I: &str = "i";
    pub(super) const OUTPUT: &str = "output";
    pub(super) const PARAM: &str = "param";
    pub(super) const BID: &str = "bid";
    pub(super) const RELAYS: &str = "relays";
    pub(super) const T: &str = "t";
    pub(super) const REQUEST: &str = "request";
    pub(super) const AMOUNT: &str = "amount";
    pub(super) const STATUS: &str = "status";
    pub(super) const ENCRYPTED: &str = "encrypted";
}

mod input_kinds {
    pub(super) const URL: &str = "url";
    pub(super) const EVENT: &str = "event";
    pub(super) const JOB: &str = "job";
    pub(super) const TEXT: &str = "text";
}

mod feedback_strings {
    pub(super) const PAYMENT_REQUIRED: &str = "payment-required";
    pub(super) const PROCESSING: &str = "processing";
    pub(super) const ERROR: &str = "error";
    pub(super) const SUCCESS: &str = "success";
    pub(super) const PARTIAL: &str = "partial";
}

/// True when `kind` is in the reserved DVM job-request range
/// `5000..=5999`.
#[must_use]
pub const fn is_job_request_kind(kind: Kind) -> bool {
    matches!(
        kind.as_u16(),
        JOB_REQUEST_RANGE_START..=JOB_REQUEST_RANGE_END
    )
}

/// True when `kind` is in the reserved DVM job-result range
/// `6000..=6999`.
#[must_use]
pub const fn is_job_result_kind(kind: Kind) -> bool {
    matches!(kind.as_u16(), JOB_RESULT_RANGE_START..=JOB_RESULT_RANGE_END)
}

/// Map a job-request kind to its corresponding result kind
/// (`request + 1000`). Returns `None` when `kind` is outside the
/// `5000..=5999` range.
#[must_use]
pub const fn result_kind_for(request_kind: Kind) -> Option<Kind> {
    if is_job_request_kind(request_kind) {
        Some(Kind::new(request_kind.as_u16() + REQUEST_TO_RESULT_OFFSET))
    } else {
        None
    }
}

/// Map a job-result kind back to its corresponding request kind
/// (`result - 1000`). Returns `None` when `kind` is outside the
/// `6000..=6999` range.
#[must_use]
pub const fn request_kind_for(result_kind: Kind) -> Option<Kind> {
    if is_job_result_kind(result_kind) {
        Some(Kind::new(result_kind.as_u16() - REQUEST_TO_RESULT_OFFSET))
    } else {
        None
    }
}

/// Errors raised by the NIP-90 typed bundles.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Nip90Error {
    /// A request kind was outside the `5000..=5999` range.
    #[error("DVM job-request kind {0} is outside `5000..=5999`")]
    InvalidRequestKind(Kind),
    /// A result kind was outside the `6000..=6999` range.
    #[error("DVM job-result kind {0} is outside `6000..=6999`")]
    InvalidResultKind(Kind),
    /// A feedback event was not `kind:7000`.
    #[error("expected kind 7000, got {0}")]
    InvalidFeedbackKind(Kind),
    /// Result kind did not match `request_kind + 1000`.
    #[error("result kind {got} does not match request kind {request} + 1000 = {expected}")]
    KindMismatch {
        /// Request kind sourced from the surrounding context.
        request: Kind,
        /// Expected result kind (`request + 1000`).
        expected: Kind,
        /// Actual result kind on the event.
        got: Kind,
    },
    /// An `i` tag's marker was not one of `url` / `event` / `job` /
    /// `text`.
    #[error("DVM `i` tag has unknown marker `{0}` (expected url/event/job/text)")]
    UnknownInputKind(String),
    /// A bid / amount value was not a valid `u64`.
    #[error("DVM millisat value `{0}` is not a valid u64")]
    MalformedMillisats(String),
    /// A `param` tag had no value column.
    #[error("DVM `param` tag missing value column")]
    MalformedParam,
    /// A target / customer / provider pubkey was malformed.
    #[error(transparent)]
    PublicKey(#[from] PublicKeyError),
    /// A relay URL was malformed.
    #[error(transparent)]
    RelayUrl(#[from] RelayUrlError),
    /// An event id was malformed.
    #[error(transparent)]
    EventId(#[from] EventIdError),
    /// A typed [`Tag`] could not be constructed.
    #[error(transparent)]
    Tag(#[from] TagError),
    /// [`EventBuilder`] signing failed.
    #[error(transparent)]
    Builder(#[from] EventBuilderError),
}

/// Input column of an `i` tag.
///
/// Each row's spec layout is `[head, value, kind, relay?, marker?]`
/// where `head == "i"`. The four kinds match the spec's
/// `url`/`event`/`job`/`text` markers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JobInput {
    /// `url` — fetch the data at this URL.
    Url(String),
    /// `event` — process the referenced Nostr event.
    Event {
        /// Event id of the referenced event.
        event_id: EventId,
        /// Optional relay hint where the event was published.
        relay: Option<RelayUrl>,
    },
    /// `job` — chain on top of a previous job's output.
    Job {
        /// Event id of the previous job.
        event_id: EventId,
        /// Optional relay hint.
        relay: Option<RelayUrl>,
    },
    /// `text` — inline text payload.
    Text(String),
}

impl JobInput {
    /// Encode the typed input as the NIP-90 `i` tag row (excluding
    /// the `marker`, which is carried by the surrounding
    /// [`JobInputRef`]).
    fn render(&self, marker: Option<&str>) -> Vec<String> {
        let mut row: Vec<String> = match self {
            Self::Url(url) => vec![url.clone(), input_kinds::URL.to_owned(), String::new()],
            Self::Text(text) => vec![text.clone(), input_kinds::TEXT.to_owned(), String::new()],
            Self::Event { event_id, relay } => vec![
                event_id.to_hex(),
                input_kinds::EVENT.to_owned(),
                relay
                    .as_ref()
                    .map(|r| r.as_str().to_owned())
                    .unwrap_or_default(),
            ],
            Self::Job { event_id, relay } => vec![
                event_id.to_hex(),
                input_kinds::JOB.to_owned(),
                relay
                    .as_ref()
                    .map(|r| r.as_str().to_owned())
                    .unwrap_or_default(),
            ],
        };
        if let Some(marker) = marker {
            row.push(marker.to_owned());
        }
        row
    }

    /// Decode an `i` tag's argument list (without the head) into a
    /// typed input plus its optional marker.
    fn parse(args: &[String]) -> Result<(Self, Option<String>), Nip90Error> {
        let value = args.first().cloned().unwrap_or_default();
        let kind = args
            .get(1)
            .cloned()
            .unwrap_or_else(|| input_kinds::URL.to_owned());
        let relay = args.get(2).and_then(|s| {
            if s.is_empty() {
                None
            } else {
                Some(RelayUrl::parse(s))
            }
        });
        let marker = args.get(3).cloned();
        let input = match kind.as_str() {
            input_kinds::URL => Self::Url(value),
            input_kinds::TEXT => Self::Text(value),
            input_kinds::EVENT => Self::Event {
                event_id: EventId::parse(&value)?,
                relay: relay.transpose()?,
            },
            input_kinds::JOB => Self::Job {
                event_id: EventId::parse(&value)?,
                relay: relay.transpose()?,
            },
            other => return Err(Nip90Error::UnknownInputKind(other.to_owned())),
        };
        Ok((input, marker))
    }
}

/// One `i` tag row plus its optional `marker` column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobInputRef {
    /// The typed input.
    pub input: JobInput,
    /// Optional marker column (free-form per spec).
    pub marker: Option<String>,
}

impl JobInputRef {
    /// Construct an input row with no marker.
    #[must_use]
    pub const fn new(input: JobInput) -> Self {
        Self {
            input,
            marker: None,
        }
    }

    /// Set the marker column.
    #[must_use]
    pub fn marker(mut self, marker: impl Into<String>) -> Self {
        self.marker = Some(marker.into());
        self
    }
}

/// Key/value `param` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobParam {
    /// Parameter name.
    pub key: String,
    /// Parameter value.
    pub value: String,
}

impl JobParam {
    /// Construct a parameter row.
    #[must_use]
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Optional payment hint carried by a [`JobResult`] or
/// [`JobFeedback`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Amount {
    /// Requested payment in millisats.
    pub msats: u64,
    /// Optional pre-built bolt11 invoice the customer can pay.
    pub bolt11: Option<String>,
}

impl Amount {
    /// Construct an amount with no invoice.
    #[must_use]
    pub const fn new(msats: u64) -> Self {
        Self {
            msats,
            bolt11: None,
        }
    }

    /// Attach a bolt11 invoice.
    #[must_use]
    pub fn invoice(mut self, bolt11: impl Into<String>) -> Self {
        self.bolt11 = Some(bolt11.into());
        self
    }

    fn render(&self) -> Vec<String> {
        let mut row = vec![self.msats.to_string()];
        if let Some(invoice) = &self.bolt11 {
            row.push(invoice.clone());
        }
        row
    }

    fn parse(args: &[String]) -> Result<Self, Nip90Error> {
        let raw = args
            .first()
            .ok_or_else(|| Nip90Error::MalformedMillisats(String::new()))?;
        let msats: u64 = raw
            .parse()
            .map_err(|_| Nip90Error::MalformedMillisats(raw.clone()))?;
        let bolt11 = args.get(1).cloned();
        Ok(Self { msats, bolt11 })
    }
}

/// Typed bundle for a `kind: 5000..=5999` job request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRequest {
    /// Kind of the request (MUST live in `5000..=5999`).
    pub kind: Kind,
    /// `.content` — usually empty; spec allows free-form text or
    /// the encrypted-params ciphertext when paired with the
    /// `encrypted` tag.
    pub content: String,
    /// Input rows (zero or more).
    pub inputs: Vec<JobInputRef>,
    /// Expected output media type / format.
    pub output: Option<String>,
    /// Optional parameters (key/value).
    pub params: Vec<JobParam>,
    /// Optional max bid in millisats.
    pub bid_msats: Option<u64>,
    /// Relays where service providers SHOULD publish responses.
    pub relays: Vec<RelayUrl>,
    /// Hashtags scoping the request (`t` tags).
    pub topics: Vec<String>,
    /// Service providers the customer wants to reach (`p` tags).
    pub providers: Vec<PublicKey>,
    /// True when the inputs / params have been encrypted into
    /// [`Self::content`]; controls the `encrypted` marker tag.
    pub encrypted: bool,
}

impl JobRequest {
    /// Construct a job request bound to `kind`.
    ///
    /// # Errors
    ///
    /// Returns [`Nip90Error::InvalidRequestKind`] when `kind` is
    /// outside `5000..=5999`.
    pub const fn new(kind: Kind) -> Result<Self, Nip90Error> {
        if !is_job_request_kind(kind) {
            return Err(Nip90Error::InvalidRequestKind(kind));
        }
        Ok(Self {
            kind,
            content: String::new(),
            inputs: Vec::new(),
            output: None,
            params: Vec::new(),
            bid_msats: None,
            relays: Vec::new(),
            topics: Vec::new(),
            providers: Vec::new(),
            encrypted: false,
        })
    }

    /// Set [`Self::content`].
    #[must_use]
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Append an input row.
    #[must_use]
    pub fn input(mut self, input: JobInputRef) -> Self {
        self.inputs.push(input);
        self
    }

    /// Append a parameter row.
    #[must_use]
    pub fn param(mut self, param: JobParam) -> Self {
        self.params.push(param);
        self
    }

    /// Set [`Self::output`].
    #[must_use]
    pub fn output(mut self, output: impl Into<String>) -> Self {
        self.output = Some(output.into());
        self
    }

    /// Set [`Self::bid_msats`].
    #[must_use]
    pub const fn bid_msats(mut self, msats: u64) -> Self {
        self.bid_msats = Some(msats);
        self
    }

    /// Append a relay hint.
    #[must_use]
    pub fn relay(mut self, url: RelayUrl) -> Self {
        self.relays.push(url);
        self
    }

    /// Append a hashtag.
    #[must_use]
    pub fn topic(mut self, topic: impl Into<String>) -> Self {
        self.topics.push(topic.into());
        self
    }

    /// Append a target service-provider pubkey.
    #[must_use]
    pub fn provider(mut self, provider: PublicKey) -> Self {
        self.providers.push(provider);
        self
    }

    /// Mark inputs / params as encrypted (stamps the `encrypted`
    /// marker tag on the rendered event).
    #[must_use]
    pub const fn encrypted(mut self, encrypted: bool) -> Self {
        self.encrypted = encrypted;
        self
    }

    /// Render the typed bundle to the public tag list.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::new();
        for input in &self.inputs {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::I),
                input.input.render(input.marker.as_deref()),
            ));
        }
        if let Some(output) = &self.output {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::OUTPUT),
                [output.clone()],
            ));
        }
        for param in &self.params {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::PARAM),
                [param.key.clone(), param.value.clone()],
            ));
        }
        if let Some(bid) = self.bid_msats {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::BID),
                [bid.to_string()],
            ));
        }
        if !self.relays.is_empty() {
            let mut row = vec![tag_names::RELAYS.to_owned()];
            for relay in &self.relays {
                row.push(relay.as_str().to_owned());
            }
            // `Tag::with` takes the head separately; build the row
            // without re-prepending the head.
            row.remove(0);
            tags.push(Tag::with(&TagKind::custom(tag_names::RELAYS), row));
        }
        for topic in &self.topics {
            tags.push(Tag::with(&TagKind::custom(tag_names::T), [topic.clone()]));
        }
        for provider in &self.providers {
            tags.push(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P)),
                [provider.to_hex()],
            ));
        }
        if self.encrypted {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::ENCRYPTED),
                Vec::<String>::new(),
            ));
        }
        tags
    }

    /// Parse a signed job-request event.
    ///
    /// # Errors
    ///
    /// Returns [`Nip90Error::InvalidRequestKind`] when the event's
    /// kind is outside `5000..=5999`; otherwise forwards every
    /// per-tag parse error.
    pub fn from_event(event: &Event) -> Result<Self, Nip90Error> {
        if !is_job_request_kind(event.kind) {
            return Err(Nip90Error::InvalidRequestKind(event.kind));
        }
        let mut req = Self::new(event.kind)?;
        req.content.clone_from(&event.content);
        for tag in &event.tags {
            let values = tag.values();
            let args = values.get(1..).unwrap_or(&[]);
            match tag.name() {
                tag_names::I => {
                    let (input, marker) = JobInput::parse(args)?;
                    req.inputs.push(JobInputRef { input, marker });
                }
                tag_names::OUTPUT => {
                    if let Some(value) = args.first() {
                        req.output = Some(value.clone());
                    }
                }
                tag_names::PARAM => {
                    let key = args.first().cloned().ok_or(Nip90Error::MalformedParam)?;
                    let value = args.get(1).cloned().ok_or(Nip90Error::MalformedParam)?;
                    req.params.push(JobParam { key, value });
                }
                tag_names::BID => {
                    if let Some(value) = args.first() {
                        let bid: u64 = value
                            .parse()
                            .map_err(|_| Nip90Error::MalformedMillisats(value.clone()))?;
                        req.bid_msats = Some(bid);
                    }
                }
                tag_names::RELAYS => {
                    for raw in args {
                        req.relays.push(RelayUrl::parse(raw)?);
                    }
                }
                tag_names::T => {
                    if let Some(value) = args.first() {
                        req.topics.push(value.clone());
                    }
                }
                "p" => {
                    if let Some(value) = args.first() {
                        req.providers.push(PublicKey::parse(value)?);
                    }
                }
                tag_names::ENCRYPTED => req.encrypted = true,
                _ => {}
            }
        }
        Ok(req)
    }
}

/// Typed bundle for a `kind: 6000..=6999` job result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobResult {
    /// Result kind (MUST live in `6000..=6999`).
    pub kind: Kind,
    /// `.content` — typically the job output; ciphertext when
    /// [`Self::encrypted`] is set.
    pub content: String,
    /// Stringified JSON of the original [`JobRequest`] event (the
    /// `request` tag).
    pub request_json: Option<String>,
    /// Original request event id (the `e` tag).
    pub request_event: Option<EventId>,
    /// Optional relay hint paired with [`Self::request_event`].
    pub request_relay: Option<RelayUrl>,
    /// Customer pubkey (the `p` tag).
    pub customer: Option<PublicKey>,
    /// Original input(s) repeated for traceability.
    pub inputs: Vec<JobInputRef>,
    /// Optional payment hint.
    pub amount: Option<Amount>,
    /// True when [`Self::content`] is encrypted ciphertext.
    pub encrypted: bool,
}

impl JobResult {
    /// Construct a result bundle bound to `kind`.
    ///
    /// # Errors
    ///
    /// Returns [`Nip90Error::InvalidResultKind`] when `kind` is
    /// outside `6000..=6999`.
    pub const fn new(kind: Kind) -> Result<Self, Nip90Error> {
        if !is_job_result_kind(kind) {
            return Err(Nip90Error::InvalidResultKind(kind));
        }
        Ok(Self {
            kind,
            content: String::new(),
            request_json: None,
            request_event: None,
            request_relay: None,
            customer: None,
            inputs: Vec::new(),
            amount: None,
            encrypted: false,
        })
    }

    /// Set [`Self::content`].
    #[must_use]
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Set the `request` tag JSON.
    #[must_use]
    pub fn request_json(mut self, json: impl Into<String>) -> Self {
        self.request_json = Some(json.into());
        self
    }

    /// Set the originating request `(event_id, relay?)`.
    #[must_use]
    pub fn request_event(mut self, event: EventId, relay: Option<RelayUrl>) -> Self {
        self.request_event = Some(event);
        self.request_relay = relay;
        self
    }

    /// Set the customer pubkey.
    #[must_use]
    pub const fn customer(mut self, customer: PublicKey) -> Self {
        self.customer = Some(customer);
        self
    }

    /// Append an original input for traceability.
    #[must_use]
    pub fn input(mut self, input: JobInputRef) -> Self {
        self.inputs.push(input);
        self
    }

    /// Set the payment hint.
    #[must_use]
    pub fn amount(mut self, amount: Amount) -> Self {
        self.amount = Some(amount);
        self
    }

    /// Mark [`Self::content`] as encrypted ciphertext.
    #[must_use]
    pub const fn encrypted(mut self, encrypted: bool) -> Self {
        self.encrypted = encrypted;
        self
    }

    /// Render the typed bundle to the public tag list.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::new();
        if let Some(json) = &self.request_json {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::REQUEST),
                [json.clone()],
            ));
        }
        if let Some(event_id) = self.request_event {
            let mut row = vec![event_id.to_hex()];
            if let Some(relay) = &self.request_relay {
                row.push(relay.as_str().to_owned());
            }
            tags.push(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E)),
                row,
            ));
        }
        for input in &self.inputs {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::I),
                input.input.render(input.marker.as_deref()),
            ));
        }
        if let Some(customer) = self.customer {
            tags.push(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P)),
                [customer.to_hex()],
            ));
        }
        if let Some(amount) = &self.amount {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::AMOUNT),
                amount.render(),
            ));
        }
        if self.encrypted {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::ENCRYPTED),
                Vec::<String>::new(),
            ));
        }
        tags
    }

    /// Parse a signed job-result event.
    ///
    /// # Errors
    ///
    /// Returns [`Nip90Error::InvalidResultKind`] when the event's
    /// kind is outside `6000..=6999`; otherwise forwards every
    /// per-tag parse error.
    pub fn from_event(event: &Event) -> Result<Self, Nip90Error> {
        if !is_job_result_kind(event.kind) {
            return Err(Nip90Error::InvalidResultKind(event.kind));
        }
        let mut result = Self::new(event.kind)?;
        result.content.clone_from(&event.content);
        for tag in &event.tags {
            let values = tag.values();
            let args = values.get(1..).unwrap_or(&[]);
            match tag.name() {
                tag_names::REQUEST => {
                    if let Some(json) = args.first() {
                        result.request_json = Some(json.clone());
                    }
                }
                "e" => {
                    if let Some(id_hex) = args.first() {
                        result.request_event = Some(EventId::parse(id_hex)?);
                    }
                    if let Some(relay) = args.get(1)
                        && !relay.is_empty()
                    {
                        result.request_relay = Some(RelayUrl::parse(relay)?);
                    }
                }
                tag_names::I => {
                    let (input, marker) = JobInput::parse(args)?;
                    result.inputs.push(JobInputRef { input, marker });
                }
                "p" => {
                    if let Some(value) = args.first() {
                        result.customer = Some(PublicKey::parse(value)?);
                    }
                }
                tag_names::AMOUNT => {
                    result.amount = Some(Amount::parse(args)?);
                }
                tag_names::ENCRYPTED => result.encrypted = true,
                _ => {}
            }
        }
        Ok(result)
    }
}

/// Status column of a [`JobFeedback`] event.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FeedbackStatus {
    /// `payment-required`.
    PaymentRequired,
    /// `processing`.
    Processing,
    /// `error`.
    Error,
    /// `success`.
    Success,
    /// `partial` — partial result samples allowed in `.content`.
    Partial,
    /// Forward-compatible escape hatch for future status tokens.
    Custom(String),
}

impl FeedbackStatus {
    /// Wire-form string representation.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::PaymentRequired => feedback_strings::PAYMENT_REQUIRED,
            Self::Processing => feedback_strings::PROCESSING,
            Self::Error => feedback_strings::ERROR,
            Self::Success => feedback_strings::SUCCESS,
            Self::Partial => feedback_strings::PARTIAL,
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Parse a wire-form string. Unknown values fall through to
    /// [`Self::Custom`].
    #[must_use]
    pub fn from_wire(s: &str) -> Self {
        match s {
            feedback_strings::PAYMENT_REQUIRED => Self::PaymentRequired,
            feedback_strings::PROCESSING => Self::Processing,
            feedback_strings::ERROR => Self::Error,
            feedback_strings::SUCCESS => Self::Success,
            feedback_strings::PARTIAL => Self::Partial,
            other => Self::Custom(other.to_owned()),
        }
    }
}

/// Typed bundle for a `kind: 7000` job-feedback event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobFeedback {
    /// `.content` — usually empty or partial result samples.
    pub content: String,
    /// `status` tag.
    pub status: FeedbackStatus,
    /// Optional human-readable explanation paired with the status.
    pub status_extra: Option<String>,
    /// Optional payment hint.
    pub amount: Option<Amount>,
    /// Original request event id.
    pub request_event: Option<EventId>,
    /// Optional relay hint paired with [`Self::request_event`].
    pub request_relay: Option<RelayUrl>,
    /// Customer pubkey.
    pub customer: Option<PublicKey>,
}

impl JobFeedback {
    /// Construct a feedback bundle.
    #[must_use]
    pub const fn new(status: FeedbackStatus) -> Self {
        Self {
            content: String::new(),
            status,
            status_extra: None,
            amount: None,
            request_event: None,
            request_relay: None,
            customer: None,
        }
    }

    /// Set [`Self::content`].
    #[must_use]
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Attach an extra human-readable status message.
    #[must_use]
    pub fn status_extra(mut self, extra: impl Into<String>) -> Self {
        self.status_extra = Some(extra.into());
        self
    }

    /// Set the payment hint.
    #[must_use]
    pub fn amount(mut self, amount: Amount) -> Self {
        self.amount = Some(amount);
        self
    }

    /// Reference the originating request.
    #[must_use]
    pub fn request_event(mut self, event: EventId, relay: Option<RelayUrl>) -> Self {
        self.request_event = Some(event);
        self.request_relay = relay;
        self
    }

    /// Set the customer pubkey.
    #[must_use]
    pub const fn customer(mut self, customer: PublicKey) -> Self {
        self.customer = Some(customer);
        self
    }

    /// Render the typed bundle to the public tag list.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::new();
        let mut status_row = vec![self.status.as_str().to_owned()];
        if let Some(extra) = &self.status_extra {
            status_row.push(extra.clone());
        }
        tags.push(Tag::with(&TagKind::custom(tag_names::STATUS), status_row));
        if let Some(amount) = &self.amount {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::AMOUNT),
                amount.render(),
            ));
        }
        if let Some(event_id) = self.request_event {
            let mut row = vec![event_id.to_hex()];
            if let Some(relay) = &self.request_relay {
                row.push(relay.as_str().to_owned());
            }
            tags.push(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E)),
                row,
            ));
        }
        if let Some(customer) = self.customer {
            tags.push(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P)),
                [customer.to_hex()],
            ));
        }
        tags
    }

    /// Parse a signed `kind: 7000` event.
    ///
    /// # Errors
    ///
    /// Returns [`Nip90Error::InvalidFeedbackKind`] when the event's
    /// kind is not `7000`; otherwise forwards every per-tag parse
    /// error.
    pub fn from_event(event: &Event) -> Result<Self, Nip90Error> {
        if event.kind != KIND_JOB_FEEDBACK {
            return Err(Nip90Error::InvalidFeedbackKind(event.kind));
        }
        let mut feedback = Self::new(FeedbackStatus::Custom(String::new()));
        feedback.content.clone_from(&event.content);
        for tag in &event.tags {
            let values = tag.values();
            let args = values.get(1..).unwrap_or(&[]);
            match tag.name() {
                tag_names::STATUS => {
                    if let Some(value) = args.first() {
                        feedback.status = FeedbackStatus::from_wire(value);
                    }
                    feedback.status_extra = args.get(1).cloned();
                }
                tag_names::AMOUNT => {
                    feedback.amount = Some(Amount::parse(args)?);
                }
                "e" => {
                    if let Some(id_hex) = args.first() {
                        feedback.request_event = Some(EventId::parse(id_hex)?);
                    }
                    if let Some(relay) = args.get(1)
                        && !relay.is_empty()
                    {
                        feedback.request_relay = Some(RelayUrl::parse(relay)?);
                    }
                }
                "p" => {
                    if let Some(value) = args.first() {
                        feedback.customer = Some(PublicKey::parse(value)?);
                    }
                }
                _ => {}
            }
        }
        Ok(feedback)
    }
}

impl EventBuilder {
    /// Author a NIP-90 job-request event from a typed [`JobRequest`].
    #[must_use]
    pub fn dvm_job_request(request: &JobRequest) -> Self {
        let mut builder = Self::new(request.kind, request.content.clone());
        for tag in request.to_tags() {
            builder = builder.tag(tag);
        }
        builder
    }

    /// Author a NIP-90 job-result event from a typed [`JobResult`].
    #[must_use]
    pub fn dvm_job_result(result: &JobResult) -> Self {
        let mut builder = Self::new(result.kind, result.content.clone());
        for tag in result.to_tags() {
            builder = builder.tag(tag);
        }
        builder
    }

    /// Author a NIP-90 job-feedback event from a typed
    /// [`JobFeedback`].
    #[must_use]
    pub fn dvm_job_feedback(feedback: &JobFeedback) -> Self {
        let mut builder = Self::new(KIND_JOB_FEEDBACK, feedback.content.clone());
        for tag in feedback.to_tags() {
            builder = builder.tag(tag);
        }
        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn other_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000005").unwrap()
    }

    fn relay() -> RelayUrl {
        RelayUrl::parse("wss://relay.example/").unwrap()
    }

    #[test]
    fn kind_helpers_round_trip() {
        let req = Kind::new(5_001);
        let res = result_kind_for(req).unwrap();
        assert_eq!(res, Kind::new(6_001));
        assert_eq!(request_kind_for(res), Some(req));
        assert!(is_job_request_kind(req));
        assert!(is_job_result_kind(res));
        assert!(!is_job_request_kind(res));
        assert!(result_kind_for(Kind::TEXT_NOTE).is_none());
        assert!(request_kind_for(Kind::new(7_000)).is_none());
    }

    #[test]
    fn job_request_round_trips_through_event() {
        let request = JobRequest::new(Kind::new(5_001))
            .unwrap()
            .input(JobInputRef::new(JobInput::Text("hello".to_owned())).marker("prompt"))
            .input(JobInputRef::new(JobInput::Url(
                "https://example.com/data".to_owned(),
            )))
            .output("text/plain")
            .param(JobParam::new("model", "LLaMA-2"))
            .param(JobParam::new("temperature", "0.5"))
            .bid_msats(21_000)
            .relay(relay())
            .topic("bitcoin")
            .provider(*other_keys().public_key());
        let event = EventBuilder::dvm_job_request(&request)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, Kind::new(5_001));
        let recovered = JobRequest::from_event(&event).unwrap();
        assert_eq!(recovered, request);
    }

    #[test]
    fn job_request_new_rejects_kind_outside_range() {
        assert!(matches!(
            JobRequest::new(Kind::TEXT_NOTE),
            Err(Nip90Error::InvalidRequestKind(_)),
        ));
        assert!(matches!(
            JobRequest::new(Kind::new(6_000)),
            Err(Nip90Error::InvalidRequestKind(_)),
        ));
    }

    #[test]
    fn job_request_input_kinds_round_trip() {
        let request = JobRequest::new(Kind::new(5_002))
            .unwrap()
            .input(JobInputRef::new(JobInput::Event {
                event_id: EventId::from_byte_array([0xaa; 32]),
                relay: Some(relay()),
            }))
            .input(JobInputRef::new(JobInput::Job {
                event_id: EventId::from_byte_array([0xbb; 32]),
                relay: None,
            }))
            .input(JobInputRef::new(JobInput::Text("hi".to_owned())));
        let event = EventBuilder::dvm_job_request(&request)
            .sign_with_keys(&keys())
            .unwrap();
        let recovered = JobRequest::from_event(&event).unwrap();
        assert_eq!(recovered.inputs, request.inputs);
    }

    #[test]
    fn job_request_encrypted_marker_round_trips() {
        let request = JobRequest::new(Kind::new(5_050))
            .unwrap()
            .content("ciphertext")
            .encrypted(true);
        let event = EventBuilder::dvm_job_request(&request)
            .sign_with_keys(&keys())
            .unwrap();
        let has_marker = event.tags.iter().any(|t| t.name() == "encrypted");
        assert!(has_marker);
        let recovered = JobRequest::from_event(&event).unwrap();
        assert!(recovered.encrypted);
    }

    #[test]
    fn job_result_round_trips_through_event() {
        let result = JobResult::new(Kind::new(6_001))
            .unwrap()
            .content("translation output")
            .request_json("{\"id\":\"abc\"}")
            .request_event(EventId::from_byte_array([0x11; 32]), Some(relay()))
            .customer(*keys().public_key())
            .input(JobInputRef::new(JobInput::Url(
                "https://example.com".to_owned(),
            )))
            .amount(Amount::new(10_000).invoice("lnbc1..."));
        let event = EventBuilder::dvm_job_result(&result)
            .sign_with_keys(&other_keys())
            .unwrap();
        assert_eq!(event.kind, Kind::new(6_001));
        let recovered = JobResult::from_event(&event).unwrap();
        assert_eq!(recovered, result);
    }

    #[test]
    fn job_result_new_rejects_kind_outside_range() {
        assert!(matches!(
            JobResult::new(Kind::TEXT_NOTE),
            Err(Nip90Error::InvalidResultKind(_)),
        ));
        assert!(matches!(
            JobResult::new(Kind::new(5_001)),
            Err(Nip90Error::InvalidResultKind(_)),
        ));
    }

    #[test]
    fn job_feedback_round_trips_through_event() {
        let feedback = JobFeedback::new(FeedbackStatus::PaymentRequired)
            .status_extra("Please pay 21 sats")
            .amount(Amount::new(21_000).invoice("lnbc..."))
            .request_event(EventId::from_byte_array([0x22; 32]), Some(relay()))
            .customer(*keys().public_key())
            .content("partial sample");
        let event = EventBuilder::dvm_job_feedback(&feedback)
            .sign_with_keys(&other_keys())
            .unwrap();
        assert_eq!(event.kind, KIND_JOB_FEEDBACK);
        let recovered = JobFeedback::from_event(&event).unwrap();
        assert_eq!(recovered, feedback);
    }

    #[test]
    fn job_feedback_status_round_trips_through_wire_form() {
        for status in [
            FeedbackStatus::PaymentRequired,
            FeedbackStatus::Processing,
            FeedbackStatus::Error,
            FeedbackStatus::Success,
            FeedbackStatus::Partial,
            FeedbackStatus::Custom("queued".to_owned()),
        ] {
            assert_eq!(FeedbackStatus::from_wire(status.as_str()), status);
        }
    }

    #[test]
    fn job_feedback_from_event_rejects_wrong_kind() {
        let event = EventBuilder::text_note("not feedback")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            JobFeedback::from_event(&event),
            Err(Nip90Error::InvalidFeedbackKind(_)),
        ));
    }

    #[test]
    fn job_feedback_amount_without_invoice_round_trips() {
        let feedback = JobFeedback::new(FeedbackStatus::Processing).amount(Amount::new(1_000));
        let event = EventBuilder::dvm_job_feedback(&feedback)
            .sign_with_keys(&keys())
            .unwrap();
        let recovered = JobFeedback::from_event(&event).unwrap();
        let amount = recovered.amount.expect("Amount must round-trip");
        assert_eq!(amount.msats, 1_000);
        assert!(
            amount.bolt11.is_none(),
            "no invoice should round-trip as None"
        );
    }
}
