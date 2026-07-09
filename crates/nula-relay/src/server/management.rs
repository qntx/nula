//! NIP-86 relay management state (the `server` feature).
//!
//! [`ManagementState`] is a shared, interior-mutable moderation store
//! that backs the served NIP-86 management API **and** doubles as the
//! relay's [`WritePolicy`]. A ban applied over the API therefore takes
//! effect on the very next inbound `EVENT`.
//!
//! The HTTP transport, NIP-98 authorization, and request framing live
//! in `crate::server::relay`; this module owns the state and the pure
//! [`ManagementState::handle_request`] dispatch (every method assumes
//! the caller is an already-authorized admin).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use nula_core::boxed::BoxFuture;
use nula_core::message::MachineReadablePrefix;
use nula_core::nips::nip11::RelayInformation;
use nula_core::nips::nip86::{IpEntry, Method, PubkeyEntry, Request, Response};
use nula_core::types::Url;
use nula_core::{Event, Kind, PublicKey};
use serde_json::{Value, json};

use crate::server::policy::{AdmitVerdict, WritePolicy};

/// Method tokens this relay advertises via `supportedmethods`.
const SUPPORTED_METHODS: &[&str] = &[
    "supportedmethods",
    "banpubkey",
    "unbanpubkey",
    "listbannedpubkeys",
    "allowpubkey",
    "unallowpubkey",
    "listallowedpubkeys",
    "allowkind",
    "disallowkind",
    "listallowedkinds",
    "blockip",
    "unblockip",
    "listblockedips",
    "changerelayname",
    "changerelaydescription",
    "changerelayicon",
];

/// Shared, mutable moderation store backing the NIP-86 management API.
///
/// Construct via [`Self::new`] with the set of admin pubkeys permitted
/// to call the API, wrap in an [`std::sync::Arc`], and install it as the
/// relay's write policy (the builder does this for you). Every mutation
/// is visible immediately to both the API and the admission path.
#[derive(Debug, Default)]
pub struct ManagementState {
    /// Pubkeys allowed to call the management API (fixed at construction).
    admins: HashSet<PublicKey>,
    /// Interior-mutable moderation state.
    inner: RwLock<Inner>,
}

/// The mutable half of [`ManagementState`].
#[derive(Debug, Default)]
struct Inner {
    banned_pubkeys: HashMap<PublicKey, Option<String>>,
    allowed_pubkeys: HashMap<PublicKey, Option<String>>,
    /// `None` means "all kinds allowed"; `Some(set)` restricts to it.
    allowed_kinds: Option<HashSet<Kind>>,
    blocked_ips: HashMap<IpAddr, Option<String>>,
    name: Option<String>,
    description: Option<String>,
    icon: Option<Url>,
}

impl ManagementState {
    /// Build a store whose API is callable by `admins`.
    #[must_use]
    pub fn new(admins: impl IntoIterator<Item = PublicKey>) -> Self {
        Self {
            admins: admins.into_iter().collect(),
            inner: RwLock::new(Inner::default()),
        }
    }

    /// `true` when `pubkey` may call the management API.
    #[must_use]
    pub fn is_admin(&self, pubkey: &PublicKey) -> bool {
        self.admins.contains(pubkey)
    }

    /// `true` when `pubkey` is currently banned.
    #[must_use]
    pub fn is_pubkey_banned(&self, pubkey: &PublicKey) -> bool {
        self.read().banned_pubkeys.contains_key(pubkey)
    }

    /// `true` when `ip` is currently blocked.
    #[must_use]
    pub fn is_ip_blocked(&self, ip: &IpAddr) -> bool {
        self.read().blocked_ips.contains_key(ip)
    }

    /// Snapshot of the currently allowlisted authors.
    #[must_use]
    pub fn allowed_pubkeys(&self) -> Vec<PublicKey> {
        self.read().allowed_pubkeys.keys().copied().collect()
    }

    /// The current relay-name override, if any.
    #[must_use]
    pub fn relay_name(&self) -> Option<String> {
        self.read().name.clone()
    }

    /// Overlay the mutable `name` / `description` / `icon` onto a base
    /// [`RelayInformation`] before it is served (NIP-11, C1).
    pub fn apply_to(&self, info: &mut RelayInformation) {
        let inner = self.read();
        if let Some(name) = &inner.name {
            info.name = Some(name.clone());
        }
        if let Some(description) = &inner.description {
            info.description = Some(description.clone());
        }
        if let Some(icon) = &inner.icon {
            info.icon = Some(icon.clone());
        }
    }

    /// Dispatch an authorized NIP-86 [`Request`]. The caller MUST have
    /// already verified NIP-98 admin authorization.
    #[must_use]
    pub fn handle_request(&self, request: &Request) -> Response {
        let params = &request.params;
        match Method::parse(&request.method) {
            Method::SupportedMethods => Response::ok(json!(SUPPORTED_METHODS)),
            Method::BanPubkey => self.set_pubkey(params, Listing::Banned),
            Method::UnbanPubkey => self.remove_pubkey(params, Listing::Banned),
            Method::ListBannedPubkeys => self.list_pubkeys(Listing::Banned),
            Method::AllowPubkey => self.set_pubkey(params, Listing::Allowed),
            Method::UnallowPubkey => self.remove_pubkey(params, Listing::Allowed),
            Method::ListAllowedPubkeys => self.list_pubkeys(Listing::Allowed),
            Method::AllowKind => self.set_kind(params, true),
            Method::DisallowKind => self.set_kind(params, false),
            Method::ListAllowedKinds => self.list_kinds(),
            Method::BlockIp => self.block_ip(params),
            Method::UnblockIp => self.unblock_ip(params),
            Method::ListBlockedIps => self.list_blocked_ips(),
            Method::ChangeRelayName => self.change_name(params),
            Method::ChangeRelayDescription => self.change_description(params),
            Method::ChangeRelayIcon => self.change_icon(params),
            other => Response::err(format!("unsupported method: {}", other.as_str())),
        }
    }

    fn read(&self) -> RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Admission decision for an inbound `EVENT`, shared by the
    /// [`WritePolicy`] impl. Bans and IP blocks win first, then the
    /// allowlist (when non-empty) and the allowed-kinds set (when set).
    fn evaluate(&self, event: &Event, addr: SocketAddr) -> AdmitVerdict {
        let inner = self.read();
        if inner.blocked_ips.contains_key(&addr.ip()) {
            AdmitVerdict::reject(MachineReadablePrefix::Blocked, "client ip is blocked")
        } else if inner.banned_pubkeys.contains_key(&event.pubkey) {
            AdmitVerdict::reject(MachineReadablePrefix::Blocked, "author is banned")
        } else if !inner.allowed_pubkeys.is_empty()
            && !inner.allowed_pubkeys.contains_key(&event.pubkey)
        {
            AdmitVerdict::reject(
                MachineReadablePrefix::Blocked,
                "author is not on this relay's allowlist",
            )
        } else if inner
            .allowed_kinds
            .as_ref()
            .is_some_and(|kinds| !kinds.contains(&event.kind))
        {
            AdmitVerdict::reject(
                MachineReadablePrefix::Blocked,
                "event kind is not allowed on this relay",
            )
        } else {
            AdmitVerdict::Accept
        }
    }

    fn set_pubkey(&self, params: &[Value], listing: Listing) -> Response {
        let Some(pubkey) = param_pubkey(params) else {
            return Response::err("expected a hex pubkey as the first parameter");
        };
        let reason = param_str(params, 1).map(str::to_owned);
        {
            let mut inner = self.write();
            match listing {
                Listing::Banned => {
                    inner.allowed_pubkeys.remove(&pubkey);
                    inner.banned_pubkeys.insert(pubkey, reason);
                }
                Listing::Allowed => {
                    inner.banned_pubkeys.remove(&pubkey);
                    inner.allowed_pubkeys.insert(pubkey, reason);
                }
            }
        }
        Response::ok(json!(true))
    }

    fn remove_pubkey(&self, params: &[Value], listing: Listing) -> Response {
        let Some(pubkey) = param_pubkey(params) else {
            return Response::err("expected a hex pubkey as the first parameter");
        };
        {
            let mut inner = self.write();
            match listing {
                Listing::Banned => inner.banned_pubkeys.remove(&pubkey),
                Listing::Allowed => inner.allowed_pubkeys.remove(&pubkey),
            };
        }
        Response::ok(json!(true))
    }

    fn list_pubkeys(&self, listing: Listing) -> Response {
        let inner = self.read();
        let rows: Vec<PubkeyEntry> = match listing {
            Listing::Banned => &inner.banned_pubkeys,
            Listing::Allowed => &inner.allowed_pubkeys,
        }
        .iter()
        .map(|(pubkey, reason)| PubkeyEntry {
            pubkey: pubkey.to_hex(),
            reason: reason.clone(),
        })
        .collect();
        drop(inner);
        serde_json::to_value(rows).map_or_else(|e| Response::err(e.to_string()), Response::ok)
    }

    fn set_kind(&self, params: &[Value], allow: bool) -> Response {
        let Some(kind) = param_kind(params) else {
            return Response::err("expected a kind integer as the first parameter");
        };
        let mut inner = self.write();
        if allow {
            inner
                .allowed_kinds
                .get_or_insert_with(HashSet::new)
                .insert(kind);
        } else if let Some(kinds) = inner.allowed_kinds.as_mut() {
            kinds.remove(&kind);
        }
        drop(inner);
        Response::ok(json!(true))
    }

    fn list_kinds(&self) -> Response {
        let kinds: Vec<u16> = {
            let inner = self.read();
            inner
                .allowed_kinds
                .as_ref()
                .map(|set| set.iter().map(|k| k.as_u16()).collect())
                .unwrap_or_default()
        };
        Response::ok(json!(kinds))
    }

    fn block_ip(&self, params: &[Value]) -> Response {
        let Some(ip) = param_ip(params) else {
            return Response::err("expected an ip address as the first parameter");
        };
        let reason = param_str(params, 1).map(str::to_owned);
        self.write().blocked_ips.insert(ip, reason);
        Response::ok(json!(true))
    }

    fn unblock_ip(&self, params: &[Value]) -> Response {
        let Some(ip) = param_ip(params) else {
            return Response::err("expected an ip address as the first parameter");
        };
        self.write().blocked_ips.remove(&ip);
        Response::ok(json!(true))
    }

    fn list_blocked_ips(&self) -> Response {
        let rows: Vec<IpEntry> = {
            let inner = self.read();
            inner
                .blocked_ips
                .iter()
                .map(|(ip, reason)| IpEntry {
                    ip: ip.to_string(),
                    reason: reason.clone(),
                })
                .collect()
        };
        serde_json::to_value(rows).map_or_else(|e| Response::err(e.to_string()), Response::ok)
    }

    fn change_name(&self, params: &[Value]) -> Response {
        let Some(name) = param_str(params, 0) else {
            return Response::err("expected a name string as the first parameter");
        };
        self.write().name = Some(name.to_owned());
        Response::ok(json!(true))
    }

    fn change_description(&self, params: &[Value]) -> Response {
        let Some(description) = param_str(params, 0) else {
            return Response::err("expected a description string as the first parameter");
        };
        self.write().description = Some(description.to_owned());
        Response::ok(json!(true))
    }

    fn change_icon(&self, params: &[Value]) -> Response {
        let Some(raw) = param_str(params, 0) else {
            return Response::err("expected an icon url as the first parameter");
        };
        let Ok(url) = Url::parse(raw) else {
            return Response::err("icon must be a valid url");
        };
        self.write().icon = Some(url);
        Response::ok(json!(true))
    }
}

impl WritePolicy for ManagementState {
    fn admit_event<'a>(
        &'a self,
        event: &'a Event,
        addr: SocketAddr,
    ) -> BoxFuture<'a, AdmitVerdict> {
        let verdict = self.evaluate(event, addr);
        Box::pin(async move { verdict })
    }
}

/// Which pubkey list a mutation targets.
#[derive(Debug, Clone, Copy)]
enum Listing {
    Banned,
    Allowed,
}

fn param_str(params: &[Value], index: usize) -> Option<&str> {
    params.get(index).and_then(Value::as_str)
}

fn param_pubkey(params: &[Value]) -> Option<PublicKey> {
    PublicKey::parse(param_str(params, 0)?).ok()
}

fn param_kind(params: &[Value]) -> Option<Kind> {
    let raw = params.first().and_then(Value::as_u64)?;
    u16::try_from(raw).ok().map(Kind::new)
}

fn param_ip(params: &[Value]) -> Option<IpAddr> {
    param_str(params, 0)?.parse().ok()
}
