# ADR-0006: Single-relay state machine — actor + detached task

- **Status:** Accepted
- **Date:** 2026-05-15
- **Decision drivers:** Layer 3 (`nula-relay`) needs a robust, testable, single-relay state machine. Multi-relay orchestration belongs to Layer 4 (`nula-relay-pool`).
- **Reverses / supersedes:** none.

## Context

`nula-relay` owns three concurrent concerns against one WebSocket:

1. **Caller-driven control flow** — `connect`, `subscribe`, `publish`, `authenticate`, `disconnect`.
2. **Wire I/O** — `["EVENT", …]` / `OK` / `EOSE` / `CLOSED` / `NOTICE` / `AUTH` flowing over the socket.
3. **Time-driven housekeeping** — reconnect backoff, publish timeouts, eventual stats updates.

These concerns share four pieces of state — the `WebSocketSink` / `WebSocketStream` pair, the subscription map, the pending-publish map, and the connection status — that must stay consistent across every wakeup. A locks-everywhere design degrades quickly: contention in the publish hot path, `Mutex` poisoning on panic, and async-locks held across awaits that the borrow checker is happy with but the human reader is not.

We want the simplest model that:

- enforces single-task ownership of the mutable state, ideally **at compile time**,
- yields cancel-safe behaviour at every wakeup boundary,
- works under the existing tokio-only runtime decision (ADR-0003),
- lets the public `Relay` handle stay `Send + Sync + Clone`, suitable for callers that share a single relay across tasks.

## Decision

`nula-relay` runs as a **single-task actor**. The public [`Relay`] handle is a thin `Arc<Inner>`; all mutable state lives inside a `tokio::spawn`ed task. The handle never touches that state directly.

```text
        Relay (Arc<Inner>) -------- Caller threads / tasks
              | command_tx
              | close_tx
              | notification_rx
              v
        ─── actor task ───────────────────────────────
        select! {
            cmd  = command_rx.recv()                 -> dispatch_command(...)
            id   = close_rx.recv()                   -> handle_drop_subscription(...)
            frame = recv_inbound(&mut stream)        -> dispatch_relay_message(...)
            ()   = next_reconnect.as_mut()           -> reconnect()
            ()   = next_publish_timeout.as_mut()     -> expire_pending_publishes()
        }
        ─────────────────────────────────────────────
              ^
              | sink.send(...)
              v
            WebSocket transport
```

### Channels

| Direction        | Channel                              | Reason                                                                                 |
| ---------------- | ------------------------------------ | -------------------------------------------------------------------------------------- |
| Handle  → Actor  | `mpsc::UnboundedSender<Command>`     | Lossless command delivery; `unbounded` is fine because commands are caller-rate.       |
| Drop    → Actor  | `mpsc::UnboundedSender<Subscription` | `SubscriptionHandle::Drop` fires a CLOSE; the handle never blocks the drop.            |
| Actor   → Handle | `mpsc::UnboundedReceiver<Notif>`     | Single-consumer, lossless protocol notifications (status, NOTICE, AUTH challenge).     |
| Reply slots      | `oneshot::Sender<Result<…>>`         | Per-command reply, cancelled if the actor exits (surfaces as `Error::Shutdown`).       |

Subscription event streams are **not** in the notification channel: each subscription gets its own `mpsc::UnboundedSender<SubscriptionItem>`, so callers consume the events from the `SubscriptionHandle` directly. Routing wrong-subscription events is structurally impossible because the actor matches on `subscription_id` before sending.

### Lifecycle and shutdown

- `Inner::Drop` (the moment the last `Relay` clone goes out of scope) fires `Command::Shutdown`. The actor breaks its loop, transitions to `RelayStatus::Terminated`, and emits `RelayNotification::Shutdown` to any listener.
- The `JoinHandle` returned by `tokio::spawn` is intentionally **dropped at the spawn site** — tokio detaches the task on drop, which is exactly the lifecycle we want. The actor's exit path is driven entirely by `Command::Shutdown` (or `command_rx` closing because every `Sender` was dropped).
- The handle never `await`s on the actor's join: the public API is non-blocking on shutdown.

### Wakeup invariants

The `select!` arms cover every observable wakeup source. Each arm yields exactly one mutation; we never hold a `&mut state` across an `await`. Two timer arms are reconstructed every loop iteration:

- `next_reconnect` — fires when the configured [`ReconnectPolicy`] schedules a retry.
- `next_publish_timeout` — fires at the earliest pending-publish deadline. Without this, an idle actor would never re-run `expire_pending_publishes` and `Relay::publish` would deadlock if the relay never replied with `OK`. The timer is a `Pin<Box<dyn Future<Output = ()> + Send>>` constructed via `tokio::time::sleep_until` (an absolute, cancel-safe deadline), or `std::future::pending()` when no deadline is armed.

Both timers re-evaluate on every loop turn, which is correct because `sleep_until` keys off an absolute deadline that survives loop iterations.

### What we explicitly rejected

- **Mutex on every field.** Forces locks across awaits, encourages partial state, and degrades clippy ergonomics on the hot path.
- **Broadcast channel for notifications.** Lossy on slow consumers — we never want to silently drop a `NOTICE` or NIP-42 `AUTH` challenge.
- **Public access to the actor's `JoinHandle`.** Exposes a footgun (handle leak, blocking shutdown). Detaching is the documented behaviour; callers that need cooperative shutdown call `Relay::disconnect` first.
- **Manual `Pin`-projected `Either<L, R>`.** Required `unsafe`, conflicting with the workspace's `forbid(unsafe_code)` posture. A `Pin<Box<dyn Future + Send>>` per arm is one allocation per loop iteration — negligible compared to the WebSocket I/O dominating the path.
- **Per-relay queueing of publishes during disconnect.** That belongs in `nula-relay-pool` where retries can use a different healthy endpoint. Keeping `nula-relay` honest about a downed connection (return `Error::NotConnected`) makes the pool layer's job tractable.

## Consequences

**Positive.**

- Single-task invariant enforced by the borrow checker; no run-time aliasing of `ActorState` is possible.
- Clean drop semantics — the last `Relay` clone shuts the actor down, no manual `close()` to forget.
- Observability is straightforward: every `select!` arm is a documented wakeup source and the actor never busy-loops.
- Cancellation safety: every awaited future is cancel-safe (`mpsc::recv`, `oneshot::recv`, `Stream::next` for tokio-tungstenite, `sleep_until`). Reconstructing the timer arms each loop preserves their absolute deadlines.

**Negative.**

- Public API now goes through channels — every operation costs at least one mpsc round-trip plus one oneshot reply. Latency is dominated by network I/O, so this is acceptable.
- Two `Pin<Box<dyn Future>>` allocations per loop iteration. Profiling has not shown them on the hot path; we will revisit if benchmarks change that.
- Tokio-only by construction; this is consistent with ADR-0003 and the broader workspace policy.

## Compliance

- The implementation lives in `crates/nula-relay/src/inner/`.
- Tests in `crates/nula-relay/tests/{lifecycle,subscribe,publish,nip42}.rs` exercise every public API path against `nula-net::mock::MockTransport`.
- Phase 2 retains every invariant above; no public method bypasses the actor.
