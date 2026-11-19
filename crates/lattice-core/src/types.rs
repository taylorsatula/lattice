//! Public types for the core: events, actions, config, identity.
//!
//! All timestamps in events and in the core's public API are milliseconds
//! since the Unix epoch. The wire format and the store keep Unix seconds;
//! conversions happen at those boundaries. `AppSend::exp` is the one
//! exception: it is a wire time (Unix seconds), matching the local API.

use lattice_proto::record::Mode;
use lattice_types::{DeliveryId, Identifier, MessageId, X25519PublicKey};

/// Link identifier assigned by the transport (simulator or sockets layer).
pub type LinkId = u64;

/// A non-fatal internal failure observed by the sans-IO core.
///
/// The core cannot log and cannot act on these itself; the caller (daemon
/// or simulator) drains them from [`crate::Node::handle`] and decides how
/// to surface them. A diagnostic means "the node kept going, but something
/// it tried to do did not happen" — e.g. a store write was lost. The node
/// never silently drops a store failure without either reporting it here
/// or carrying a comment explaining why dropping is correct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    /// Static tag naming the operation that failed (e.g. `"outbound_put"`).
    pub op: &'static str,
    /// The underlying error, rendered.
    pub detail: String,
}

#[derive(Clone, Debug)]
pub struct AppSend {
    /// Service making the request (must match an authenticated service at the API edge).
    pub service: String,
    pub mid_hint: Option<MessageId>,
    pub to: Identifier,
    pub tsvc: String,
    pub tmbx: Vec<u8>,
    pub fmbx: Vec<u8>,
    pub body: Vec<u8>,
    /// Expiry as Unix seconds (wire time), as accepted by the local API.
    pub exp: Option<u64>,
    pub priority: u8,
    /// 0 = default (share decides), 1 = waypoint, 2 = direct.
    pub route: u8,
}

#[derive(Clone, Debug)]
pub enum Event {
    LinkUp {
        at: u64,
        link: LinkId,
        peer: Option<Identifier>,
        remote_ck: X25519PublicKey,
    },
    LinkDown {
        at: u64,
        link: LinkId,
    },
    Frame {
        at: u64,
        link: LinkId,
        frame: lattice_proto::frames::Frame,
        /// Bucket index (0-3) of the wire frame as received, if known.
        /// The transport knows the wire length; the core does not. Used
        /// to answer an echo request in the same bucket (spec §6, snow).
        /// `None` for synthetic frames; the core falls back to a sampled
        /// bucket.
        bucket: Option<usize>,
    },
    /// Wake the core. Delivered by the caller at the instant reported by
    /// [`crate::Node::next_deadline`] (or earlier, which is always safe).
    Tick {
        at: u64,
    },
    AppSend(AppSend),
    AppAck {
        service: String,
        delivery_ids: Vec<DeliveryId>,
        at: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Send a frame on a link (padding applied by the transport).
    /// `pad_to` requests a specific FRAME_BUCKETS index (see
    /// `lattice_net::FRAME_BUCKETS`) for the wire padding (snow dummies
    /// must land in a sampled bucket); `None` lets the transport pick the
    /// smallest fitting bucket.
    SendFrame {
        link: LinkId,
        frame: lattice_proto::frames::Frame,
        pad_to: Option<usize>,
    },
    /// Hand a delivery to the application.
    Deliver {
        service: String,
        delivery_id: DeliveryId,
        mid: MessageId,
        from: Identifier,
        fsvc: String,
        fmbx: Vec<u8>,
        tmbx: Vec<u8>,
        body: Vec<u8>,
        /// Unix seconds (as stored and as reported on the local API).
        received: u64,
    },
    /// Status transition for a message this node originated (or accepted).
    /// `service` is the originating service, so the daemon can route the
    /// event to the right application connection.
    Status {
        mid: MessageId,
        status: u64,
        detail: Option<u64>,
        service: String,
    },
    /// Number of unfetched deliveries for a service changed.
    Inbox { service: String, unread: u64 },
    /// A link's binding to a peer changed (or was cleared). Emitted when
    /// the core (re)derives a link's attribution — on link-up, on a record
    /// admission or claim sweep — so the runtime can keep its link table in
    /// sync. `peer: None` means the binding was cleared (contested or
    /// lost); the link itself is still up.
    LinkBound {
        link: LinkId,
        peer: Option<Identifier>,
    },
}

#[derive(Clone, Debug)]
pub struct Config {
    pub snow_per_min: f64,
    pub echo_share: f64,
    pub sideways_prob: f64,
    pub waypoint_share: f64,
    pub receipt_timeout_public: u64,
    pub receipt_timeout_private: u64,
    /// Per-destination custody allowance, shared across upstream links, bytes.
    pub custody_allowance: u64,
    /// Total transit storage cap, bytes.
    pub transit_cap: u64,
    /// Per-service inbox cap, deliveries.
    pub inbox_max_deliveries: u64,
    /// Global inbox cap across all services, deliveries. Bounds total
    /// undelivered storage regardless of how senders label `tsvc`.
    pub inbox_max_total: u64,
    /// Daily record refresh interval, in seconds (spec §3; jittered ±10%).
    pub record_refresh_secs: u64,
    /// Minimum seconds between record publishes (spec §3: 2 minutes).
    /// 0 disables the floor (publish on every advertised-set change).
    /// Defaults to 0 because the convergence tests (simulator, end-to-end)
    /// require records to propagate in seconds; set to 120 to enforce the
    /// spec's spacing. The mechanism is enforced whenever non-zero.
    pub republish_min_interval_secs: u64,
    pub reconcile_interval_secs: u64,
    pub buffer_classes: u8,
    pub retry_base_secs: u64,
    pub retry_max_secs: u64,
    pub fresh_waypoint_retries: u32,
    pub default_message_horizon: u64,
    pub rng_seed: u64,
    /// Endpoints to publish in our record (public mode). `ws://` or `wss://` URLs.
    pub advertise: Vec<String>,
    /// Literal IP addresses advertised in the record's endpoints (public
    /// mode). Useful when the host has no stable DNS name; connecting
    /// nodes prefer these over resolving the URL's host.
    pub advertise_ips: Vec<std::net::IpAddr>,
    /// Gateway node ids for a private node's record (1-3, private mode only).
    pub gateways: Vec<Identifier>,
    /// Public or private record mode.
    pub mode: Mode,
    /// Names of the services this node serves. A message addressed to any
    /// other service is accepted into custody but never stored or delivered;
    /// the sender gets a negative receipt (reason 1).
    pub services: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            snow_per_min: 2.0,
            echo_share: 0.25,
            sideways_prob: 0.15,
            waypoint_share: 0.0,
            receipt_timeout_public: 15 * 60,
            receipt_timeout_private: 12 * 3600,
            custody_allowance: 4 * 1024 * 1024,
            transit_cap: 256 * 1024 * 1024,
            inbox_max_deliveries: 1024,
            inbox_max_total: 4096,
            record_refresh_secs: 86_400,
            republish_min_interval_secs: 0,
            reconcile_interval_secs: 60,
            buffer_classes: 16,
            retry_base_secs: 30,
            retry_max_secs: 30 * 60,
            fresh_waypoint_retries: 3,
            default_message_horizon: 3 * 24 * 3600,
            rng_seed: 0x5eed_u64,
            advertise: Vec::new(),
            advertise_ips: Vec::new(),
            gateways: Vec::new(),
            mode: Mode::Public,
            services: Vec::new(),
        }
    }
}

// Failure/detail codes used in Status actions (detail field). This is a
// separate namespace from the `ERR_*` codes in lattice-proto::local (1-6,
// local-API response codes); these are carried in Status event details.
// The two families share no values and must not be mixed.
pub const ERR_NO_RECORD: u64 = 100;
pub const ERR_NO_ROUTE: u64 = 101;
pub const ERR_INTERNAL: u64 = 102;
pub const ERR_REFUSED: u64 = 103;
pub const ERR_EXPIRED: u64 = 104;
