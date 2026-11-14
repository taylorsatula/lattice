//! Public types for the core: events, actions, config, identity.

use lattice_proto::record::Mode;

/// Link identifier assigned by the transport (simulator or sockets layer).
pub type LinkId = u64;

#[derive(Clone, Debug)]
pub struct AppSend {
    /// Service making the request (must match an authenticated service at the API edge).
    pub service: String,
    pub mid_hint: Option<[u8; 16]>,
    pub to: [u8; 32],
    pub tsvc: String,
    pub tmbx: Vec<u8>,
    pub fmbx: Vec<u8>,
    pub body: Vec<u8>,
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
        peer: Option<[u8; 32]>,
        remote_ck: [u8; 32],
        wan: bool,
    },
    LinkDown {
        at: u64,
        link: LinkId,
    },
    Frame {
        at: u64,
        link: LinkId,
        from: [u8; 32],
        frame: lattice_proto::frames::Frame,
    },
    Tick {
        at: u64,
    },
    AppSend(AppSend),
    AppAck {
        service: String,
        delivery_ids: Vec<[u8; 16]>,
        at: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Send a frame on a link (padding applied by the transport).
    /// `pad_to` requests a specific FRAME_BUCKETS index for the wire
    /// padding (snow dummies must land in a sampled bucket); `None` lets the
    /// transport pick the smallest fitting bucket.
    SendFrame {
        link: LinkId,
        frame: lattice_proto::frames::Frame,
        pad_to: Option<usize>,
    },
    /// Hand a delivery to the application.
    Deliver {
        service: String,
        delivery_id: [u8; 16],
        mid: [u8; 16],
        from: [u8; 32],
        fsvc: String,
        fmbx: Vec<u8>,
        tmbx: Vec<u8>,
        body: Vec<u8>,
        received: u64,
    },
    /// Status transition for a message this node originated (or accepted).
    Status {
        mid: [u8; 16],
        status: u64,
        detail: Option<u64>,
    },
    /// Number of unfetched deliveries for a service changed.
    Inbox { service: String, unread: u64 },
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
    pub record_refresh_secs: u64,
    pub reconcile_interval_secs: u64,
    pub buffer_classes: u8,
    pub retry_base_secs: u64,
    pub retry_max_secs: u64,
    pub fresh_waypoint_retries: u32,
    pub wary_threshold: usize,
    pub wary_list_max: usize,
    pub default_message_horizon: u64,
    pub rng_seed: u64,
    /// Endpoints to publish in our record (public mode). `wss://host[:port]/` URLs.
    pub advertise: Vec<String>,
    /// Gateway node ids for a private node's record (1-3, private mode only).
    pub gateways: Vec<[u8; 32]>,
    /// Public or private record mode.
    pub mode: Mode,
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
            record_refresh_secs: 120,
            reconcile_interval_secs: 60,
            buffer_classes: 16,
            retry_base_secs: 30,
            retry_max_secs: 30 * 60,
            fresh_waypoint_retries: 3,
            wary_threshold: 3,
            wary_list_max: 32,
            default_message_horizon: 3 * 24 * 3600,
            rng_seed: 0x5eed_u64,
            advertise: Vec::new(),
            gateways: Vec::new(),
            mode: Mode::Public,
        }
    }
}

// Failure/detail codes used in Status actions (detail field).
pub const ERR_NO_RECORD: u64 = 100;
pub const ERR_NO_ROUTE: u64 = 101;
pub const ERR_INTERNAL: u64 = 102;
pub const ERR_REFUSED: u64 = 103;
pub const ERR_EXPIRED: u64 = 104;
