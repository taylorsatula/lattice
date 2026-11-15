//! Transition rules for [`OutboundState`], kept in one place.
//!
//! `OutboundState` is persisted via serde (see `lattice-store`) and the
//! on-disk representation is unchanged. These methods encode the legal
//! predecessors of each transition so the call sites in `node.rs` cannot
//! silently write an illegal one. Terminal states (`Delivered`, `Failed`,
//! `Expired`) are absorbing: nothing transitions out of them.
//!
//! The methods live on an extension trait rather than on the enum because
//! the type is owned by `lattice-store`; lattice-core cannot add inherent
//! impls. Each returns `false` (leaving the message untouched) when the
//! current state is not a legal predecessor.

use lattice_store::{OutboundMessage, OutboundState};

/// State queries on the persisted state enum.
pub(crate) trait OutboundStateExt {
    /// True for `Delivered`, `Failed`, `Expired` — the absorbing states.
    #[must_use]
    fn is_terminal(&self) -> bool;
}

impl OutboundStateExt for OutboundState {
    fn is_terminal(&self) -> bool {
        matches!(
            self,
            OutboundState::Delivered | OutboundState::Failed | OutboundState::Expired
        )
    }
}

/// Transitions on an [`OutboundMessage`]. Each returns `false` and leaves
/// the message untouched when the current state is terminal.
pub(crate) trait OutboundMessageExt {
    /// `Queued | InFlight -> InFlight`.
    fn mark_in_flight(&mut self) -> bool;
    /// `Queued | InFlight -> Queued`, setting `next_attempt`.
    fn requeue(&mut self, next_attempt: u64) -> bool;
    /// `Queued | InFlight -> Failed`.
    fn mark_failed(&mut self) -> bool;
    /// `Queued | InFlight -> Expired`.
    fn mark_expired(&mut self) -> bool;
    /// `Queued | InFlight -> Delivered`.
    fn mark_delivered(&mut self) -> bool;
}

impl OutboundMessageExt for OutboundMessage {
    fn mark_in_flight(&mut self) -> bool {
        transition_to(self, OutboundState::InFlight)
    }

    fn requeue(&mut self, next_attempt: u64) -> bool {
        if !transition_to(self, OutboundState::Queued) {
            return false;
        }
        self.next_attempt = next_attempt;
        true
    }

    fn mark_failed(&mut self) -> bool {
        transition_to(self, OutboundState::Failed)
    }

    fn mark_expired(&mut self) -> bool {
        transition_to(self, OutboundState::Expired)
    }

    fn mark_delivered(&mut self) -> bool {
        transition_to(self, OutboundState::Delivered)
    }
}

fn transition_to(msg: &mut OutboundMessage, to: OutboundState) -> bool {
    if msg.state.is_terminal() {
        return false;
    }
    msg.state = to;
    true
}
