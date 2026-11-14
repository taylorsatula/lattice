//! Lattice simulator.
//!
//! A deterministic in-process mesh: virtual clock, seeded randomness, links
//! with latency/loss/reordering, partitions, crashes mid-custody, and adversarial
//! nodes. Every run is reproducible from its seed. Failures become regression
//! seeds, not assertions to weaken.
//!

#![forbid(unsafe_code)]
