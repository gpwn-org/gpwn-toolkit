//! Packet-capture analysis primitives used by the GPWN analyzer CLI and HTTP API.
//!
//! The reusable path starts with [`parser::Packet`] for rows emitted by the
//! crate's stable [`fields::FIELDS`] tshark schema. Feed packets to a
//! [`parser::Analyzer`], then call [`parser::Analyzer::publish`] to copy its
//! derived topology and events into a [`model::CaptureModel`]. For complete or
//! growing capture files, [`pipeline::analyze`] drives tshark and maintains a
//! shared model asynchronously.

/// Axum handlers for capture models, events, artifacts, and health checks.
pub mod api;
/// Validated favicon fetching, domain normalization, and in-memory caching.
pub mod favicon;
/// Stable ordered tshark field schema consumed by the parser.
pub mod fields;
/// Serializable capture topology, event, session, and artifact records.
pub mod model;
/// Incremental tshark row parsing and protocol event detection.
pub mod parser;
/// Capture-file and growing-file tshark orchestration.
pub mod pipeline;
