//! Pure-Rust DSP pipeline: sweep, identify, demod. Source-free — operates on
//! `SampleBlock` data, exhaustively testable with no I/O.

pub mod demod;
pub mod identify;
pub mod sweep;
