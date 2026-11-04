//! ipping measurement node.
//!
//! The node dials the backend, receives typed tasks, validates them locally and answers with
//! structured results. It never executes commands it is sent.

pub mod policy;
pub mod protocol;
