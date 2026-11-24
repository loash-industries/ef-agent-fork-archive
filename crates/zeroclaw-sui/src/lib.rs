//! Sui transaction verification for ZeroClaw.
//!
//! ZeroClaw agents obtain transactions from builders that deliberately hold no
//! key: the builder assembles a programmable transaction and returns it
//! unsigned, and the agent decides whether to commit its key to it. That split
//! only buys safety if the deciding half re-derives its facts from the
//! transaction bytes, so this crate treats the builder's own description as a
//! claim to be checked rather than as information.
//!
//! ```no_run
//! use std::str::FromStr;
//! use sui_sdk_types::Address;
//! use zeroclaw_sui::{PreparedTransaction, SubmitPolicy, verify};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let me = Address::from_str(
//!     "0x1111111111111111111111111111111111111111111111111111111111111111",
//! )?;
//! let policy = SubmitPolicy::deny_all(me).allow_target("0x2::coin::zero".parse()?);
//!
//! let prepared = PreparedTransaction::from_json(r#"{ "...": "from the builder" }"#)?;
//! let verified = verify(&prepared, &policy, 1_789_000_000_000)?;
//! // `verified.kind` is now safe to wrap with gas data and sign.
//! # Ok(())
//! # }
//! ```

pub mod error;
pub mod gas_station;
pub mod policy;
pub mod prepared;
pub mod rpc;
pub mod seal;
pub mod signer;
pub mod submit;
pub mod target;
pub mod verify;

// Re-exported because it is unavoidable in this crate's public API:
// `SubmitPolicy::deny_all` takes one, so a caller cannot use the crate without
// naming the type.
pub use sui_sdk_types::Address;

pub use error::VerifyError;
pub use gas_station::{ExecutionOutcome, GasReservation, GasStation, GasStationError};
pub use policy::SubmitPolicy;
pub use prepared::{PinnedObject, PreparedIntent, PreparedTransaction, WorstCaseSpend};
pub use rpc::{RpcError, SuiRpc};
pub use seal::{
    EncryptedHeader, SealError, SealSession, SessionClaims, SharedObject, build_seal_approve,
    build_seal_approve_bytes, parse_encrypted_header, validate_proposed_session_message,
    validate_session_message,
};
pub use signer::{AgentSigner, SignerError};
pub use submit::{SubmitError, SubmitRequest, Submitted, submit};
pub use target::{MoveTarget, TargetParseError};
pub use verify::{VerifiedTransaction, verify};
