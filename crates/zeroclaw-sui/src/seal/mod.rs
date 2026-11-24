//! Seal / Keyspace decryption.
//!
//! A Keyspace entry is encrypted under Seal's threshold IBE scheme. Reading one
//! takes three things: a wallet signature over a session message, a
//! `seal_approve` programmable transaction the key servers dry-run against the
//! on-chain ACL, and then BLS12-381 work to turn the returned shares into
//! plaintext.
//!
//! The first of those lives here, because it is the part that commits this
//! agent's wallet key — see [`session`]. The last lives in the out-of-workspace
//! `seal-decrypt` binary, because it needs `fastcrypto`, whose dependency tree
//! cannot enter the graph that signs transactions without weakening
//! `deny.toml`. Nothing in this crate or that binary runs a key server; both are
//! clients of Mysten-operated infrastructure.

pub mod approve;
pub mod session;

pub use approve::{
    EncryptedHeader, SharedObject, build_seal_approve, build_seal_approve_bytes,
    parse_encrypted_header,
};
pub use session::{
    SealSession, SessionClaims, session_message, validate_proposed_session_message,
    validate_session_message,
};

/// Why a Seal operation stopped.
///
/// Variants that name the session message are refusals to *sign*, and are the
/// security-relevant ones: they are what keeps a narrow, verifiable signing
/// capability from becoming a general "sign this text" oracle.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    #[error("could not generate a session key: {reason}")]
    Entropy { reason: String },
    #[error("a session lifetime of zero minutes would already be expired")]
    SessionTtlZero,
    #[error(
        "message requests a {requested}-minute session but this agent signs for at most {max}; \
         refusing to sign"
    )]
    SessionTtlTooLong { requested: u16, max: u16 },
    #[error("creation time {creation_time_ms}ms is not a representable timestamp")]
    TimestampRange { creation_time_ms: u64 },
    #[error(
        "refusing to sign: this is not a Seal session message. A wallet signature is only ever \
         given for the exact session template, never for arbitrary text. Message was: {message:?}"
    )]
    MessageNotASession { message: String },
    #[error(
        "message authorises package `{found}` but this agent is configured for `{expected}`; \
         refusing to sign"
    )]
    MessageForOtherPackage { found: String, expected: String },
    #[error(
        "message is dated {creation_secs} but now is {now_secs}; refusing to sign a session \
         message that was not minted just now"
    )]
    MessageNotFresh { creation_secs: i64, now_secs: i64 },
    #[error("message authorises session key `{found}`, which this agent did not generate")]
    MessageForOtherSessionKey { found: String },
    #[error("the encrypted entry ended before its header did")]
    CiphertextTruncated,
    #[error("the encrypted entry's header is malformed")]
    CiphertextMalformed,
    #[error(
        "entry was encrypted under package `{found}` but this agent is configured for \
         `{expected}`; refusing to request keys for it"
    )]
    CiphertextForOtherPackage { found: String, expected: String },
    #[error("could not encode the seal_approve transaction: {reason}")]
    PtbEncoding { reason: String },
}
