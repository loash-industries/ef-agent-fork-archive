//! Refusal reasons.
//!
//! Each variant names one specific thing that was wrong, so an operator reading
//! a log can tell a stale payload from a hostile one without re-deriving the
//! check. Every variant is a refusal to sign; none is recoverable by retrying
//! the same payload.

/// Why a prepared transaction may not be signed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("prepared sender `{sender}` is not a valid Sui address: {reason}")]
    UnparseableSender { sender: String, reason: String },

    #[error("prepared for `{found}` but this agent signs as `{expected}`")]
    SenderMismatch { expected: String, found: String },

    #[error("prepared {age_ms}ms ago, which exceeds the {max_age_ms}ms freshness window")]
    Stale { age_ms: u64, max_age_ms: u64 },

    #[error("prepared at {built_at_ms} which is ahead of local time {now_ms}")]
    BuiltInFuture { built_at_ms: u64, now_ms: u64 },

    #[error("transaction bytes are not valid base64: {reason}")]
    Base64 { reason: String },

    #[error("transaction bytes are empty")]
    EmptyTransaction,

    #[error("transaction bytes are not a valid BCS TransactionKind: {reason}")]
    Bcs { reason: String },

    #[error("`{kind}` is not a user-signable transaction kind")]
    UnsupportedTransactionKind { kind: String },

    #[error("transaction contains no commands")]
    NoCommands,

    #[error("transaction has {found} commands, above the limit of {max}")]
    TooManyCommands { found: usize, max: usize },

    #[error("command {index} calls `{target}`, which is not on the allowlist")]
    TargetNotAllowed { index: usize, target: String },

    #[error("command {index} is `{command}`, which this agent never signs")]
    ForbiddenCommand { index: usize, command: String },

    #[error("command {index} transfers to a computed recipient rather than a literal address")]
    ComputedTransferRecipient { index: usize },

    #[error("command {index} references input slot {slot}, which does not exist")]
    InputOutOfRange { index: usize, slot: u16 },

    #[error("command {index} has a transfer recipient that is not a readable address")]
    UnreadableTransferRecipient { index: usize },

    #[error("command {index} transfers to `{recipient}`, which is not this agent")]
    TransferToThirdParty { index: usize, recipient: String },

    #[error("declared target `{target}` is unparseable: {reason}")]
    UnparseableDeclaredTarget { target: String, reason: String },

    #[error("declared targets {declared:?} do not match the calls in the bytes {found:?}")]
    IntentMismatch {
        declared: Vec<String>,
        found: Vec<String>,
    },
}
