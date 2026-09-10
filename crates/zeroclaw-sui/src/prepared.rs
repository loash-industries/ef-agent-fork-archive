//! The wire payload produced by a keyless transaction builder.
//!
//! An external service (today: the Trinary Exchange MCP server) constructs a
//! programmable transaction and returns it *unsigned*. This module models that
//! response. Nothing here is trusted: the fields exist so they can be
//! cross-checked against the transaction bytes, not so they can be believed.

use serde::Deserialize;

/// An unsigned transaction handed to us by a builder that holds no key.
///
/// Unknown fields are tolerated on purpose. Every security decision is made by
/// decoding [`Self::tx_kind_bytes`], so an additive change upstream cannot
/// weaken verification — but rejecting new fields would break the agent for no
/// safety gain.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedTransaction {
    /// Base64-encoded BCS `TransactionKind`, as produced by building with
    /// `onlyTransactionKind: true`. This is the only authoritative field.
    pub tx_kind_bytes: String,
    /// Address the builder assumed would sign. Checked against our own
    /// address; never used to decide *who* signs.
    pub sender: String,
    /// The builder's own claim about what it built.
    pub intent: PreparedIntent,
    /// Object versions this build resolved against.
    #[serde(default)]
    pub pinned_objects: Vec<PinnedObject>,
    /// Unix epoch milliseconds at which the builder assembled this payload.
    pub built_at_ms: u64,
    /// Human-readable guidance from the builder. Advisory only.
    #[serde(default)]
    pub notes: Vec<String>,
}

/// The builder's declared intent. Treated as a claim to be falsified against
/// the decoded transaction, never as a description to be trusted.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedIntent {
    /// Short action label, e.g. `create_account`.
    pub action: String,
    /// Fully-qualified Move targets the builder claims it called.
    #[serde(default)]
    pub targets: Vec<String>,
    /// Action-specific arguments, echoed back for the caller's benefit.
    #[serde(default)]
    pub params: serde_json::Value,
    /// Upper bound on value this transaction can move, when the action spends.
    /// Absent for actions that cannot spend (e.g. cancelling an order).
    #[serde(default)]
    pub worst_case_spend: Option<WorstCaseSpend>,
}

/// A declared ceiling on what a transaction may spend.
///
/// `kind` is deliberately a string rather than an enum: only `currency` has
/// been observed in the wild, and an unrecognized kind must be rejected by
/// policy rather than fail to deserialize, so the failure is a clear refusal
/// instead of a parse error.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorstCaseSpend {
    /// Discriminator for how to read `asset`, e.g. `currency`.
    pub kind: String,
    /// Asset symbol, e.g. `CRED`.
    pub asset: String,
    /// Base-unit amount, as a decimal string to survive u64 range in JSON.
    pub amount: String,
}

/// An object version the builder resolved while assembling the transaction.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinnedObject {
    pub object_id: String,
    pub version: String,
    pub kind: String,
}

impl PreparedTransaction {
    /// Parse a prepared payload from the JSON text a builder returned.
    pub fn from_json(raw: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(raw)
    }
}
