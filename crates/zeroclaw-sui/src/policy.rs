//! What the agent is willing to sign.
//!
//! The policy is default-closed in every dimension that matters: an empty
//! target allowlist admits nothing, an unlisted asset admits no spend, and an
//! unrecognized spend kind is a refusal rather than a shrug.

use std::time::Duration;

use sui_sdk_types::Address;

use crate::target::MoveTarget;

/// A ceiling on how much of one asset a single transaction may commit.
///
/// Applied to the *builder's declared* worst case, which unlike every other
/// rule here cannot be re-derived from the transaction bytes. See
/// [`crate::verify`]'s spend check for why, and do not rely on this as a bound
/// against a hostile builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendCap {
    /// Matches `WorstCaseSpend::kind`, e.g. `currency`.
    pub kind: String,
    /// Matches `WorstCaseSpend::asset`, e.g. `CRED`.
    pub asset: String,
    /// Inclusive maximum, in the asset's base units.
    pub max_amount: u128,
}

/// The rules a prepared transaction must satisfy before the agent signs it.
#[derive(Debug, Clone)]
pub struct SubmitPolicy {
    /// The agent's own address. A payload prepared for anyone else is refused.
    pub expected_sender: Address,
    /// Move calls the agent may make. Empty means the agent signs nothing.
    pub allowed_targets: Vec<MoveTarget>,
    /// How long after preparation a payload stays signable.
    pub max_age: Duration,
    /// Tolerance for a builder clock running ahead of ours.
    pub max_clock_skew: Duration,
    /// Per-asset spend ceilings. An asset with no entry may not be spent.
    pub spend_caps: Vec<SpendCap>,
    /// Upper bound on commands in one transaction, to bound review cost.
    pub max_commands: usize,
}

impl SubmitPolicy {
    /// A policy that refuses everything, for the agent's own address.
    ///
    /// This is the intended starting point: callers widen it deliberately,
    /// rather than narrowing something permissive and hoping they caught
    /// every case.
    pub fn deny_all(expected_sender: Address) -> Self {
        Self {
            expected_sender,
            allowed_targets: Vec::new(),
            max_age: Duration::from_secs(60),
            max_clock_skew: Duration::from_secs(5),
            spend_caps: Vec::new(),
            max_commands: 16,
        }
    }

    /// Permit a Move target. Accepts any package spelling; stored canonically.
    pub fn allow_target(mut self, target: MoveTarget) -> Self {
        if !self.allowed_targets.contains(&target) {
            self.allowed_targets.push(target);
        }
        self
    }

    /// Permit spending up to `max_amount` base units of one asset.
    pub fn allow_spend(
        mut self,
        kind: impl Into<String>,
        asset: impl Into<String>,
        max_amount: u128,
    ) -> Self {
        self.spend_caps.push(SpendCap {
            kind: kind.into(),
            asset: asset.into(),
            max_amount,
        });
        self
    }

    /// Replace the freshness window.
    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }

    /// Whether this exact target is permitted.
    pub fn permits_target(&self, target: &MoveTarget) -> bool {
        self.allowed_targets.contains(target)
    }

    /// The cap covering this `kind`/`asset` pair, if one is configured.
    pub fn spend_cap_for(&self, kind: &str, asset: &str) -> Option<&SpendCap> {
        self.spend_caps
            .iter()
            .find(|cap| cap.kind == kind && cap.asset == asset)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn addr() -> Address {
        Address::from_str("0x1111111111111111111111111111111111111111111111111111111111111111")
            .expect("valid address")
    }

    #[test]
    fn deny_all_permits_nothing() {
        let policy = SubmitPolicy::deny_all(addr());
        let target: MoveTarget = "0x2::coin::zero".parse().expect("parses");
        assert!(!policy.permits_target(&target));
        assert!(policy.spend_cap_for("currency", "CRED").is_none());
    }

    #[test]
    fn allowing_a_short_form_target_permits_its_canonical_form() {
        let policy =
            SubmitPolicy::deny_all(addr()).allow_target("0x2::coin::zero".parse().expect("parses"));
        let canonical: MoveTarget =
            "0x0000000000000000000000000000000000000000000000000000000000000002::coin::zero"
                .parse()
                .expect("parses");
        assert!(policy.permits_target(&canonical));
    }

    #[test]
    fn allowing_one_target_does_not_permit_a_sibling_function() {
        let policy =
            SubmitPolicy::deny_all(addr()).allow_target("0x2::coin::zero".parse().expect("parses"));
        let sibling: MoveTarget = "0x2::coin::mint".parse().expect("parses");
        assert!(!policy.permits_target(&sibling));
    }

    #[test]
    fn spend_caps_are_keyed_on_both_kind_and_asset() {
        let policy = SubmitPolicy::deny_all(addr()).allow_spend("currency", "CRED", 1_000);
        assert!(policy.spend_cap_for("currency", "CRED").is_some());
        assert!(policy.spend_cap_for("currency", "SUI").is_none());
        assert!(policy.spend_cap_for("items", "CRED").is_none());
    }

    #[test]
    fn allow_target_is_idempotent() {
        let policy = SubmitPolicy::deny_all(addr())
            .allow_target("0x2::coin::zero".parse().expect("parses"))
            .allow_target("0x2::coin::zero".parse().expect("parses"));
        assert_eq!(policy.allowed_targets.len(), 1);
    }
}
