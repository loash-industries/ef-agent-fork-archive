//! Decide whether an externally prepared transaction may be signed.
//!
//! Every conclusion here is drawn from the BCS transaction bytes. The builder's
//! JSON is read only so it can be contradicted: if the declared intent and the
//! decoded commands disagree, the builder is wrong or hostile and the payload
//! is refused either way. A verifier that trusted the JSON would inherit the
//! builder's authority, which is the one thing keeping the key out of the
//! builder is meant to prevent.

use std::collections::BTreeSet;
use std::str::FromStr;

use base64::Engine as _;
use sui_sdk_types::{Address, Argument, Command, Input, ProgrammableTransaction, TransactionKind};

use crate::error::VerifyError;
use crate::policy::SubmitPolicy;
use crate::prepared::PreparedTransaction;
use crate::target::MoveTarget;

/// A payload that satisfied the policy, carrying the decoded transaction so
/// the caller never has to parse the bytes a second time.
#[derive(Debug, Clone)]
pub struct VerifiedTransaction {
    /// The decoded transaction body, ready to be wrapped with gas data.
    pub kind: TransactionKind,
    /// The address that must sign, already confirmed to be ours.
    pub sender: Address,
    /// Move targets actually present in the bytes, in command order.
    pub targets: Vec<MoveTarget>,
}

/// Verify `prepared` against `policy` as of `now_ms` (Unix epoch milliseconds).
///
/// Time is a parameter rather than read from the clock so callers can test the
/// freshness boundary exactly.
pub fn verify(
    prepared: &PreparedTransaction,
    policy: &SubmitPolicy,
    now_ms: u64,
) -> Result<VerifiedTransaction, VerifyError> {
    check_sender(prepared, policy)?;
    check_freshness(prepared, policy, now_ms)?;
    check_spend(prepared, policy)?;

    let kind = decode_kind(&prepared.tx_kind_bytes)?;
    let programmable = programmable_body(&kind)?;

    if programmable.commands.is_empty() {
        return Err(VerifyError::NoCommands);
    }
    if programmable.commands.len() > policy.max_commands {
        return Err(VerifyError::TooManyCommands {
            found: programmable.commands.len(),
            max: policy.max_commands,
        });
    }

    let targets = check_commands(programmable, policy)?;
    check_intent_matches_bytes(prepared, &targets)?;

    Ok(VerifiedTransaction {
        kind: kind.clone(),
        sender: policy.expected_sender,
        targets,
    })
}

/// The payload must have been prepared for us. A payload naming another sender
/// is not merely useless — signing it would attest to someone else's intent.
fn check_sender(prepared: &PreparedTransaction, policy: &SubmitPolicy) -> Result<(), VerifyError> {
    let declared =
        Address::from_str(&prepared.sender).map_err(|e| VerifyError::UnparseableSender {
            sender: prepared.sender.clone(),
            reason: e.to_string(),
        })?;
    if declared != policy.expected_sender {
        return Err(VerifyError::SenderMismatch {
            expected: policy.expected_sender.to_string(),
            found: declared.to_string(),
        });
    }
    Ok(())
}

/// Bound how long a prepared payload stays signable.
///
/// The builder pins object versions at build time, so holding two payloads over
/// the same owned objects invites equivocation. A short window is what keeps a
/// stale payload from being signed after the world moved on.
fn check_freshness(
    prepared: &PreparedTransaction,
    policy: &SubmitPolicy,
    now_ms: u64,
) -> Result<(), VerifyError> {
    let built = prepared.built_at_ms;
    let skew_ms = duration_ms(policy.max_clock_skew);
    if built > now_ms.saturating_add(skew_ms) {
        return Err(VerifyError::BuiltInFuture {
            built_at_ms: built,
            now_ms,
        });
    }
    let age_ms = now_ms.saturating_sub(built);
    let max_age_ms = duration_ms(policy.max_age);
    if age_ms > max_age_ms {
        return Err(VerifyError::Stale { age_ms, max_age_ms });
    }
    Ok(())
}

/// A declared spend must fall under a configured ceiling for its exact
/// kind/asset pair. An unrecognized kind is refused rather than ignored,
/// because ignoring it would silently waive the ceiling it describes.
///
/// **This check is weaker than the rest of this module and must not be read as
/// a spend bound.** Every other check here re-derives its facts from the
/// transaction bytes; this one cannot. Amounts live in `Pure` inputs whose
/// meaning depends on the callee's ABI, so deciding which argument is "the
/// amount" would require per-contract knowledge this crate does not have. A
/// hostile builder can therefore understate `worstCaseSpend` and pass.
///
/// What actually bounds loss is the target allowlist — a transaction can only
/// call functions the operator approved — together with whatever balance those
/// functions can reach. Treat this as a guard against an honest builder's
/// mistake, not against a dishonest one.
fn check_spend(prepared: &PreparedTransaction, policy: &SubmitPolicy) -> Result<(), VerifyError> {
    let Some(spend) = prepared.intent.worst_case_spend.as_ref() else {
        return Ok(());
    };
    let amount =
        u128::from_str(&spend.amount).map_err(|_| VerifyError::UnparseableSpendAmount {
            amount: spend.amount.clone(),
        })?;
    let Some(cap) = policy.spend_cap_for(&spend.kind, &spend.asset) else {
        return Err(VerifyError::SpendNotPermitted {
            kind: spend.kind.clone(),
            asset: spend.asset.clone(),
        });
    };
    if amount > cap.max_amount {
        return Err(VerifyError::SpendExceedsCap {
            asset: spend.asset.clone(),
            amount,
            max_amount: cap.max_amount,
        });
    }
    Ok(())
}

/// Decode base64 then BCS.
///
/// `bcs::from_bytes` refuses input with unconsumed trailing bytes, so a payload
/// cannot smuggle extra data past a transaction that decodes cleanly on its own.
fn decode_kind(tx_kind_bytes: &str) -> Result<TransactionKind, VerifyError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(tx_kind_bytes)
        .map_err(|e| VerifyError::Base64 {
            reason: e.to_string(),
        })?;
    if raw.is_empty() {
        return Err(VerifyError::EmptyTransaction);
    }
    bcs::from_bytes::<TransactionKind>(&raw).map_err(|e| VerifyError::Bcs {
        reason: e.to_string(),
    })
}

/// Only a user-submitted programmable transaction is signable.
///
/// The system variants (epoch change, consensus prologue, randomness, and the
/// privileged `ProgrammableSystemTransaction`) are validator-authored. An agent
/// key has no business attesting to one, so they are refused by name rather
/// than falling through to a generic check.
fn programmable_body(kind: &TransactionKind) -> Result<&ProgrammableTransaction, VerifyError> {
    match kind {
        TransactionKind::ProgrammableTransaction(pt) => Ok(pt),
        other => Err(VerifyError::UnsupportedTransactionKind {
            kind: describe_kind(other).to_string(),
        }),
    }
}

fn describe_kind(kind: &TransactionKind) -> &'static str {
    match kind {
        TransactionKind::ProgrammableTransaction(_) => "ProgrammableTransaction",
        TransactionKind::ProgrammableSystemTransaction(_) => "ProgrammableSystemTransaction",
        TransactionKind::ChangeEpoch(_) => "ChangeEpoch",
        TransactionKind::Genesis(_) => "Genesis",
        TransactionKind::ConsensusCommitPrologue(_) => "ConsensusCommitPrologue",
        TransactionKind::ConsensusCommitPrologueV2(_) => "ConsensusCommitPrologueV2",
        TransactionKind::ConsensusCommitPrologueV3(_) => "ConsensusCommitPrologueV3",
        TransactionKind::ConsensusCommitPrologueV4(_) => "ConsensusCommitPrologueV4",
        TransactionKind::AuthenticatorStateUpdate(_) => "AuthenticatorStateUpdate",
        TransactionKind::EndOfEpoch(_) => "EndOfEpoch",
        TransactionKind::RandomnessStateUpdate(_) => "RandomnessStateUpdate",
        // `TransactionKind` is `#[non_exhaustive]`: a variant added upstream
        // must be refused, not admitted by a permissive fallback.
        _ => "unrecognized",
    }
}

/// Walk every command, refusing anything not explicitly understood.
fn check_commands(
    pt: &ProgrammableTransaction,
    policy: &SubmitPolicy,
) -> Result<Vec<MoveTarget>, VerifyError> {
    let mut targets = Vec::new();
    for (index, command) in pt.commands.iter().enumerate() {
        match command {
            Command::MoveCall(call) => {
                let target = MoveTarget {
                    package: call.package,
                    module: call.module.to_string(),
                    function: call.function.to_string(),
                };
                if !policy.permits_target(&target) {
                    return Err(VerifyError::TargetNotAllowed {
                        index,
                        target: target.canonical(),
                    });
                }
                targets.push(target);
            }
            Command::TransferObjects(transfer) => {
                check_transfer_recipient(pt, &transfer.address, index, policy)?;
            }
            // Structural value plumbing. None of these can name a recipient or
            // introduce new code, so they need no allowlist of their own; where
            // the value ends up is decided by the MoveCall and TransferObjects
            // commands that are checked.
            Command::SplitCoins(_) | Command::MergeCoins(_) | Command::MakeMoveVector(_) => {}
            // Publishing or upgrading code under the agent's address is never
            // part of trading, and the blast radius is unbounded.
            Command::Publish(_) => {
                return Err(VerifyError::ForbiddenCommand {
                    index,
                    command: "Publish".to_string(),
                });
            }
            Command::Upgrade(_) => {
                return Err(VerifyError::ForbiddenCommand {
                    index,
                    command: "Upgrade".to_string(),
                });
            }
            // `Command` is `#[non_exhaustive]`; refuse what we cannot reason about.
            _ => {
                return Err(VerifyError::ForbiddenCommand {
                    index,
                    command: "unrecognized".to_string(),
                });
            }
        }
    }
    Ok(targets)
}

/// A `TransferObjects` recipient must be a literal equal to our own address.
///
/// This is the command that can hand an object to a third party. Allowing a
/// computed recipient would mean the destination depends on runtime results
/// that cannot be read from the bytes, so only a pure literal is accepted —
/// and only if it is us.
fn check_transfer_recipient(
    pt: &ProgrammableTransaction,
    recipient: &Argument,
    index: usize,
    policy: &SubmitPolicy,
) -> Result<(), VerifyError> {
    let Argument::Input(slot) = recipient else {
        return Err(VerifyError::ComputedTransferRecipient { index });
    };
    let input = pt
        .inputs
        .get(usize::from(*slot))
        .ok_or(VerifyError::InputOutOfRange { index, slot: *slot })?;
    let Input::Pure(bytes) = input else {
        return Err(VerifyError::ComputedTransferRecipient { index });
    };
    let address = bcs::from_bytes::<Address>(bytes)
        .map_err(|_| VerifyError::UnreadableTransferRecipient { index })?;
    if address != policy.expected_sender {
        return Err(VerifyError::TransferToThirdParty {
            index,
            recipient: address.to_string(),
        });
    }
    Ok(())
}

/// The declared targets must be exactly the Move calls found in the bytes.
///
/// The allowlist has already passed at this point, so this cannot admit
/// anything new. What it catches is a builder whose description of its own work
/// is wrong — a signal to stop dealing with that builder, not to sign anyway.
fn check_intent_matches_bytes(
    prepared: &PreparedTransaction,
    decoded: &[MoveTarget],
) -> Result<(), VerifyError> {
    let mut declared = BTreeSet::new();
    for raw in &prepared.intent.targets {
        let parsed =
            MoveTarget::from_str(raw).map_err(|e| VerifyError::UnparseableDeclaredTarget {
                target: raw.clone(),
                reason: e.to_string(),
            })?;
        declared.insert(parsed.canonical());
    }
    let found: BTreeSet<String> = decoded.iter().map(MoveTarget::canonical).collect();
    if declared != found {
        return Err(VerifyError::IntentMismatch {
            declared: declared.into_iter().collect(),
            found: found.into_iter().collect(),
        });
    }
    Ok(())
}

/// Saturating millisecond conversion; a policy duration never legitimately
/// approaches `u64::MAX`, and saturating avoids a panic path.
fn duration_ms(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
