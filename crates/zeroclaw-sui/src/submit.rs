//! Verify, reserve, sign, submit — in that order.
//!
//! The ordering is a safety property, not a style choice. Local verification
//! runs before the transaction is shown to anyone, so a payload that was never
//! going to be signed is not sent off-box. Signing runs after the reservation,
//! because the signature commits to the gas payment and a transaction cannot be
//! re-gassed once signed.
//!
//! The signer-api decides the gas budget itself, which means the amount is not
//! ours to choose — only to refuse. `max_gas_budget` is that refusal: a budget
//! larger than the operator sanctioned stops the submission before signing.

use sui_sdk_types::{GasPayment, Transaction, TransactionExpiration};

use crate::error::VerifyError;
use crate::gas_station::{ExecutionOutcome, GasStation, GasStationError};
use crate::policy::SubmitPolicy;
use crate::prepared::PreparedTransaction;
use crate::signer::{AgentSigner, SignerError};
use crate::target::MoveTarget;
use crate::verify::verify;

/// Why a submission did not happen. Each variant names the stage that stopped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SubmitError {
    #[error("refused before signing: {0}")]
    Verify(#[from] VerifyError),
    #[error(
        "configured key signs for `{signer}` but the policy expects `{expected}`; \
         refusing to sign for an address this agent does not control"
    )]
    SignerAddressMismatch { signer: String, expected: String },
    #[error("gas station: {0}")]
    GasStation(#[from] GasStationError),
    #[error(
        "sponsor set a gas budget of {budget} MIST, above the configured ceiling \
         of {max} MIST; refusing to sign"
    )]
    GasBudgetTooHigh { budget: u64, max: u64 },
    #[error("signing: {0}")]
    Signer(#[from] SignerError),
}

/// Everything a single submission needs beyond the key and the station.
#[derive(Debug, Clone)]
pub struct SubmitRequest<'a> {
    /// The unsigned payload from the builder.
    pub prepared: &'a PreparedTransaction,
    /// What this agent is willing to sign.
    pub policy: &'a SubmitPolicy,
    /// Ceiling on the gas budget the sponsor may set, in MIST. The sponsor
    /// chooses the actual budget; this only bounds what will be signed.
    pub max_gas_budget: u64,
    /// The network's reference gas price. The reservation does not supply this,
    /// so the caller reads it from the chain; a stale value is rejected by
    /// validators rather than silently repriced.
    pub gas_price: u64,
    /// Current time, Unix epoch milliseconds, used for the freshness check.
    pub now_ms: u64,
}

/// A transaction that reached the network.
#[derive(Debug, Clone)]
pub struct Submitted {
    /// What the service reported back, including the on-chain digest.
    pub outcome: ExecutionOutcome,
    /// The Move calls that were actually signed for, read from the bytes.
    pub targets: Vec<MoveTarget>,
    /// The reservation the gas was drawn from.
    pub reservation_id: u64,
    /// The budget the sponsor set and this agent accepted.
    pub gas_budget: u64,
}

/// Run the full commit path for one prepared transaction.
pub async fn submit(
    request: SubmitRequest<'_>,
    signer: &AgentSigner,
    station: &GasStation,
) -> Result<Submitted, SubmitError> {
    // The key and the policy must agree about who this agent is before
    // anything else happens. A mismatch means the deployment is misconfigured,
    // and every later check would reason about the wrong identity.
    let signer_address = signer.address();
    if signer_address != request.policy.expected_sender {
        return Err(SubmitError::SignerAddressMismatch {
            signer: signer_address.to_string(),
            expected: request.policy.expected_sender.to_string(),
        });
    }

    let verified = verify(request.prepared, request.policy, request.now_ms)?;

    // The sponsor validates the commands before funding them, so it has to see
    // the transaction first. Gas is a placeholder here; the real values arrive
    // in the reservation and are set below.
    let unsigned = Transaction {
        kind: verified.kind.clone(),
        sender: verified.sender,
        gas_payment: GasPayment {
            objects: Vec::new(),
            owner: verified.sender,
            price: request.gas_price,
            budget: 0,
        },
        expiration: TransactionExpiration::None,
    };
    let reservation = station.reserve(&unsigned).await?;

    // The sponsor's budget is accepted or the submission stops. Signing a
    // larger budget than the operator sanctioned would let a compromised or
    // misconfigured sponsor drain the daily allowance on one transaction.
    if reservation.gas_budget > request.max_gas_budget {
        return Err(SubmitError::GasBudgetTooHigh {
            budget: reservation.gas_budget,
            max: request.max_gas_budget,
        });
    }

    let transaction = Transaction {
        kind: verified.kind,
        sender: verified.sender,
        gas_payment: GasPayment {
            objects: reservation.gas_coins,
            owner: reservation.sponsor,
            price: request.gas_price,
            budget: reservation.gas_budget,
        },
        // The reservation window already bounds how long this is submittable,
        // and an epoch bound would add a second expiry to keep in step with it.
        expiration: TransactionExpiration::None,
    };

    let signature = signer.sign_transaction(&transaction)?;
    let outcome = station
        .execute(reservation.reservation_id, &transaction, &signature)
        .await?;

    Ok(Submitted {
        outcome,
        targets: verified.targets,
        reservation_id: reservation.reservation_id,
        gas_budget: reservation.gas_budget,
    })
}
