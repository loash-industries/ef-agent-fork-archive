//! Verify, gas, sign, submit — in that order.
//!
//! The ordering is a safety property, not a style choice. Verification happens
//! before a reservation is taken, so a payload that was never going to be
//! signed does not consume the sponsor's coins. Signing happens after the
//! reservation, because the signature commits to the gas payment and a
//! transaction cannot be re-gassed once signed.

use std::time::Duration;

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
    #[error("gas station reserved no coins")]
    NoGasCoins,
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
    /// Gas budget, in MIST, to reserve and to record in the transaction.
    pub gas_budget: u64,
    /// The network's reference gas price. The reservation does not supply this,
    /// so the caller must read it from the chain; a stale value is rejected by
    /// validators rather than silently repriced.
    pub gas_price: u64,
    /// How long to hold the reservation. Keep it short.
    pub reserve_for: Duration,
    /// Current time, Unix epoch milliseconds, used for the freshness check.
    pub now_ms: u64,
}

/// A transaction that reached the network.
#[derive(Debug, Clone)]
pub struct Submitted {
    /// What the station reported back.
    pub outcome: ExecutionOutcome,
    /// The Move calls that were actually signed for, read from the bytes.
    pub targets: Vec<MoveTarget>,
    /// The reservation the gas was drawn from.
    pub reservation_id: u64,
}

/// Run the full commit path for one prepared transaction.
pub async fn submit(
    request: SubmitRequest<'_>,
    signer: &AgentSigner,
    station: &GasStation,
) -> Result<Submitted, SubmitError> {
    // The key and the policy must agree about who this agent is before
    // anything else happens. A mismatch here means the deployment is
    // misconfigured, and every later check would be reasoning about the wrong
    // identity.
    let signer_address = signer.address();
    if signer_address != request.policy.expected_sender {
        return Err(SubmitError::SignerAddressMismatch {
            signer: signer_address.to_string(),
            expected: request.policy.expected_sender.to_string(),
        });
    }

    let verified = verify(request.prepared, request.policy, request.now_ms)?;

    let reservation = station
        .reserve(request.gas_budget, request.reserve_for)
        .await?;
    if reservation.gas_coins.is_empty() {
        return Err(SubmitError::NoGasCoins);
    }

    let transaction = Transaction {
        kind: verified.kind,
        sender: verified.sender,
        gas_payment: GasPayment {
            objects: reservation.gas_coins,
            owner: reservation.sponsor,
            price: request.gas_price,
            budget: request.gas_budget,
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
    })
}
