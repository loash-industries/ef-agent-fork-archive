//! Client for the Trinary Exchange signer-api sponsorship endpoints.
//!
//! The flow is inverted from a plain gas station: the service wants to see the
//! transaction *before* it will fund it. `reserve` takes the unsigned body,
//! validates its Move calls against a server-side allowlist, decides the gas
//! budget itself, and returns coins owned by the sponsor. The caller then
//! rebuilds the transaction with that gas, signs it, and calls `execute`.
//!
//! Two wire details drive the error handling. Failures arrive as flat
//! `{message, error, statusCode}` bodies on non-2xx, and — more dangerously —
//! `execute` answers `200` even when the transaction did not land: a submission
//! failure appears in `error`, and a transaction that executed but aborted in
//! Move reports it in `effects.status`. Reading only the status code would call
//! both of those a success.

use std::fmt;

use base64::Engine as _;
use serde::Deserialize;
use sui_sdk_types::{Address, Digest, ObjectReference, Transaction, UserSignature};

/// Why a sponsorship call did not produce a usable result.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GasStationError {
    #[error("signer-api transport error: {reason}")]
    Transport { reason: String },
    #[error("signer-api returned HTTP {status}: {message}")]
    Refused { status: u16, message: String },
    #[error("signer-api response was not valid JSON: {reason}")]
    Body { reason: String },
    #[error("signer-api returned an unusable gas coin: {reason}")]
    GasCoin { reason: String },
    #[error("signer-api reserved no gas coins")]
    NoGasCoins,
    #[error("could not encode the transaction: {reason}")]
    Encode { reason: String },
    #[error("transaction was submitted but failed on chain: {reason}")]
    ExecutionFailed { reason: String },
    #[error("signer-api reported success without a transaction digest")]
    MissingDigest,
}

/// Gas the sponsor has set aside for one transaction.
#[derive(Debug, Clone)]
pub struct GasReservation {
    /// The sponsor's address, which becomes the gas owner.
    pub sponsor: Address,
    /// Handle the execute call quotes back.
    pub reservation_id: u64,
    /// Coins the rebuilt transaction must name as its gas payment.
    pub gas_coins: Vec<ObjectReference>,
    /// Budget the service decided on, in MIST. Set verbatim: the service
    /// reserved exactly this much and validates against it.
    pub gas_budget: u64,
    /// ISO-8601 instant after which the reservation is void.
    pub expires_at: String,
}

/// What the service reported after submitting.
#[derive(Debug, Clone)]
pub struct ExecutionOutcome {
    /// On-chain transaction digest.
    pub digest: String,
    /// Raw effects, passed through rather than modelled: they are large and
    /// versioned by the node, not by us.
    pub effects: Option<serde_json::Value>,
}

/// A configured signer-api endpoint.
///
/// `Debug` prints the base URL only; a derived one would put the bearer JWT
/// into any log line that formatted this struct.
pub struct GasStation {
    base_url: String,
    auth_token: String,
    http: reqwest::Client,
}

impl fmt::Debug for GasStation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GasStation")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl GasStation {
    /// Point at a signer-api. `auth_token` is the bearer JWT it issues.
    pub fn new(base_url: impl Into<String>, auth_token: impl Into<String>) -> Self {
        Self::with_client(base_url, auth_token, reqwest::Client::new())
    }

    pub fn with_client(
        base_url: impl Into<String>,
        auth_token: impl Into<String>,
        http: reqwest::Client,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            auth_token: auth_token.into(),
            http,
        }
    }

    /// Submit the unsigned transaction for validation and gas reservation.
    ///
    /// `unsigned` carries placeholder gas: the service reads only its commands,
    /// and the gas it returns is what must be set before signing.
    pub async fn reserve(&self, unsigned: &Transaction) -> Result<GasReservation, GasStationError> {
        let body = serde_json::json!({ "tx_bytes": encode_transaction(unsigned)? });
        let wire: ReserveResponse = self.post("/v1/sponsorship/reserve", &body).await?;

        if wire.gas_coins.is_empty() {
            return Err(GasStationError::NoGasCoins);
        }
        let mut gas_coins = Vec::with_capacity(wire.gas_coins.len());
        for coin in wire.gas_coins {
            gas_coins.push(coin.into_object_reference()?);
        }
        Ok(GasReservation {
            sponsor: wire.sponsor_address.parse::<Address>().map_err(|e| {
                GasStationError::GasCoin {
                    reason: format!("sponsor address `{}`: {e}", wire.sponsor_address),
                }
            })?,
            reservation_id: wire.reservation_id,
            gas_coins,
            gas_budget: wire.gas_budget,
            expires_at: wire.expires_at,
        })
    }

    /// Submit the signed transaction against a reservation.
    ///
    /// The service adds the sponsor's own signature; `user_sig` is only ours.
    pub async fn execute(
        &self,
        reservation_id: u64,
        transaction: &Transaction,
        user_sig: &UserSignature,
    ) -> Result<ExecutionOutcome, GasStationError> {
        let body = serde_json::json!({
            "reservation_id": reservation_id,
            "tx_bytes": encode_transaction(transaction)?,
            "user_sig": base64::engine::general_purpose::STANDARD.encode(user_sig.to_bytes()),
        });
        let wire: ExecuteResponse = self.post("/v1/sponsorship/execute", &body).await?;

        // A 200 is not yet a success. Check the submission error, then the
        // on-chain status in whichever envelope carries it.
        if let Some(error) = wire.error.as_ref().and_then(unwrap_error_text) {
            return Err(GasStationError::ExecutionFailed { reason: error });
        }
        let effects = wire.effects.clone().or_else(|| {
            wire.tx_block_response
                .as_ref()
                .and_then(|r| r.get("effects").cloned())
        });
        if let Some(reason) = effects.as_ref().and_then(execution_status_error) {
            return Err(GasStationError::ExecutionFailed { reason });
        }

        let digest = wire
            .digest
            .or_else(|| {
                effects
                    .as_ref()
                    .and_then(|e| e.get("transactionDigest"))
                    .and_then(|d| d.as_str())
                    .map(str::to_string)
            })
            .ok_or(GasStationError::MissingDigest)?;
        Ok(ExecutionOutcome { digest, effects })
    }

    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T, GasStationError> {
        let response = self
            .http
            .post(format!("{}{path}", self.base_url))
            .bearer_auth(&self.auth_token)
            .json(body)
            .send()
            .await
            .map_err(|e| GasStationError::Transport {
                // `reqwest`'s Display can name the URL but never the bearer
                // token, which is only ever set as a header.
                reason: e.to_string(),
            })?;

        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| GasStationError::Transport {
                reason: e.to_string(),
            })?;

        if !status.is_success() {
            // Errors are flat `{message, error, statusCode}` bodies; the
            // message is the operator-useful part (e.g. which Move function
            // is not approved for sponsorship).
            let message = serde_json::from_str::<ErrorBody>(&text)
                .ok()
                .and_then(|b| b.message.as_ref().and_then(unwrap_error_text))
                .unwrap_or_else(|| text.chars().take(200).collect());
            return Err(GasStationError::Refused {
                status: status.as_u16(),
                message,
            });
        }
        serde_json::from_str::<T>(&text).map_err(|e| GasStationError::Body {
            reason: e.to_string(),
        })
    }
}

fn encode_transaction(transaction: &Transaction) -> Result<String, GasStationError> {
    let bytes = bcs::to_bytes(transaction).map_err(|e| GasStationError::Encode {
        reason: e.to_string(),
    })?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// `message` is a string for most errors and an array for validation failures.
fn unwrap_error_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Array(items) => {
            let joined: Vec<String> = items
                .iter()
                .filter_map(|i| i.as_str().map(str::to_string))
                .collect();
            (!joined.is_empty()).then(|| joined.join("; "))
        }
        _ => None,
    }
}

/// Effects serialize as `{status: {status: "failure", error: "MoveAbort(…)"}}`,
/// so a transaction can be executed and still have failed.
fn execution_status_error(effects: &serde_json::Value) -> Option<String> {
    let status = effects.get("status")?;
    if status.get("status").and_then(|s| s.as_str()) != Some("failure") {
        return None;
    }
    Some(
        status
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("the transaction failed on chain")
            .to_string(),
    )
}

#[derive(Debug, Deserialize)]
struct ReserveResponse {
    sponsor_address: String,
    reservation_id: u64,
    gas_coins: Vec<WireObjectRef>,
    gas_budget: u64,
    #[serde(default)]
    expires_at: String,
}

#[derive(Debug, Deserialize)]
struct ExecuteResponse {
    #[serde(default)]
    digest: Option<String>,
    #[serde(default)]
    effects: Option<serde_json::Value>,
    #[serde(default)]
    tx_block_response: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    #[serde(default)]
    message: Option<serde_json::Value>,
}

/// Sui's JSON object reference. `version` arrives as a string here but is a
/// number in some encodings; accept either rather than break against a node
/// that differs.
#[derive(Debug, Deserialize)]
struct WireObjectRef {
    #[serde(rename = "objectId")]
    object_id: String,
    version: WireVersion,
    digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum WireVersion {
    Number(u64),
    Text(String),
}

impl WireVersion {
    fn value(&self) -> Result<u64, GasStationError> {
        match self {
            Self::Number(n) => Ok(*n),
            Self::Text(s) => s.parse::<u64>().map_err(|e| GasStationError::GasCoin {
                reason: format!("version `{s}`: {e}"),
            }),
        }
    }
}

impl WireObjectRef {
    fn into_object_reference(self) -> Result<ObjectReference, GasStationError> {
        let address = self
            .object_id
            .parse::<Address>()
            .map_err(|e| GasStationError::GasCoin {
                reason: format!("object id `{}`: {e}", self.object_id),
            })?;
        let digest = self
            .digest
            .parse::<Digest>()
            .map_err(|e| GasStationError::GasCoin {
                reason: format!("digest `{}`: {e}", self.digest),
            })?;
        Ok(ObjectReference::new(address, self.version.value()?, digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_accepts_both_json_spellings() {
        let numeric: WireVersion = serde_json::from_str("123").expect("parses");
        let textual: WireVersion = serde_json::from_str("\"123\"").expect("parses");
        assert_eq!(numeric.value().expect("numeric"), 123);
        assert_eq!(textual.value().expect("textual"), 123);
    }

    #[test]
    fn debug_output_never_contains_the_bearer_token() {
        let station = GasStation::new("https://signer.example", "super-secret-jwt");
        let rendered = format!("{station:?}");
        assert!(rendered.contains("signer.example"));
        assert!(!rendered.contains("super-secret-jwt"), "token leaked");
    }

    #[test]
    fn base_url_trailing_slash_is_normalized() {
        let station = GasStation::new("https://signer.example/", "t");
        assert_eq!(station.base_url, "https://signer.example");
    }

    #[test]
    fn a_failed_move_status_is_recognized() {
        let effects = serde_json::json!({
            "status": { "status": "failure", "error": "MoveAbort(place_limit_order, 3)" }
        });
        assert_eq!(
            execution_status_error(&effects).as_deref(),
            Some("MoveAbort(place_limit_order, 3)")
        );
    }

    #[test]
    fn a_successful_status_is_not_an_error() {
        let effects = serde_json::json!({ "status": { "status": "success" } });
        assert!(execution_status_error(&effects).is_none());
    }

    #[test]
    fn validation_messages_arrive_as_arrays_too() {
        assert_eq!(
            unwrap_error_text(&serde_json::json!(["a must be set", "b invalid"])).as_deref(),
            Some("a must be set; b invalid")
        );
        assert_eq!(
            unwrap_error_text(&serde_json::json!("plain")).as_deref(),
            Some("plain")
        );
        assert!(unwrap_error_text(&serde_json::Value::Null).is_none());
    }
}
