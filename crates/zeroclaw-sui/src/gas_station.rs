//! Client for the sponsored-gas service.
//!
//! The station reserves coins it owns, the agent signs a transaction whose gas
//! is payable by the sponsor, and the station adds its own signature and
//! submits. The agent therefore never needs SUI of its own — but it does sign
//! over the sponsor's gas coins, so the reservation must be obtained before
//! signing and used immediately after.
//!
//! One wire quirk drives the error handling here: the service answers `200 OK`
//! with `{"error": "..."}` for application failures. Checking only the HTTP
//! status would read a refusal as a success and return a reservation that does
//! not exist.

use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use serde::Deserialize;
use sui_sdk_types::{Address, Digest, ObjectReference, Transaction, UserSignature};

/// Ten minutes, the longest reservation the service accepts.
pub const MAX_RESERVE_DURATION: Duration = Duration::from_secs(10 * 60);

/// Why a gas-station call did not produce a usable result.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GasStationError {
    #[error("gas station transport error: {reason}")]
    Transport { reason: String },
    #[error("gas station returned HTTP {status}")]
    Status { status: u16 },
    #[error("gas station response was not valid JSON: {reason}")]
    Body { reason: String },
    #[error("gas station refused the request: {message}")]
    Refused { message: String },
    #[error("gas station returned neither a result nor an error")]
    EmptyResponse,
    #[error("gas station returned an unusable gas coin: {reason}")]
    GasCoin { reason: String },
    #[error("reserve duration {secs}s exceeds the {max}s maximum")]
    ReserveDuration { secs: u64, max: u64 },
    #[error("gas budget must be greater than zero")]
    ZeroBudget,
    #[error("could not encode the transaction: {reason}")]
    Encode { reason: String },
}

/// Gas coins held for us, and who is paying.
#[derive(Debug, Clone)]
pub struct GasReservation {
    /// The station's address, which becomes the gas owner.
    pub sponsor: Address,
    /// Handle to release or spend the reservation.
    pub reservation_id: u64,
    /// Coins the signed transaction must name as its gas payment.
    pub gas_coins: Vec<ObjectReference>,
}

/// What the service reported after submitting.
///
/// Effects are passed through as raw JSON: they are large, versioned by the
/// node rather than by us, and this crate has no reason to model them. Callers
/// that need a field can read it; callers that do not are unaffected when the
/// node's shape changes.
#[derive(Debug, Clone)]
pub struct ExecutionOutcome {
    pub effects: Option<serde_json::Value>,
    pub response: Option<serde_json::Value>,
}

/// A configured gas-station endpoint.
///
/// `Debug` prints the base URL only; a derived one would put the bearer token
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
    /// Point at a station. `base_url` may carry a trailing slash or not.
    pub fn new(base_url: impl Into<String>, auth_token: impl Into<String>) -> Self {
        Self::with_client(base_url, auth_token, reqwest::Client::new())
    }

    /// Point at a station using a caller-supplied HTTP client.
    pub fn with_client(
        base_url: impl Into<String>,
        auth_token: impl Into<String>,
        http: reqwest::Client,
    ) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        Self {
            base_url,
            auth_token: auth_token.into(),
            http,
        }
    }

    /// Reserve gas coins for a bounded window.
    pub async fn reserve(
        &self,
        gas_budget: u64,
        reserve_for: Duration,
    ) -> Result<GasReservation, GasStationError> {
        if gas_budget == 0 {
            return Err(GasStationError::ZeroBudget);
        }
        let secs = reserve_for.as_secs();
        if secs == 0 || reserve_for > MAX_RESERVE_DURATION {
            return Err(GasStationError::ReserveDuration {
                secs,
                max: MAX_RESERVE_DURATION.as_secs(),
            });
        }

        let body = serde_json::json!({
            "gas_budget": gas_budget,
            "reserve_duration_secs": secs,
        });
        let wire: ReserveGasResponse = self.post("/v1/reserve_gas", &body).await?;
        let result = match (wire.result, wire.error) {
            (Some(result), _) => result,
            (None, Some(message)) => return Err(GasStationError::Refused { message }),
            (None, None) => return Err(GasStationError::EmptyResponse),
        };

        let mut gas_coins = Vec::with_capacity(result.gas_coins.len());
        for coin in result.gas_coins {
            gas_coins.push(coin.into_object_reference()?);
        }
        Ok(GasReservation {
            sponsor: parse_address(&result.sponsor_address)?,
            reservation_id: result.reservation_id,
            gas_coins,
        })
    }

    /// Submit a signed transaction against a reservation.
    ///
    /// The station adds the sponsor's own signature; `user_sig` is only ours.
    pub async fn execute(
        &self,
        reservation_id: u64,
        transaction: &Transaction,
        user_sig: &UserSignature,
    ) -> Result<ExecutionOutcome, GasStationError> {
        let tx_bytes = bcs::to_bytes(transaction).map_err(|e| GasStationError::Encode {
            reason: e.to_string(),
        })?;
        let engine = base64::engine::general_purpose::STANDARD;
        let body = serde_json::json!({
            "reservation_id": reservation_id,
            "tx_bytes": engine.encode(&tx_bytes),
            "user_sig": engine.encode(user_sig.to_bytes()),
        });
        let wire: ExecuteTxResponse = self.post("/v1/execute_tx", &body).await?;
        if let Some(message) = wire.error {
            return Err(GasStationError::Refused { message });
        }
        if wire.effects.is_none() && wire.tx_block_response.is_none() {
            return Err(GasStationError::EmptyResponse);
        }
        Ok(ExecutionOutcome {
            effects: wire.effects,
            response: wire.tx_block_response,
        })
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
                // `reqwest`'s Display can include the URL but never the bearer
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

        // A refusal body is more useful than the status code, so parse first
        // and only fall back to the status when the body is not our shape.
        match serde_json::from_str::<T>(&text) {
            Ok(parsed) => Ok(parsed),
            Err(e) => {
                if !status.is_success() {
                    Err(GasStationError::Status {
                        status: status.as_u16(),
                    })
                } else {
                    Err(GasStationError::Body {
                        reason: e.to_string(),
                    })
                }
            }
        }
    }
}

fn parse_address(raw: &str) -> Result<Address, GasStationError> {
    raw.parse::<Address>()
        .map_err(|e| GasStationError::GasCoin {
            reason: format!("sponsor address `{raw}`: {e}"),
        })
}

#[derive(Debug, Deserialize)]
struct ReserveGasResponse {
    result: Option<ReserveGasResult>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReserveGasResult {
    sponsor_address: String,
    reservation_id: u64,
    gas_coins: Vec<WireObjectRef>,
}

#[derive(Debug, Deserialize)]
struct ExecuteTxResponse {
    effects: Option<serde_json::Value>,
    tx_block_response: Option<serde_json::Value>,
    error: Option<String>,
}

/// Sui's JSON object reference.
///
/// `version` is accepted as either a number or a decimal string: Sui's JSON
/// encodings disagree about which one `SequenceNumber` uses, and a client that
/// insisted on one would break against a node that chose the other.
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
    fn a_non_numeric_version_is_an_error_not_a_panic() {
        let bad: WireVersion = serde_json::from_str("\"soon\"").expect("parses as text");
        assert!(matches!(bad.value(), Err(GasStationError::GasCoin { .. })));
    }

    #[test]
    fn debug_output_never_contains_the_bearer_token() {
        let station = GasStation::new("https://gas.example", "super-secret-token");
        let rendered = format!("{station:?}");
        assert!(rendered.contains("gas.example"));
        assert!(!rendered.contains("super-secret-token"), "token leaked");
    }

    #[test]
    fn base_url_trailing_slash_is_normalized() {
        let station = GasStation::new("https://gas.example/", "t");
        assert_eq!(station.base_url, "https://gas.example");
    }
}
