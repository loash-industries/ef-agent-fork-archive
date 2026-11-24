//! The one piece of chain state the commit path needs.
//!
//! A transaction records the gas price it was built for, and validators reject
//! one priced below the current reference. That reference changes at epoch
//! boundaries, so a value pinned in configuration is correct until it silently
//! is not — and the symptom is every submission failing at once. Reading it per
//! submission costs one request and removes the failure mode.
//!
//! # Why GraphQL and not JSON-RPC
//!
//! This originally spoke JSON-RPC (`suix_getReferenceGasPrice`). That endpoint
//! is gone: public fullnodes on both mainnet and testnet now answer it with
//!
//! ```text
//! -32601  Method not found. JSON-RPC on public fullnodes has been deprecated.
//!         Please migrate to gRPC or GraphQL endpoints.
//! ```
//!
//! so every submission would have failed at the gas-price step. GraphQL is the
//! migration path that needs no new dependency — it is one POST of one query
//! over the `reqwest` client this crate already carries, where gRPC would pull
//! a protobuf stack into the graph for a single scalar.
//!
//! `url` is therefore a GraphQL endpoint (`https://graphql.testnet.sui.io/graphql`),
//! not a fullnode JSON-RPC URL. Pointing it at a fullnode yields a 404.

use serde::Deserialize;

use crate::seal::SharedObject;

/// The only query this module issues. Kept as a constant so the shape the
/// response parser expects is visible next to it.
const REFERENCE_GAS_PRICE_QUERY: &str = "{ epoch { referenceGasPrice } }";

/// Why the reference gas price could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RpcError {
    #[error("sui graphql transport error: {reason}")]
    Transport { reason: String },
    #[error("sui graphql returned HTTP {status}")]
    Status { status: u16 },
    #[error("sui graphql response was not valid JSON: {reason}")]
    Body { reason: String },
    #[error("sui graphql error: {message}")]
    Rpc { message: String },
    #[error("sui graphql returned no reference gas price")]
    Missing,
    #[error("sui graphql returned an unreadable gas price `{value}`")]
    Unreadable { value: String },
    #[error("no object at `{address}`")]
    ObjectNotFound { address: String },
    #[error("object `{address}` is not a shared object")]
    ObjectNotShared { address: String },
}

/// A Sui GraphQL endpoint.
#[derive(Debug, Clone)]
pub struct SuiRpc {
    url: String,
    http: reqwest::Client,
}

impl SuiRpc {
    pub fn new(url: impl Into<String>) -> Self {
        Self::with_client(url, reqwest::Client::new())
    }

    pub fn with_client(url: impl Into<String>, http: reqwest::Client) -> Self {
        Self {
            url: url.into(),
            http,
        }
    }

    /// POST one GraphQL query and return its `data`, refusing error responses.
    async fn query(&self, query: &str) -> Result<serde_json::Value, RpcError> {
        let response = self
            .http
            .post(&self.url)
            .json(&serde_json::json!({ "query": query }))
            .send()
            .await
            .map_err(|e| RpcError::Transport {
                reason: e.to_string(),
            })?;
        let status = response.status();
        let text = response.text().await.map_err(|e| RpcError::Transport {
            reason: e.to_string(),
        })?;

        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(e) => {
                // A non-2xx status with an unparseable body is a transport-level
                // failure; report the status, which is the more useful fact.
                return Err(if status.is_success() {
                    RpcError::Body {
                        reason: e.to_string(),
                    }
                } else {
                    RpcError::Status {
                        status: status.as_u16(),
                    }
                });
            }
        };
        // GraphQL reports query errors in `errors` with a 200, so the status
        // alone never establishes success.
        if let Some(message) = value.pointer("/errors/0/message").and_then(|m| m.as_str()) {
            return Err(RpcError::Rpc {
                message: message.to_string(),
            });
        }
        Ok(value)
    }

    /// Read the version at which an object became shared.
    ///
    /// A shared input is identified by that initial version, not the object's
    /// current one, so reading `version` would not do.
    pub async fn shared_object(&self, address: &str) -> Result<SharedObject, RpcError> {
        let id =
            address
                .parse::<sui_sdk_types::Address>()
                .map_err(|_| RpcError::ObjectNotFound {
                    address: address.to_string(),
                })?;
        let query = format!(
            r#"{{ object(address: "{address}") {{ owner {{ __typename ... on Shared {{ initialSharedVersion }} }} }} }}"#
        );
        let json = self.query(&query).await?;
        let owner = json
            .pointer("/data/object/owner")
            .ok_or_else(|| RpcError::ObjectNotFound {
                address: address.to_string(),
            })?;
        // An owned object satisfies none of what `seal_approve` needs, and
        // saying so names the real problem rather than a missing field.
        if owner.get("__typename").and_then(|t| t.as_str()) != Some("Shared") {
            return Err(RpcError::ObjectNotShared {
                address: address.to_string(),
            });
        }
        let initial_shared_version = owner
            .get("initialSharedVersion")
            .and_then(read_u64)
            .ok_or_else(|| RpcError::ObjectNotShared {
                address: address.to_string(),
            })?;
        Ok(SharedObject {
            id,
            initial_shared_version,
        })
    }

    /// Read the current reference gas price, in MIST.
    pub async fn reference_gas_price(&self) -> Result<u64, RpcError> {
        let json = self.query(REFERENCE_GAS_PRICE_QUERY).await?;
        let parsed: GraphQlResponse = serde_json::from_value(json).map_err(|e| RpcError::Body {
            reason: e.to_string(),
        })?;
        let price = parsed
            .data
            .and_then(|data| data.epoch)
            .and_then(|epoch| epoch.reference_gas_price)
            .ok_or(RpcError::Missing)?;

        // Sui returns this as a JSON string (it is a BigInt in the schema), but
        // accept a number too rather than break against a deployment that differs.
        match price {
            serde_json::Value::String(s) => s
                .parse::<u64>()
                .map_err(|_| RpcError::Unreadable { value: s }),
            serde_json::Value::Number(n) => n.as_u64().ok_or_else(|| RpcError::Unreadable {
                value: n.to_string(),
            }),
            other => Err(RpcError::Unreadable {
                value: other.to_string(),
            }),
        }
    }
}

/// Move integers reach GraphQL as strings or numbers; accept both.
fn read_u64(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::String(s) => s.parse::<u64>().ok(),
        serde_json::Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

/// Only `data` is modelled: `query` has already refused any response carrying
/// an `errors` array, so nothing downstream needs to see one.
#[derive(Debug, Deserialize)]
struct GraphQlResponse {
    data: Option<GraphQlData>,
}

#[derive(Debug, Deserialize)]
struct GraphQlData {
    epoch: Option<GraphQlEpoch>,
}

#[derive(Debug, Deserialize)]
struct GraphQlEpoch {
    #[serde(rename = "referenceGasPrice")]
    reference_gas_price: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a canned body the same way `reference_gas_price` does, so these
    /// cases exercise the real decoding without standing up an HTTP server.
    fn price_from(body: &str) -> Result<u64, RpcError> {
        // Mirrors `query` then `reference_gas_price`: the error array is checked
        // on the raw value first, exactly as the real path does.
        let value: serde_json::Value = serde_json::from_str(body).map_err(|e| RpcError::Body {
            reason: e.to_string(),
        })?;
        if let Some(message) = value.pointer("/errors/0/message").and_then(|m| m.as_str()) {
            return Err(RpcError::Rpc {
                message: message.to_string(),
            });
        }
        let parsed: GraphQlResponse =
            serde_json::from_value(value).map_err(|e| RpcError::Body {
                reason: e.to_string(),
            })?;
        let price = parsed
            .data
            .and_then(|d| d.epoch)
            .and_then(|e| e.reference_gas_price)
            .ok_or(RpcError::Missing)?;
        match price {
            serde_json::Value::String(s) => s
                .parse::<u64>()
                .map_err(|_| RpcError::Unreadable { value: s }),
            serde_json::Value::Number(n) => n.as_u64().ok_or_else(|| RpcError::Unreadable {
                value: n.to_string(),
            }),
            other => Err(RpcError::Unreadable {
                value: other.to_string(),
            }),
        }
    }

    #[test]
    fn reads_the_string_form_the_live_endpoint_returns() {
        // Verbatim from https://graphql.testnet.sui.io/graphql.
        let body = r#"{"data":{"epoch":{"referenceGasPrice":"1000"}}}"#;
        assert_eq!(price_from(body).expect("parses"), 1000);
    }

    #[test]
    fn reads_a_numeric_price_too() {
        let body = r#"{"data":{"epoch":{"referenceGasPrice":100}}}"#;
        assert_eq!(price_from(body).expect("parses"), 100);
    }

    #[test]
    fn a_graphql_error_is_not_a_price_even_though_the_status_was_200() {
        let body = r#"{"errors":[{"message":"unknown field"}]}"#;
        assert_eq!(
            price_from(body).expect_err("must not be read as a price"),
            RpcError::Rpc {
                message: "unknown field".to_string()
            }
        );
    }

    #[test]
    fn a_null_epoch_is_missing_rather_than_zero() {
        // Reading this as 0 would price a transaction below the reference and
        // have it rejected by validators for a reason the error would not name.
        let body = r#"{"data":{"epoch":null}}"#;
        assert_eq!(
            price_from(body).expect_err("must not default"),
            RpcError::Missing
        );
    }

    #[test]
    fn a_non_numeric_price_is_refused() {
        let body = r#"{"data":{"epoch":{"referenceGasPrice":"not a number"}}}"#;
        assert_eq!(
            price_from(body).expect_err("must not be read as a price"),
            RpcError::Unreadable {
                value: "not a number".to_string()
            }
        );
    }

    #[test]
    fn the_deprecated_json_rpc_error_body_is_reported_not_swallowed() {
        // What a fullnode now answers if someone points `rpc_url` at one.
        let body =
            r#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found."},"id":null}"#;
        // No `data` and no GraphQL `errors`, so this surfaces as a missing price
        // rather than being mistaken for a successful read.
        assert_eq!(
            price_from(body).expect_err("must not parse"),
            RpcError::Missing
        );
    }
}
