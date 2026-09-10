//! The one piece of chain state the commit path needs.
//!
//! A transaction records the gas price it was built for, and validators reject
//! one priced below the current reference. That reference changes at epoch
//! boundaries, so a value pinned in configuration is correct until it silently
//! is not — and the symptom is every submission failing at once. Reading it per
//! submission costs one request and removes the failure mode.

use serde::Deserialize;

/// Why the reference gas price could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RpcError {
    #[error("sui rpc transport error: {reason}")]
    Transport { reason: String },
    #[error("sui rpc returned HTTP {status}")]
    Status { status: u16 },
    #[error("sui rpc response was not valid JSON: {reason}")]
    Body { reason: String },
    #[error("sui rpc error: {message}")]
    Rpc { message: String },
    #[error("sui rpc returned no reference gas price")]
    Missing,
    #[error("sui rpc returned an unreadable gas price `{value}`")]
    Unreadable { value: String },
}

/// A Sui JSON-RPC endpoint.
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

    /// Read the current reference gas price, in MIST.
    pub async fn reference_gas_price(&self) -> Result<u64, RpcError> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "suix_getReferenceGasPrice",
            "params": [],
        });
        let response = self
            .http
            .post(&self.url)
            .json(&request)
            .send()
            .await
            .map_err(|e| RpcError::Transport {
                reason: e.to_string(),
            })?;
        let status = response.status();
        let text = response.text().await.map_err(|e| RpcError::Transport {
            reason: e.to_string(),
        })?;

        let parsed: RpcResponse = match serde_json::from_str(&text) {
            Ok(parsed) => parsed,
            Err(e) => {
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
        if let Some(error) = parsed.error {
            return Err(RpcError::Rpc {
                message: error.message,
            });
        }
        // Sui returns this as a JSON string in most deployments and as a number
        // in some; accept either rather than break against a node that differs.
        match parsed.result {
            Some(serde_json::Value::String(s)) => s
                .parse::<u64>()
                .map_err(|_| RpcError::Unreadable { value: s }),
            Some(serde_json::Value::Number(n)) => n.as_u64().ok_or_else(|| RpcError::Unreadable {
                value: n.to_string(),
            }),
            Some(other) => Err(RpcError::Unreadable {
                value: other.to_string(),
            }),
            None => Err(RpcError::Missing),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<RpcErrorBody>,
}

#[derive(Debug, Deserialize)]
struct RpcErrorBody {
    message: String,
}
