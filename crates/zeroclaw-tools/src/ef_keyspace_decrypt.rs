//! `ef_keyspace_decrypt` — read one Seal-encrypted Keyspace entry.
//!
//! The agent supplies only identifiers it got from `keyspace_get_acl`. This tool
//! fetches the ciphertext, proves to the key servers that the agent's address is
//! allowed to read it, and returns the plaintext.
//!
//! # Where the parts live
//!
//! The BLS12-381 work happens in the out-of-workspace `seal-decrypt` binary,
//! because its dependency tree cannot enter the graph that signs transactions
//! without weakening `deny.toml`. The wallet key never goes there: the child
//! asks for a signature over the session message, and this process decides
//! whether to give one.
//!
//! # What is checked before anything is signed or fetched
//!
//! Every identifier arrives through the model, so each is treated as a claim:
//!
//! * the entry URI must be `https` and its host must be on the operator's
//!   allow-list, or a prompt-injected agent could aim the fetch anywhere this
//!   process can reach;
//! * the ciphertext must name the configured Seal package, read from its own
//!   bytes rather than from the metadata that accompanied it;
//! * the ciphertext's policy id must begin with the Keyspace the caller named,
//!   so an entry belonging to some other Keyspace cannot be approved under this
//!   one;
//! * the session message the child proposes must be a Seal session message, for
//!   that package, within the configured lifetime, minted now.
//!
//! Registered as `ToolOperation::Act` rather than a read: it commits the wallet
//! key to a signature and turns protected data into plaintext, and both belong
//! on the approval path.

use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::json;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use zeroclaw_api::tool::{Tool, ToolOutput, ToolResult};
use zeroclaw_config::policy::{SecurityPolicy, ToolOperation};
use zeroclaw_config::schema::SuiConfig;
use zeroclaw_sui::{
    Address, AgentSigner, SuiRpc, build_seal_approve_bytes, parse_encrypted_header,
    validate_proposed_session_message,
};

/// How long the child gets before it is abandoned. Generous: it makes several
/// network round trips, one per committee member.
const CHILD_TIMEOUT: Duration = Duration::from_secs(90);

/// Ceiling on the entry body, so a hostile or mistaken URI cannot exhaust memory.
const MAX_ENTRY_BYTES: usize = 8 * 1024 * 1024;

pub struct EfKeyspaceDecryptTool {
    signer: AgentSigner,
    rpc: SuiRpc,
    http: reqwest::Client,
    security: Arc<SecurityPolicy>,
    package: Address,
    aggregator_url: String,
    key_server_object_id: String,
    graphql_url: String,
    session_ttl_min: u16,
    sidecar_path: String,
    allowed_entry_hosts: Vec<String>,
}

/// Prints the agent's address and the shape of its rules, never key material.
impl std::fmt::Debug for EfKeyspaceDecryptTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EfKeyspaceDecryptTool")
            .field("address", &self.signer.address())
            .field("package", &self.package)
            .field("session_ttl_min", &self.session_ttl_min)
            .field("allowed_entry_hosts", &self.allowed_entry_hosts.len())
            .finish_non_exhaustive()
    }
}

impl EfKeyspaceDecryptTool {
    pub const NAME: &'static str = "ef_keyspace_decrypt";

    /// Build from configuration, failing closed.
    ///
    /// Every missing value is an error rather than a default, so a
    /// half-configured deployment leaves the tool absent instead of present
    /// with rules nobody wrote.
    pub fn from_config(config: &SuiConfig, security: Arc<SecurityPolicy>) -> Result<Self, String> {
        let seal = &config.seal;
        let raw_key = config.private_key.trim();
        if raw_key.is_empty() {
            return Err("sui.private_key is required".to_string());
        }
        // Same two spellings `ef_submit` accepts, so one configured key serves
        // both tools rather than the deployment carrying two.
        let signer = if raw_key.starts_with("suiprivkey") {
            AgentSigner::from_bech32(raw_key)
        } else {
            AgentSigner::from_hex(raw_key)
        }
        .map_err(|e| format!("sui.private_key could not be loaded: {e}"))?;

        let require = |value: &str, name: &str| -> Result<String, String> {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Err(format!("{name} is required"))
            } else {
                Ok(trimmed.to_string())
            }
        };

        let package_text = require(&seal.package_id, "sui.seal.package_id")?;
        let package: Address = package_text
            .parse()
            .map_err(|_| format!("sui.seal.package_id `{package_text}` is not an address"))?;

        if seal.session_ttl_min == 0 {
            return Err("sui.seal.session_ttl_min must be at least 1".to_string());
        }
        // An empty allow-list would let the model choose the fetch target.
        if seal.allowed_entry_hosts.is_empty() {
            return Err("sui.seal.allowed_entry_hosts is empty, so no entry may be fetched".into());
        }

        Ok(Self {
            signer,
            rpc: SuiRpc::new(require(&config.rpc_url, "sui.rpc_url")?),
            http: reqwest::Client::new(),
            security,
            package,
            aggregator_url: require(&seal.aggregator_url, "sui.seal.aggregator_url")?,
            key_server_object_id: require(
                &seal.key_server_object_id,
                "sui.seal.key_server_object_id",
            )?,
            graphql_url: require(&config.rpc_url, "sui.rpc_url")?,
            session_ttl_min: seal.session_ttl_min,
            sidecar_path: require(&seal.sidecar_path, "sui.seal.sidecar_path")?,
            allowed_entry_hosts: seal
                .allowed_entry_hosts
                .iter()
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect(),
        })
    }

    pub fn address(&self) -> Address {
        self.signer.address()
    }

    /// Fetch the ciphertext, refusing anything not on the operator's allow-list.
    async fn fetch_entry(&self, uri: &str) -> Result<Vec<u8>, String> {
        let parsed =
            reqwest::Url::parse(uri).map_err(|e| format!("entry uri is not a URL: {e}"))?;
        if parsed.scheme() != "https" {
            return Err(format!(
                "entry uri uses `{}`; only https is allowed",
                parsed.scheme()
            ));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| "entry uri has no host".to_string())?
            .to_ascii_lowercase();
        if !self.allowed_entry_hosts.contains(&host) {
            return Err(format!(
                "entry host `{host}` is not in sui.seal.allowed_entry_hosts; refusing to fetch"
            ));
        }

        let response = self
            .http
            .get(parsed)
            .send()
            .await
            .map_err(|e| format!("fetching the entry: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("entry host returned HTTP {}", response.status()));
        }
        let body = response
            .text()
            .await
            .map_err(|e| format!("reading the entry: {e}"))?;
        if body.len() > MAX_ENTRY_BYTES {
            return Err(format!("entry is larger than {MAX_ENTRY_BYTES} bytes"));
        }

        // Keyspace stores the ciphertext hex-encoded inside a small JSON wrapper.
        let wrapper: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("entry was not JSON: {e}"))?;
        let hex_text = wrapper
            .get("blob")
            .and_then(|b| b.as_str())
            .ok_or_else(|| "entry JSON has no `blob` field".to_string())?;
        hex::decode(hex_text).map_err(|e| format!("entry blob is not hex: {e}"))
    }
}

/// Shape a successful decryption.
///
/// The plaintext goes in the **text**, not only in the structured value:
/// `ToolOutput` sends `text` to the model and keeps `data` for other consumers,
/// so a summary-only text means the caller is told the decryption worked while
/// receiving none of it. That was the original bug here.
fn decrypted(keyspace_id: &str, plaintext: &[u8]) -> ToolResult {
    let text = String::from_utf8_lossy(plaintext).to_string();
    let data = json!({
        "keyspaceId": keyspace_id,
        "plaintext": text,
        "bytes": plaintext.len(),
    });
    // The reminder rides with the payload because the moment it is read is the
    // moment it can be copied somewhere it should not go.
    let rendered = format!(
        "Decrypted {} bytes from {keyspace_id}. This is protected data: use it to answer the \
         question at hand, and do not store it, write it to memory, or pass it to another tool.\n\n{text}",
        plaintext.len()
    );
    ToolResult {
        success: true,
        output: ToolOutput::json_with_text(data, rendered),
        error: None,
    }
}

fn failed(message: impl Into<String>) -> ToolResult {
    ToolResult {
        success: false,
        output: ToolOutput::default(),
        error: Some(message.into()),
    }
}

#[async_trait]
impl Tool for EfKeyspaceDecryptTool {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn description(&self) -> &str {
        "Decrypt one Seal-encrypted Keyspace entry that this agent's address is allowed to read, \
         and return its plaintext. Pass the ids exactly as `keyspace_get_acl` reported them. \
         Requires a wallet signature, so it is not free and not silent: prefer decrypting the one \
         entry you need over decrypting everything. The plaintext is protected data — do not \
         store it, repeat it into other tools, or write it to memory."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "keyspaceId": {
                    "type": "string",
                    "description": "Keyspace object id, as `keyspace_get_acl` reported it.",
                    "pattern": "^0x[0-9a-fA-F]{1,64}$"
                },
                "ouId": {
                    "type": "string",
                    "description": "Org-unit object id granting the read role, from the keyspace's readPrincipals.",
                    "pattern": "^0x[0-9a-fA-F]{1,64}$"
                },
                "uri": {
                    "type": "string",
                    "description": "The entry's `uri` from the keyspace metadata. Must be https and on the operator's allow-list."
                }
            },
            "required": ["keyspaceId", "ouId", "uri"],
            "additionalProperties": false
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        if let Err(e) = self
            .security
            .enforce_tool_operation(ToolOperation::Act, Self::NAME)
        {
            return Ok(failed(e.to_string()));
        }

        let string_arg = |name: &str| -> Result<String, String> {
            args.get(name)
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .ok_or_else(|| format!("`{name}` is required"))
        };

        let keyspace_id = match string_arg("keyspaceId") {
            Ok(v) => v,
            Err(e) => return Ok(failed(e)),
        };
        let ou_id = match string_arg("ouId") {
            Ok(v) => v,
            Err(e) => return Ok(failed(e)),
        };
        let uri = match string_arg("uri") {
            Ok(v) => v,
            Err(e) => return Ok(failed(e)),
        };

        let keyspace_address: Address = match keyspace_id.parse() {
            Ok(v) => v,
            Err(_) => return Ok(failed(format!("`{keyspace_id}` is not an address"))),
        };

        let ciphertext = match self.fetch_entry(&uri).await {
            Ok(v) => v,
            Err(e) => return Ok(failed(e)),
        };

        // Read the entry's own claims from its bytes, and contradict the
        // metadata if they disagree.
        let header = match parse_encrypted_header(&ciphertext) {
            Ok(v) => v,
            Err(e) => return Ok(failed(e.to_string())),
        };
        if header.package != self.package {
            return Ok(failed(format!(
                "entry was encrypted under package `{}` but this agent is configured for `{}`",
                header.package, self.package
            )));
        }
        // The policy id is the Keyspace id followed by a nonce; if it names a
        // different Keyspace, approving it under this one would be wrong.
        if header.policy_id.len() < 32 || &header.policy_id[..32] != keyspace_address.inner() {
            return Ok(failed(format!(
                "entry does not belong to keyspace `{keyspace_id}`"
            )));
        }

        let keyspace = match self.rpc.shared_object(&keyspace_id).await {
            Ok(v) => v,
            Err(e) => return Ok(failed(format!("reading the keyspace object: {e}"))),
        };
        let org_unit = match self.rpc.shared_object(&ou_id).await {
            Ok(v) => v,
            Err(e) => return Ok(failed(format!("reading the org-unit object: {e}"))),
        };

        let ptb_bytes =
            match build_seal_approve_bytes(self.package, &header.policy_id, keyspace, org_unit) {
                Ok(v) => v,
                Err(e) => return Ok(failed(e.to_string())),
            };

        let request = json!({
            "graphql_url": self.graphql_url,
            "key_server_object_id": self.key_server_object_id,
            "aggregator_url": self.aggregator_url,
            "package_id": self.package.to_string(),
            "ttl_min": self.session_ttl_min,
            "wallet_address": self.signer.address().to_string(),
            "wallet_public_key_b64": B64.encode(self.signer.public_key_bytes()),
            "encrypted_object_b64": B64.encode(&ciphertext),
            "ptb_b64": B64.encode(&ptb_bytes),
        });

        match tokio::time::timeout(CHILD_TIMEOUT, self.run_child(request)).await {
            Ok(Ok(plaintext)) => Ok(decrypted(&keyspace_id, &plaintext)),
            Ok(Err(e)) => Ok(failed(e)),
            Err(_) => Ok(failed(format!(
                "seal-decrypt did not finish within {}s",
                CHILD_TIMEOUT.as_secs()
            ))),
        }
    }
}

impl EfKeyspaceDecryptTool {
    /// Drive the child: send the request, answer its one signing question, read
    /// the result.
    async fn run_child(&self, request: serde_json::Value) -> Result<Vec<u8>, String> {
        let mut child = tokio::process::Command::new(&self.sidecar_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("starting {}: {e}", self.sidecar_path))?;

        let mut stdin = child.stdin.take().ok_or("child has no stdin")?;
        let stdout = child.stdout.take().ok_or("child has no stdout")?;
        let mut reader = BufReader::new(stdout).lines();

        let mut line = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        line.push(b'\n');
        stdin
            .write_all(&line)
            .await
            .map_err(|e| format!("writing the request: {e}"))?;
        stdin
            .flush()
            .await
            .map_err(|e| format!("flushing the request: {e}"))?;

        let outcome = loop {
            let Some(line) = reader
                .next_line()
                .await
                .map_err(|e| format!("reading from seal-decrypt: {e}"))?
            else {
                break Err("seal-decrypt exited without answering".to_string());
            };
            let message: serde_json::Value = serde_json::from_str(&line)
                .map_err(|e| format!("seal-decrypt said `{line}`: {e}"))?;

            match message.get("status").and_then(|s| s.as_str()) {
                Some("sign_request") => {
                    let proposed = message
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or_default();
                    match self.sign_session(proposed) {
                        Ok(signature_b64) => {
                            let mut reply = serde_json::to_vec(&json!({
                                "signature_b64": signature_b64
                            }))
                            .map_err(|e| e.to_string())?;
                            reply.push(b'\n');
                            stdin
                                .write_all(&reply)
                                .await
                                .map_err(|e| format!("writing the signature: {e}"))?;
                            stdin
                                .flush()
                                .await
                                .map_err(|e| format!("flushing the signature: {e}"))?;
                        }
                        // Refusing to sign ends the exchange; dropping stdin
                        // lets the child fail rather than wait.
                        Err(e) => break Err(e),
                    }
                }
                Some("ok") => {
                    let encoded = message
                        .get("plaintext_b64")
                        .and_then(|p| p.as_str())
                        .unwrap_or_default();
                    break B64
                        .decode(encoded)
                        .map_err(|e| format!("plaintext was not base64: {e}"));
                }
                Some("error") => {
                    break Err(message
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("seal-decrypt failed")
                        .to_string());
                }
                other => {
                    break Err(format!("seal-decrypt sent an unknown status {other:?}"));
                }
            }
        };

        // Do not leave the child running when we are no longer listening.
        let _ = child.kill().await;
        outcome
    }

    /// Validate a proposed session message and sign it, or refuse.
    ///
    /// This is the only place the wallet key is used on this path, and the
    /// validation above it is what keeps that from being a general signing
    /// oracle.
    fn sign_session(&self, proposed: &str) -> Result<String, String> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .map_err(|e| format!("reading the clock: {e}"))?;
        validate_proposed_session_message(proposed, self.package, self.session_ttl_min, now_ms)
            .map_err(|e| e.to_string())?;
        let signature = self
            .signer
            .sign_personal_message_bytes(proposed.as_bytes())
            .map_err(|e| format!("signing the session message: {e}"))?;
        Ok(B64.encode(signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plaintext must reach the model, which reads `output.as_str()`.
    ///
    /// Regression: the first version put it only in the structured `data`, so
    /// the agent was told "Decrypted 822 bytes" and given nothing to answer
    /// with — a decryption that succeeded and still failed its purpose.
    #[test]
    fn the_plaintext_is_in_the_text_the_model_reads() {
        let result = decrypted("0xabc", b"{\"IKEA\":\"J-GAM XI\"}");
        assert!(result.success);
        let shown = result.output.as_str();
        assert!(
            shown.contains("J-GAM XI"),
            "plaintext must appear in the text the model receives, got: {shown}"
        );
        assert!(
            shown.contains("19 bytes"),
            "byte count should still be stated"
        );
    }

    #[test]
    fn the_structured_value_still_carries_it_too() {
        let result = decrypted("0xabc", b"hello");
        let data = result.output.data().expect("structured value present");
        assert_eq!(data["plaintext"], "hello");
        assert_eq!(data["bytes"], 5);
        assert_eq!(data["keyspaceId"], "0xabc");
    }

    #[test]
    fn the_handling_reminder_travels_with_the_payload() {
        let result = decrypted("0xabc", b"secret place");
        assert!(result.output.as_str().contains("do not store it"));
    }
}
