//! Seal decryption, run as a short-lived child process.
//!
//! # Why this is a separate process
//!
//! Decrypting a Keyspace entry needs BLS12-381, which means `fastcrypto`, which
//! arrives with an older RustCrypto generation in tow (see `Cargo.toml` for the
//! measured cost). ef-agent's own dependency graph is the one that signs
//! transactions, and it is gated by `deny.toml` at `allow-git = []` with no
//! duplicate-version skips. Rather than weaken that gate, the crypto lives out
//! here and is reached across a pipe.
//!
//! # What crosses the boundary, and what never does
//!
//! The wallet key never leaves ef-agent. When this process needs the session
//! message signed it asks for a signature over the pipe; ef-agent validates the
//! message against its own template, package allowlist, TTL ceiling and
//! freshness check before signing anything. This process proposes; the parent
//! decides.
//!
//! The ephemeral session key is generated here and dies here. It authorises
//! nothing on its own — key-server requests it signs are honoured only
//! alongside the wallet's signature over the session message.
//!
//! # Protocol
//!
//! Line-delimited JSON both ways, so the exchange is greppable in a log:
//!
//! ```text
//! stdin  → { "key_servers": […], "aggregator_urls": {…}, … }   the request
//! stdout ← { "status": "sign_request", "message": "Accessing keys of package …" }
//! stdin  → { "signature_b64": "…" }
//! stdout ← { "status": "ok", "plaintext_b64": "…" }
//! ```
//!
//! # Trust posture
//!
//! stdin is trusted (ef-agent wrote it). Key-server responses are not:
//! `seal-sdk-rs` verifies every returned share against the serving key server's
//! IBE public key before use, so a server can withhold a share but cannot
//! substitute one. With a committee, the threshold does the rest.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader, Stdin, Stdout};
use tokio::sync::Mutex;

use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use fastcrypto::error::FastCryptoError;
use fastcrypto::traits::ToFromBytes as _;
use seal_sdk_rs::base_client::{BaseSealClient, KeyServerInfo, PartialKeyServer, ServerType};
use seal_sdk_rs::cache::NoCache;
use seal_sdk_rs::generic_types::{BCSSerializableProgrammableTransaction, ObjectID, SuiAddress};
use seal_sdk_rs::session_key::SessionKey;
use seal_sdk_rs::signer::Signer;
use seal_sdk_rs::sui_client::SuiClient;

// ── Wire protocol ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Request {
    /// Sui GraphQL endpoint. JSON-RPC on public fullnodes is deprecated, so the
    /// one on-chain read this process makes goes over GraphQL.
    graphql_url: String,
    /// On-chain object id of the key server.
    key_server_object_id: String,
    /// Aggregator base URL for that key server. For a committee (V2) server the
    /// URL is configuration rather than an on-chain value.
    aggregator_url: String,
    /// Keyspace package id, which scopes the session.
    package_id: String,
    /// The agent's wallet address. Public data — it is what the certificate
    /// names as `user`, and the key servers match it against the ACL.
    wallet_address: String,
    /// Base64 of the agent's 32-byte Ed25519 wallet public key. Also public:
    /// the certificate carries it so the key servers can check the signature.
    /// The private half never crosses this boundary.
    wallet_public_key_b64: String,
    /// Session lifetime in minutes. ef-agent enforces its own ceiling when it
    /// validates the message this produces.
    ttl_min: u16,
    /// The Keyspace entry ciphertext: BCS of Seal's `EncryptedObject`.
    encrypted_object_b64: String,
    /// BCS of the `seal_approve` programmable transaction. Never signed and
    /// never submitted — the key servers dry-run it against the on-chain ACL.
    ptb_b64: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Response {
    /// Asks the parent to sign; the parent replies with [`SignReply`].
    SignRequest {
        message: String,
    },
    Ok {
        plaintext_b64: String,
    },
    /// A refusal or failure, naming the stage rather than trying to be
    /// machine-readable — the parent logs it.
    Error {
        message: String,
    },
}

#[derive(Debug, Deserialize)]
struct SignReply {
    /// Base64 of the 64-byte raw Ed25519 signature over the session message.
    signature_b64: String,
}

/// A `seal_approve` transaction that was built by the parent.
///
/// Kept as opaque bytes: ef-agent builds the transaction because that is where
/// the object ids and the allowlist live, and passing bytes avoids both sides
/// having to agree on a `sui-sdk-types` version.
struct PreBuiltPtb(Vec<u8>);

impl BCSSerializableProgrammableTransaction for PreBuiltPtb {
    fn to_bcs_bytes(&self) -> Result<Vec<u8>, seal_sdk_rs::error::SealClientError> {
        Ok(self.0.clone())
    }
}

#[tokio::main]
async fn main() {
    let io = Io::new();
    let response = match run(&io).await {
        Ok(plaintext) => Response::Ok {
            plaintext_b64: B64.encode(plaintext),
        },
        // Every error path lands here so the parent always gets one JSON object,
        // never a bare non-zero exit it has to interpret.
        Err(error) => Response::Error {
            message: format!("{error:#}"),
        },
    };
    let failed = matches!(response, Response::Error { .. });
    if let Err(e) = io.write(&response).await {
        eprintln!("seal-decrypt: could not write response: {e:#}");
    }
    if failed {
        std::process::exit(1);
    }
}

async fn run(io: &Io) -> Result<Vec<u8>> {
    let request: Request = io.read_line_json().await.context("reading the request")?;

    let key_server_id = parse_object_id(&request.key_server_object_id, "key_server_object_id")?;
    let package_id = parse_object_id(&request.package_id, "package_id")?;
    let ciphertext = B64
        .decode(&request.encrypted_object_b64)
        .context("encrypted_object_b64 is not valid base64")?;
    let ptb = PreBuiltPtb(
        B64.decode(&request.ptb_b64)
            .context("ptb_b64 is not valid base64")?,
    );

    // Asking the parent to sign. `SessionKey::new` generates the ephemeral key
    // and composes the message; ef-agent independently validates that message
    // before its wallet key goes anywhere near it.
    let mut signer = PipeSigner {
        io,
        address: parse_object_id(&request.wallet_address, "wallet_address")?,
        public_key: B64
            .decode(&request.wallet_public_key_b64)
            .context("wallet_public_key_b64 is not valid base64")?,
    };
    let session_key = SessionKey::new(package_id, request.ttl_min, &mut signer)
        .await
        .context("establishing the Seal session")?;

    let sui = GraphQlSuiClient {
        url: request.graphql_url.clone(),
        http: reqwest::Client::new(),
    };
    let client = BaseSealClient::new_custom(
        NoCache::default(),
        NoCache::default(),
        sui,
        reqwest::Client::new(),
    );

    let mut aggregator_urls = HashMap::new();
    aggregator_urls.insert(key_server_id, request.aggregator_url.clone());

    client
        .decrypt_object_bytes(&ciphertext, ptb, &session_key, aggregator_urls)
        .await
        .context("decrypting the entry")
}

// ── The one on-chain read ───────────────────────────────────────────────────

/// Reads key-server metadata over Sui GraphQL.
///
/// `seal-sdk-rs` ships an implementation backed by the full `sui_sdk`, but that
/// pulls the Sui monorepo for this single query, so it is reimplemented here
/// against the GraphQL endpoint ef-agent already uses for the gas price.
struct GraphQlSuiClient {
    url: String,
    http: reqwest::Client,
}

#[async_trait::async_trait]
impl SuiClient for GraphQlSuiClient {
    type Error = anyhow::Error;

    async fn get_key_server_info(
        &self,
        key_server_id: [u8; 32],
    ) -> Result<KeyServerInfo, Self::Error> {
        let address = format!("0x{}", hex::encode(key_server_id));

        // The KeyServer object holds only a version range; the payload lives in
        // a dynamic field keyed by the u64 version.
        let version = self.supported_version(&address).await?;
        let name_bcs = B64.encode(version.to_le_bytes());
        let query = format!(
            r#"{{ object(address: "{address}") {{ dynamicField(name: {{type: "u64", bcs: "{name_bcs}"}}) {{ value {{ ... on MoveValue {{ json }} }} }} }} }}"#
        );
        let json = self.query(&query).await?;
        let value = json
            .pointer("/data/object/dynamicField/value/json")
            .ok_or_else(|| {
                anyhow::Error::msg(format!("key server {address} has no v{version} record"))
            })?;

        let name = value
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_default()
            .to_string();
        // GraphQL renders the Move `vector<u8>` as base64, but the SDK
        // hex-decodes this field (`decode_public_key`), so re-encode rather
        // than pass it through.
        let public_key_b64 = value
            .get("pk")
            .and_then(|p| p.as_str())
            .ok_or_else(|| anyhow::Error::msg(format!("key server {address} has no public key")))?;
        let public_key = hex::encode(
            B64.decode(public_key_b64)
                .context("key server public key is not valid base64")?,
        );

        Ok(KeyServerInfo {
            object_id: ObjectID(key_server_id),
            name,
            public_key,
            server_type: parse_server_type(value, &address)?,
        })
    }
}

impl GraphQlSuiClient {
    /// Pick the record version to read from the object's supported range.
    async fn supported_version(&self, address: &str) -> Result<u64> {
        let query = format!(
            r#"{{ object(address: "{address}") {{ asMoveObject {{ contents {{ json }} }} }} }}"#
        );
        let json = self.query(&query).await?;
        let contents = json
            .pointer("/data/object/asMoveObject/contents/json")
            .ok_or_else(|| anyhow::Error::msg(format!("no key server object at {address}")))?;
        // Serialised as strings by GraphQL because they are Move u64s.
        let last = contents
            .get("last_version")
            .and_then(|v| v.as_str())
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or_else(|| {
                anyhow::Error::msg(format!("key server {address} reports no last_version"))
            })?;
        Ok(last)
    }

    async fn query(&self, query: &str) -> Result<serde_json::Value> {
        let response = self
            .http
            .post(&self.url)
            .json(&serde_json::json!({ "query": query }))
            .send()
            .await
            .context("sending the GraphQL query")?;
        let status = response.status();
        let text = response.text().await.context("reading the GraphQL body")?;
        if !status.is_success() {
            bail!(
                "sui graphql returned HTTP {}: {}",
                status.as_u16(),
                text.trim()
            );
        }
        let json: serde_json::Value =
            serde_json::from_str(&text).context("GraphQL response was not JSON")?;
        // GraphQL reports query errors with a 200, so the status never
        // establishes success on its own.
        if let Some(first) = json.pointer("/errors/0/message").and_then(|m| m.as_str()) {
            bail!("sui graphql error: {first}");
        }
        Ok(json)
    }
}

/// Map the on-chain `ServerType` enum onto the SDK's representation.
///
/// GraphQL flattens a Move enum into its fields plus an `@variant` tag, which is
/// why this reads `@variant` rather than looking for a nested object.
fn parse_server_type(value: &serde_json::Value, address: &str) -> Result<ServerType> {
    let server_type = value
        .get("server_type")
        .ok_or_else(|| anyhow::Error::msg(format!("key server {address} has no server_type")))?;
    let variant = server_type
        .get("@variant")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    match variant {
        "Independent" => Ok(ServerType::Independent {
            url: server_type
                .get("url")
                .and_then(|u| u.as_str())
                .unwrap_or_default()
                .to_string(),
        }),
        "Committee" => {
            let members = server_type
                .get("partial_key_servers")
                .and_then(|m| m.as_array())
                .map(Vec::as_slice)
                .unwrap_or_default();
            let partial_key_servers = members
                .iter()
                .map(|m| {
                    Ok(PartialKeyServer {
                        name: string_field(m, "name"),
                        url: string_field(m, "url"),
                        partial_pk: B64
                            .decode(string_field(m, "partial_pk"))
                            .context("a committee member's partial_pk is not valid base64")?,
                        // A Move u16 arrives as a JSON string.
                        party_id: string_field(m, "party_id")
                            .parse::<u16>()
                            .unwrap_or_default(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(ServerType::Committee {
                version: numeric_field(server_type, "version") as u32,
                threshold: numeric_field(server_type, "threshold") as u16,
                partial_key_servers,
            })
        }
        other => bail!("key server {address} has an unsupported server type `{other}`"),
    }
}

fn string_field(value: &serde_json::Value, field: &str) -> String {
    value
        .get(field)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

/// Move integers reach GraphQL as either JSON numbers or strings; accept both.
fn numeric_field(value: &serde_json::Value, field: &str) -> u64 {
    match value.get(field) {
        Some(serde_json::Value::String(s)) => s.parse().unwrap_or_default(),
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or_default(),
        _ => 0,
    }
}

// ── Signing, which happens in the parent ────────────────────────────────────

/// A [`Signer`] whose key is in another process.
struct PipeSigner<'a> {
    io: &'a Io,
    /// Supplied by the parent rather than derived here. `SessionKey::new` reads
    /// both of these *before* it asks for a signature, because the certificate
    /// names the signer; neither is secret.
    address: ObjectID,
    public_key: Vec<u8>,
}

#[async_trait::async_trait]
impl Signer for PipeSigner<'_> {
    // Forced by the SDK: `SessionKey::new` requires `SessionKeyError: From<Self::Error>`,
    // and the only unconditional conversion is from `FastCryptoError`. Detail is
    // preserved in the message rather than in the variant.
    type Error = FastCryptoError;

    async fn sign_personal_message(
        &mut self,
        message: Vec<u8>,
    ) -> Result<Ed25519Signature, Self::Error> {
        let message = String::from_utf8(message).map_err(|e| {
            FastCryptoError::GeneralError(format!("session message not UTF-8: {e}"))
        })?;
        self.io
            .write(&Response::SignRequest { message })
            .await
            .map_err(|e| {
                FastCryptoError::GeneralError(format!("asking the parent to sign: {e:#}"))
            })?;
        let reply: SignReply = self.io.read_line_json().await.map_err(|e| {
            FastCryptoError::GeneralError(format!("reading the signature from the parent: {e:#}"))
        })?;
        let bytes = B64
            .decode(&reply.signature_b64)
            .map_err(|e| FastCryptoError::GeneralError(format!("signature not base64: {e}")))?;
        Ed25519Signature::from_bytes(&bytes)
    }

    fn get_public_key(&mut self) -> Result<Ed25519PublicKey, Self::Error> {
        Ed25519PublicKey::from_bytes(&self.public_key)
    }

    fn get_sui_address(&mut self) -> Result<SuiAddress, Self::Error> {
        Ok(SuiAddress(self.address.0))
    }
}

// ── Line-delimited JSON over the pipe ───────────────────────────────────────

/// Owns stdin/stdout so both the request read and the signing round-trip share
/// one buffered reader — a second reader would drop buffered bytes.
struct Io {
    stdin: Mutex<BufReader<Stdin>>,
    stdout: Arc<Mutex<Stdout>>,
}

impl Io {
    fn new() -> Self {
        Self {
            stdin: Mutex::new(BufReader::new(tokio::io::stdin())),
            stdout: Arc::new(Mutex::new(tokio::io::stdout())),
        }
    }

    async fn read_line_json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        let mut guard = self.stdin.lock().await;
        let mut line = String::new();
        let read = guard
            .read_line(&mut line)
            .await
            .context("reading a line from stdin")?;
        if read == 0 {
            bail!("the parent closed the pipe before replying");
        }
        serde_json::from_str(line.trim()).context("input was not the expected JSON")
    }

    async fn write<T: Serialize>(&self, value: &T) -> Result<()> {
        let mut line = serde_json::to_vec(value).context("encoding a response")?;
        line.push(b'\n');
        let mut guard = self.stdout.lock().await;
        guard.write_all(&line).await.context("writing to stdout")?;
        // Flushed because the parent blocks on this line before replying.
        guard.flush().await.context("flushing stdout")
    }
}

fn parse_object_id(text: &str, field: &str) -> Result<ObjectID> {
    let hex_text = text.strip_prefix("0x").unwrap_or(text);
    if hex_text.len() > 64 || hex_text.is_empty() {
        bail!("{field} `{text}` is not a Sui object id");
    }
    let padded = format!("{hex_text:0>64}");
    let bytes = hex::decode(&padded).with_context(|| format!("{field} `{text}` is not hex"))?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::Error::msg(format!("{field} `{text}` is not 32 bytes")))?;
    Ok(ObjectID(bytes))
}
