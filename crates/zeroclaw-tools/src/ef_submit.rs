//! `ef_submit` — commit the agent's key to a transaction it did not build.
//!
//! This is deliberately a **native** tool rather than one reached over MCP.
//! ZeroClaw auto-admits any runtime-discovered MCP tool (any name containing
//! `__`) into a non-empty `allowed_tools` list, so an MCP-hosted version of
//! this capability would bypass the very allow-list an operator would reach for
//! to constrain it. As a native tool it is gated normally, and it declares
//! `ToolOperation::Act` so autonomy level and approval routing apply.
//!
//! The tool holds the key; it does not decide what is safe. Every judgement
//! about the transaction is made by `zeroclaw_sui::verify` against a policy
//! built from configuration, from the transaction bytes rather than from the
//! builder's description of them.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde_json::json;
use zeroclaw_api::tool::{Tool, ToolOutput, ToolResult};
use zeroclaw_config::policy::{SecurityPolicy, ToolOperation};
use zeroclaw_config::schema::SuiConfig;
use zeroclaw_sui::{
    AgentSigner, GasStation, PreparedTransaction, SubmitPolicy, SubmitRequest, SuiRpc,
};

/// Everything the tool needs that does not come from the model.
pub struct EfSubmitTool {
    signer: Arc<AgentSigner>,
    station: Arc<GasStation>,
    rpc: SuiRpc,
    policy: Arc<SubmitPolicy>,
    max_gas_budget: u64,
    security: Arc<SecurityPolicy>,
}

impl EfSubmitTool {
    pub const NAME: &'static str = "ef_submit";

    pub fn new(
        signer: Arc<AgentSigner>,
        station: Arc<GasStation>,
        rpc: SuiRpc,
        policy: Arc<SubmitPolicy>,
        max_gas_budget: u64,
        security: Arc<SecurityPolicy>,
    ) -> Self {
        Self {
            signer,
            station,
            rpc,
            policy,
            max_gas_budget,
            security,
        }
    }

    /// The address this tool signs for. Useful for diagnostics and for the
    /// caller that wants to check configuration lines up before enabling it.
    pub fn address(&self) -> String {
        self.signer.address().to_string()
    }

    /// Build from `[sui]` configuration.
    ///
    /// Every failure here is a refusal to construct the tool at all, so a
    /// deployment with a typo in an allow-list entry starts without
    /// `ef_submit` rather than with a silently narrower one. The error is a
    /// plain string so the caller can log it without leaking the key or token
    /// that sit beside it in config.
    pub fn from_config(config: &SuiConfig, security: Arc<SecurityPolicy>) -> Result<Self, String> {
        if config.gas_station_url.trim().is_empty() {
            return Err("sui.gas_station_url is required".to_string());
        }
        if config.gas_station_token.trim().is_empty() {
            return Err("sui.gas_station_token is required".to_string());
        }
        if config.rpc_url.trim().is_empty() {
            return Err("sui.rpc_url is required".to_string());
        }

        let raw_key = config.private_key.trim();
        if raw_key.is_empty() {
            return Err("sui.private_key is required".to_string());
        }
        let signer = if raw_key.starts_with("suiprivkey") {
            AgentSigner::from_bech32(raw_key)
        } else {
            AgentSigner::from_hex(raw_key)
        }
        // The error carries no key material, but say so explicitly rather than
        // interpolating anything derived from the input.
        .map_err(|e| format!("sui.private_key could not be loaded: {e}"))?;

        let mut policy = SubmitPolicy::deny_all(signer.address())
            .with_max_age(Duration::from_secs(config.max_prepared_age_secs));
        for raw in &config.allowed_targets {
            let target = raw
                .parse()
                .map_err(|e| format!("sui.allowed_targets entry `{raw}` is invalid: {e}"))?;
            policy = policy.allow_target(target);
        }

        Ok(Self::new(
            Arc::new(signer),
            Arc::new(GasStation::new(
                config.gas_station_url.trim(),
                config.gas_station_token.trim(),
            )),
            SuiRpc::new(config.rpc_url.trim()),
            Arc::new(policy),
            config.max_gas_budget,
            security,
        ))
    }
}

/// Written by hand rather than derived. The signer and gas-station client each
/// redact themselves, but spelling out exactly what appears here keeps a future
/// field from being printed by accident.
impl std::fmt::Debug for EfSubmitTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EfSubmitTool")
            .field("address", &self.signer.address())
            .field("max_gas_budget", &self.max_gas_budget)
            .field("allowed_targets", &self.policy.allowed_targets.len())
            .finish_non_exhaustive()
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
impl Tool for EfSubmitTool {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn description(&self) -> &str {
        "Sign and submit a transaction that was prepared by a keyless builder \
         (such as a Trinary Exchange `prepare_*` tool), paying gas through the \
         sponsored gas station. Pass the builder's response object unchanged as \
         `prepared`. The transaction is re-checked against this agent's own \
         allow-list from its bytes before anything is signed; a payload that \
         calls anything unapproved, pays out to another address, is stale, or \
         was prepared for a different account is refused. Submitting moves real \
         value and cannot be undone."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "prepared": {
                    "type": "object",
                    "description": "The prepared-transaction object exactly as the builder returned it. \
                        Must contain txKindBytes, sender, intent, and builtAtMs. Do not edit any field: \
                        the bytes are what gets signed, and altering the description around them only \
                        causes the submission to be refused."
                }
            },
            "required": ["prepared"]
        })
    }

    fn output_schema(&self) -> Option<serde_json::Value> {
        Some(json!({
            "type": "object",
            "properties": {
                "submitted": { "type": "boolean" },
                "digest": { "type": "string" },
                "reservationId": { "type": "integer" },
                "gasBudget": { "type": "integer" },
                "targets": { "type": "array", "items": { "type": "string" } },
                "gasPrice": { "type": "integer" },
                "effects": { "type": "object" }
            },
            "required": ["submitted", "digest", "targets"]
        }))
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        if let Err(error) = self
            .security
            .enforce_tool_operation(ToolOperation::Act, Self::NAME)
        {
            return Ok(failed(error));
        }

        let Some(prepared_value) = args.get("prepared") else {
            return Ok(failed("`prepared` is required"));
        };
        // Re-serializing here rather than deserializing the borrowed value keeps
        // one parsing path: whatever the model passed is read exactly the way a
        // builder response is read.
        let prepared = match serde_json::to_string(prepared_value)
            .map_err(|e| e.to_string())
            .and_then(|raw| PreparedTransaction::from_json(&raw).map_err(|e| e.to_string()))
        {
            Ok(prepared) => prepared,
            Err(reason) => {
                return Ok(failed(format!(
                    "`prepared` is not a builder response: {reason}"
                )));
            }
        };

        let now_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(since) => match u64::try_from(since.as_millis()) {
                Ok(ms) => ms,
                Err(_) => return Ok(failed("system clock is beyond the representable range")),
            },
            Err(_) => return Ok(failed("system clock is before the Unix epoch")),
        };

        // Read the gas price before reserving so a stale-price failure costs
        // nothing; the reservation is the only step with a side effect.
        let gas_price = match self.rpc.reference_gas_price().await {
            Ok(price) => price,
            Err(e) => {
                return Ok(failed(format!(
                    "could not read the reference gas price: {e}"
                )));
            }
        };

        let request = SubmitRequest {
            prepared: &prepared,
            policy: &self.policy,
            max_gas_budget: self.max_gas_budget,
            gas_price,
            now_ms,
        };

        match zeroclaw_sui::submit(request, &self.signer, &self.station).await {
            Ok(submitted) => {
                let targets: Vec<String> =
                    submitted.targets.iter().map(|t| t.canonical()).collect();
                let summary = format!(
                    "Submitted {} call(s) as {} (digest {}): {}",
                    targets.len(),
                    self.signer.address(),
                    submitted.outcome.digest,
                    targets.join(", ")
                );
                let data = json!({
                    "submitted": true,
                    "digest": submitted.outcome.digest,
                    "reservationId": submitted.reservation_id,
                    "targets": targets,
                    "gasPrice": gas_price,
                    "gasBudget": submitted.gas_budget,
                    "effects": submitted.outcome.effects,
                });
                Ok(ToolResult {
                    success: true,
                    output: ToolOutput::json_with_text(data, summary),
                    error: None,
                })
            }
            // A refusal is a normal, non-fatal outcome: the model should see why
            // and stop, not retry the same payload against a different tool.
            Err(e) => Ok(failed(format!("refused to submit: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use zeroclaw_config::policy::SecurityPolicy;
    use zeroclaw_sui::Address;

    fn security() -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy::default())
    }

    fn tool() -> EfSubmitTool {
        let signer = Arc::new(AgentSigner::from_seed(&[7u8; 32]).expect("key loads"));
        let policy = Arc::new(SubmitPolicy::deny_all(signer.address()));
        EfSubmitTool::new(
            signer,
            Arc::new(GasStation::new("https://unused.example", "token")),
            SuiRpc::new("https://unused.example"),
            policy,
            100_000_000,
            security(),
        )
    }

    #[test]
    fn the_tool_is_named_for_its_native_registration() {
        assert_eq!(tool().name(), "ef_submit");
    }

    #[test]
    fn the_schema_requires_the_builder_payload_verbatim() {
        let schema = tool().parameters_schema();
        assert_eq!(schema["required"][0], "prepared");
        assert_eq!(schema["properties"]["prepared"]["type"], "object");
    }

    #[test]
    fn the_description_warns_that_submission_is_irreversible() {
        let description = tool().description().to_lowercase();
        assert!(description.contains("cannot be undone"));
    }

    #[tokio::test]
    async fn a_missing_payload_is_a_non_fatal_refusal() {
        let result = tool().execute(json!({})).await.expect("non-fatal");
        assert!(!result.success);
        assert!(
            result.error.unwrap_or_default().contains("required"),
            "should name the missing field"
        );
    }

    #[tokio::test]
    async fn a_malformed_payload_is_rejected_before_any_network_call() {
        // The endpoints above are unroutable; reaching them would hang or error
        // differently. A parse refusal proves nothing was contacted.
        let result = tool()
            .execute(json!({ "prepared": { "nonsense": true } }))
            .await
            .expect("non-fatal");
        assert!(!result.success);
        assert!(
            result
                .error
                .unwrap_or_default()
                .contains("not a builder response")
        );
    }

    #[test]
    fn the_tool_reports_the_address_it_signs_for() {
        let signer = AgentSigner::from_seed(&[7u8; 32]).expect("key loads");
        assert_eq!(tool().address(), signer.address().to_string());
        assert!(Address::from_str(&tool().address()).is_ok());
    }

    fn valid_config() -> SuiConfig {
        SuiConfig {
            enabled: true,
            gas_station_url: "https://gas.example".to_string(),
            gas_station_token: "token".to_string(),
            rpc_url: "https://rpc.example".to_string(),
            private_key: "07".repeat(32),
            allowed_targets: vec!["0x2::coin::zero".to_string()],
            ..SuiConfig::default()
        }
    }

    #[test]
    fn a_valid_config_builds_a_tool_that_signs_for_the_configured_key() {
        let tool = EfSubmitTool::from_config(&valid_config(), security()).expect("builds");
        let expected = AgentSigner::from_seed(&[7u8; 32]).expect("key loads");
        assert_eq!(tool.address(), expected.address().to_string());
    }

    #[test]
    fn each_required_field_is_actually_required() {
        for (name, mutate) in [
            (
                "gas_station_url",
                (|c: &mut SuiConfig| c.gas_station_url.clear()) as fn(&mut SuiConfig),
            ),
            ("gas_station_token", |c: &mut SuiConfig| {
                c.gas_station_token.clear()
            }),
            ("rpc_url", |c: &mut SuiConfig| c.rpc_url.clear()),
            ("private_key", |c: &mut SuiConfig| c.private_key.clear()),
        ] {
            let mut config = valid_config();
            mutate(&mut config);
            let err = EfSubmitTool::from_config(&config, security())
                .err()
                .unwrap_or_else(|| panic!("{name} should be required"));
            assert!(err.contains(name), "error should name {name}, got: {err}");
        }
    }

    #[test]
    fn a_bad_allow_list_entry_prevents_registration_rather_than_narrowing_it() {
        // Failing closed matters here: silently dropping the unparseable entry
        // would leave the agent running with an allow-list nobody wrote.
        let mut config = valid_config();
        config.allowed_targets.push("0x2::coin".to_string());
        let err = EfSubmitTool::from_config(&config, security()).expect_err("must refuse");
        assert!(err.contains("allowed_targets"), "{err}");
    }

    #[test]
    fn an_unreadable_private_key_is_refused_without_echoing_it() {
        let mut config = valid_config();
        config.private_key = "not-a-key".to_string();
        let err = EfSubmitTool::from_config(&config, security()).expect_err("must refuse");
        assert!(err.contains("private_key"), "{err}");
        assert!(!err.contains("not-a-key"), "error echoed the key: {err}");
    }

    #[test]
    fn debug_output_leaks_neither_the_key_nor_the_gas_station_token() {
        let mut config = valid_config();
        config.gas_station_token = "super-secret-token".to_string();
        let tool = EfSubmitTool::from_config(&config, security()).expect("builds");
        let rendered = format!("{tool:?}");
        assert!(rendered.contains("EfSubmitTool"));
        assert!(!rendered.contains("super-secret-token"), "token leaked");
        assert!(!rendered.contains("07070707"), "key material leaked");
    }

    #[test]
    fn an_empty_allow_list_still_builds_but_signs_nothing() {
        // Registration succeeds so the misconfiguration is visible as refusals
        // at call time rather than as a silently missing tool.
        let mut config = valid_config();
        config.allowed_targets.clear();
        let tool = EfSubmitTool::from_config(&config, security()).expect("builds");
        assert!(tool.policy.allowed_targets.is_empty());
    }
}
