//! Connectivity spike: drive the real triex-mcp deployment through ZeroClaw's
//! own MCP client, proving the read/prepare surface is reachable with config
//! alone (no ef-agent Rust code).
//!
//! Ignored by default — needs network and a live TriEx API key:
//!   TRIEX_API_KEY=sk_... TRIEX_TEST_ADDRESS=0x... \
//!     cargo test -p zeroclaw-tools --test triex_mcp_spike -- --ignored --nocapture
//!
//! `TRIEX_TEST_ADDRESS` is supplied by the operator rather than hardcoded: a real
//! on-chain account is an identity, and the privacy contract keeps those out of
//! the tree. Any address with at least one accessible Keyspace ACL works.

use std::collections::HashMap;

use zeroclaw_config::schema::{McpServerConfig, McpTransport};
use zeroclaw_tools::mcp_client::McpServer;

const TRIEX_MCP_URL: &str = "https://triex-mcp-dev-api.trinary.exchange/mcp";

fn config(api_key: &str) -> McpServerConfig {
    let mut headers = HashMap::new();
    headers.insert("x-api-key".to_string(), api_key.to_string());
    McpServerConfig {
        name: "triex".to_string(),
        transport: McpTransport::Http,
        url: Some(TRIEX_MCP_URL.to_string()),
        headers,
        tool_timeout_secs: Some(30),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires network + TRIEX_API_KEY"]
async fn triex_mcp_surface_is_reachable() {
    let api_key = std::env::var("TRIEX_API_KEY").expect("TRIEX_API_KEY must be set");
    let server = McpServer::connect(config(&api_key))
        .await
        .expect("connect to triex-mcp");

    let tools = server.tools().await;
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    println!("server name : {}", server.name().await);
    println!("tool count  : {}", tools.len());

    let reads = names.iter().filter(|n| !n.starts_with("prepare_")).count();
    let prepares = names.iter().filter(|n| n.starts_with("prepare_")).count();
    println!("read tools  : {reads}");
    println!("prepare     : {prepares}");

    for expected in ["keyspace_list_accessible", "keyspace_get_acl"] {
        assert!(names.contains(&expected), "missing tool `{expected}`");
    }
    assert_eq!(tools.len(), 25, "unexpected tool count: {names:?}");

    for t in &tools {
        assert_eq!(
            t.input_schema.get("type").and_then(|v| v.as_str()),
            Some("object"),
            "tool `{}` has no object input schema",
            t.name
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires network + TRIEX_API_KEY + TRIEX_TEST_ADDRESS"]
async fn triex_mcp_read_executes_end_to_end() {
    let api_key = std::env::var("TRIEX_API_KEY").expect("TRIEX_API_KEY must be set");
    let server = McpServer::connect(config(&api_key)).await.expect("connect");

    let addr = std::env::var("TRIEX_TEST_ADDRESS")
        .expect("TRIEX_TEST_ADDRESS must be set to an address holding Keyspace access");
    let res = server
        .call_tool(
            "keyspace_list_accessible",
            serde_json::json!({ "address": &addr }),
        )
        .await
        .expect("keyspace_list_accessible");

    let text = res["content"][0]["text"].as_str().expect("text content");
    println!("keyspace_list_accessible -> {text}");
    let parsed: serde_json::Value = serde_json::from_str(text).expect("tool returns JSON");
    assert_eq!(parsed["address"], addr.as_str());
    assert!(
        parsed["count"].as_u64().expect("count") >= 1,
        "expected at least one accessible ACL"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires network + TRIEX_API_KEY"]
async fn triex_mcp_prepare_returns_unsigned_tx() {
    let api_key = std::env::var("TRIEX_API_KEY").expect("TRIEX_API_KEY must be set");
    let server = McpServer::connect(config(&api_key)).await.expect("connect");

    let sender = "0x1111111111111111111111111111111111111111111111111111111111111111";
    let res = server
        .call_tool(
            "prepare_create_account",
            serde_json::json!({ "sender": sender }),
        )
        .await
        .expect("prepare_create_account");

    let text = res["content"][0]["text"].as_str().expect("text content");
    let p: serde_json::Value = serde_json::from_str(text).expect("prepared payload is JSON");
    println!(
        "prepare_create_account -> {}",
        serde_json::to_string_pretty(&p).unwrap()
    );

    assert_eq!(p["sender"], sender);
    assert!(p["txKindBytes"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(
        p["intent"]["targets"]
            .as_array()
            .is_some_and(|t| !t.is_empty())
    );

    // The whole point of the split: no key material ever crosses this boundary.
    let blob = text.to_lowercase();
    for forbidden in ["privatekey", "signature", "suiprivkey", "secretkey"] {
        assert!(
            !blob.contains(forbidden),
            "prepared payload leaked `{forbidden}`"
        );
    }
}
