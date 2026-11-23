# ef-agent

ef-agent is a fork of [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw), a
self-hosted agent runtime written in Rust. The fork turns ZeroClaw into an
autonomous operator for **Trinary Exchange (TriEx)** on Sui, in the EVE
Frontier ecosystem.

It is **not** a game character and it never writes to world-contracts. It
reads chain and market state, has transactions built for it by a keyless
service, and commits its own key only to transactions it has checked itself.
Everything ZeroClaw already does (LLM providers, chat channels, memory, cron,
gateway, MCP client) is inherited unchanged. The fork adds only the half that
must hold a key.

## Status (2026-11-23)

| Piece | Where | State |
|---|---|---|
| ZeroClaw runtime | `master` | Tracks upstream |
| TriEx read and prepare via `triex-mcp` | PR #1 (`test/triex-mcp-connectivity-spike`) | Works with configuration only. Covered by an ignored live test |
| `zeroclaw-sui` crate and `ef_submit` tool | PR #2 (`feat/sui-prepared-transaction-verification`) | Built and unit-tested. **Never submitted to a real chain** |
| Seal / Keyspace decryption (`ef_keyspace_decrypt`, `sidecars/seal-decrypt`) | Same branch, not yet committed | In progress |
| Cortex onboarding | This directory | Docs only |

## How ZeroClaw works

ZeroClaw is a single binary that you configure and run. A turn moves through
these stages:

1. **Channels** bring messages in. There are 30+ channels, including CLI,
   Discord, Telegram, Matrix, email, webhooks and the gateway's REST/WebSocket
   API.
2. **The runtime** builds the prompt from memory, skills and SOPs, then calls a
   **provider** (Anthropic, OpenAI, OpenRouter, Ollama and about 20 others).
3. **Tools** carry out the model's tool calls. Native tools (shell, HTTP,
   browser, files, memory, cron) are compiled in. MCP tools are discovered at
   runtime from configured servers.
4. **The security policy** gates every tool call. It applies the autonomy level,
   risk-profile allow and exclude lists, and the approval routing for
   `ToolOperation::Act` tools.

### Crate map

| Crate | Role |
|---|---|
| `zeroclaw-runtime` | Agent loop and tool registry (`src/tools/mod.rs` registers the ef tools) |
| `zeroclaw-tools` | Native tools, including `ef_submit` and `ef_keyspace_decrypt`, and the MCP client (`mcp_client`) |
| `zeroclaw-config` | TOML schema. The `[sui]`, `[sui.seal]` and `[mcp]` sections are the ones ef-agent uses |
| `zeroclaw-sui` | **ef-agent specific.** Verifies prepared transactions, signs, sponsors gas, submits, and handles Seal sessions |
| `zeroclaw-providers` | LLM provider adapters |
| `zeroclaw-channels` | Inbound and outbound messaging |
| `zeroclaw-gateway` | REST/WebSocket API and dashboard backend |
| `zeroclaw-memory` | Long-term memory |
| `zeroclaw-plugins`, `wit/` | WASM plugin host and its WIT interfaces |
| `sidecars/seal-decrypt` | **ef-agent specific.** A separate workspace for BLS12-381 Seal decryption |

## Core design: the prepare/commit split

```
           ┌──────────────────────┐   read + prepare_* (keyless)   ┌──────────────┐
  LLM ───▶ │ ef-agent (ZeroClaw)  │ ─────────── MCP ─────────────▶ │  triex-mcp   │
           │                      │ ◀── {txKindBytes, intent, …} ──│ (@trinaryex/ │
           │  ef_submit (native)  │                                 │     sdk)     │
           │   1. verify bytes    │                                 └──────────────┘
           │   2. reserve gas ────┼──▶ signer-api sponsorship (validates + funds)
           │   3. sign (own key)  │
           │   4. execute ────────┼──▶ signer-api ──▶ Sui
           └──────────────────────┘
```

- **Building is outsourced.** `triex-mcp` returns unsigned transaction kinds as
  `{txKindBytes, sender, intent, pinnedObjects, builtAtMs, notes}`.
- **Deciding stays local.** `zeroclaw_sui::verify` re-derives every fact from the
  BCS bytes. The builder's JSON is parsed only so it can be contradicted. If the
  declared intent and the decoded commands disagree, the payload is refused.
- **The rules are default-closed:**
  - Only programmable transactions are accepted.
  - Every Move call must match `allowed_targets`. Targets are compared as parsed
    addresses, so `0x2::` matches the padded form.
  - `TransferObjects` may only send to the agent's own address.
  - `Publish` and `Upgrade` are refused.
  - Unknown enum variants and trailing bytes are refused.
  - Sender, freshness (`max_prepared_age_secs`) and command count are checked.
- **There is no spend cap.** `worstCaseSpend` is the builder's own figure and
  cannot be recovered from bytes. The target allowlist is what bounds loss.
- **Gas is sponsored.** The signer-api reviews the unsigned body against its own
  allowlist, sets the budget, and returns the sponsor's coins. The agent refuses
  any budget above `max_gas_budget`, then signs and executes.
- **`200 OK` is not success.** `execute` answers `200` even when submission failed
  (the failure is in `error`) or when the Move call aborted (it is in
  `effects.status`). The client checks both.

## Augmenting ef-agent with external tooling

### General mechanism: MCP servers

Any MCP server (stdio, HTTP or SSE) can be added under `[[mcp.servers]]`. Its
tools appear to the model as `<server>__<tool>`. Set
`mcp.deferred_loading = true` to keep large tool catalogs out of the prompt.
The model then fetches schemas on demand through `tool_search`.

> **Caution: adding an MCP server grants privileges.** A non-empty risk-profile
> `allowed_tools` list does not constrain MCP tools. Any name containing `__` is
> admitted automatically, and only `excluded_tools` blocks an individual MCP
> tool. Audit `excluded_tools` every time you add a server. Any tool that holds a
> key or writes must be **native**, never MCP.

### Trinary Exchange SDK MCP (`triex-mcp`)

- Endpoint (dev): `https://triex-mcp-dev-api.trinary.exchange/mcp`. It is
  versioned in lock-step with `@trinaryex/sdk`.
- 25 tools: 14 reads and 11 `prepare_*` builders, for example
  `keyspace_list_accessible` and `keyspace_get_acl`. All of them are keyless and
  side-effect-free.
- Requires no Rust. Configuration alone is enough:

```toml
[[mcp.servers]]
name = "triex"
transport = "http"
url = "https://triex-mcp-dev-api.trinary.exchange/mcp"
headers = { "x-api-key" = "sk_..." }
tool_timeout_secs = 30
```

- To run the live test:
  `TRIEX_API_KEY=… TRIEX_TEST_ADDRESS=0x… cargo test -p zeroclaw-tools --test triex_mcp_spike -- --ignored`
- On a cycle rollover, the SDK and MCP get new package IDs. Update
  `allowed_targets` to match. The Cortex skill `new-cycle-deployment` has the
  procedure.

### Sui wallet (native signer and `ef_submit`)

The wallet is deliberately not an MCP server, so that the allow-list and
autonomy gating apply to it. `ef_submit` is registered as `ToolOperation::Act`.

```toml
[sui]
enabled = false                 # off: the tool is not registered at all
rpc_url = "https://graphql.testnet.sui.io/graphql"   # GraphQL, not fullnode JSON-RPC
private_key = "suiprivkey1…"    # its own secret (ADR-013), not derived from the master key
gas_station_url = "https://signer-api.trinary.exchange"
gas_station_token = "<signer-api JWT>"   # a JWT, not the TriEx API key
max_gas_budget = 50000000       # MIST; a refusal threshold
max_prepared_age_secs = 120
allowed_targets = []            # "pkg::module::function"; empty signs nothing
```

- The reference gas price is fetched over GraphQL on every submission, because
  a hardcoded price goes stale at the next epoch.
- `sign_personal_message` exists, but the agent cannot call it.

### Seal / Keyspace decryption (`ef_keyspace_decrypt`)

This tool reads Seal-encrypted Keyspace entries. The agent's input is only the
identifiers that `triex__keyspace_get_acl` returned.

- The BLS12-381 work runs in `sidecars/seal-decrypt`, a child process with its
  own workspace and lockfile. Keeping it separate keeps `fastcrypto` and its
  duplicate RustCrypto tree out of the graph that signs transactions, so
  `deny.toml` stays strict.
- The wallet key never crosses the pipe. The child proposes a session message,
  and ef-agent checks the template, package, TTL and freshness before it signs.
- Before anything is fetched or signed, these checks run:
  - the entry URI is `https` on an `allowed_entry_hosts` host;
  - the ciphertext names the configured package (read from its own bytes);
  - the policy id is prefixed by the named Keyspace.

```toml
[sui.seal]
enabled = false
aggregator_url = "https://seal-aggregator-testnet.mystenlabs.com"
key_server_object_id = "0x…"
package_id = "0x…"              # Keyspace package
session_ttl_min = 10            # short on purpose
sidecar_path = "/path/to/seal-decrypt"
allowed_entry_hosts = []        # empty means nothing is fetched
```

### Cortex

Cortex plays two roles:

1. **Knowledge home for this repo.** This `.cortex/` directory is ingested on
   merge to `master`. Before each commit, use `chronicle_changes` with
   `service_id: "ef-agent"` to keep `changelog.md` and this overview current.
2. **A tool source for the running agent.** Cortex is an HTTP MCP server, so
   ef-agent can query org knowledge at runtime: service docs, runbooks, API
   contracts and conventions.

```toml
[[mcp.servers]]
name = "cortex"
transport = "http"
url = "https://cortex-relay-dev-api.trinary.exchange/mcp"
headers = { "Authorization" = "Bearer <cortex key>" }
```

   Cortex tools are read-mostly. The exceptions, `chronicle_changes` and
   `resolve_pr_reviews` (which auto-replies to PR comments), belong in
   `excluded_tools` for an autonomous agent.

### Other extension points

- **Skills and SOPs:** procedural know-how loaded into the prompt, with no code
  required.
- **WASM plugins** (`wit/`, `zeroclaw-plugins`): sandboxed native-speed tools.
  The WIT interfaces are versioned and frozen.
- **Channels:** expose the agent to Discord or Telegram operators, or drive it
  through gateway webhooks or cron.

### Checklist for a new integration

1. Is it read-only and keyless? Make it an MCP server and configure it.
2. Does it hold a key, write, or spend? Make it a native tool with
   `ToolOperation::Act`, a default-off config section, and default-closed
   allowlists.
3. Audit `excluded_tools` against the new server's tool list.
4. Treat every model-supplied identifier as a claim, and re-derive it from bytes
   or on-chain state.

## Development notes

- **Toolchain:** the MSRV is 1.96 and there is no `rust-toolchain.toml`. Use
  `rustup run stable cargo …`.
- **Disk:** `cargo check --workspace --all-targets` can fill the disk because it
  pulls tauri and wasmtime. Use `cargo check --workspace` plus
  `cargo clippy -p <crate> --all-targets`.
- **Tests:** `cargo test -p zeroclaw-sui` and `cargo test -p zeroclaw-tools`.

## Known gaps

- No transaction has been submitted end to end. Gas pricing, reservation
  expiry and on-chain acceptance are unexercised, and there is no funded key or
  signer-api JWT yet.
- The allowlist is the only bound on loss. A broad target such as a generic
  `transfer` widens it a lot.
- `triex-mcp` tools are admitted automatically. A future write-capable tool on
  that server would be admitted silently unless it is excluded.
