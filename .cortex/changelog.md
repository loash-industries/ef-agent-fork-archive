# Changelog

## 2026-11-24 — Seal decryption and GraphQL RPC landed; pilots planned

PR #4 landed `ef_keyspace_decrypt` with the `sidecars/seal-decrypt` child process, moved `[sui].rpc_url` to Sui GraphQL, and removed `[[sui.spend_caps]]`. The overview's status table now records it, and points at ROAD-66 for the plan to run ef-agent pilots on the cluster with KMS-held keys.

## 2026-11-23 — cortex onboarding

Bootstrapped `.cortex/` directory. Service registered with the Cortex knowledge ledger. The overview gives a project outline: what ef-agent is, the prepare/commit split, and how to add triex-mcp, the Sui wallet, Seal/Keyspace, and Cortex itself.
