# Changelog

## 2026-11-24 — KMS Ed25519 signatures proven on Sui devnet (ZERO-2)

An AWS KMS `ECC_NIST_EDWARDS25519` key signed a Sui transaction and devnet executed it (digest `35R2DGt79FfzpBkiCcNqXq4S7Uzo1RA5djuQ1h2oqUpE`). KMS must be given the 32-byte `Blake2b-256(intent || tx_bytes)`, which is `sui-crypto`'s `signing_digest()`, with `ED25519_SHA_512` and message type `RAW`; its raw 64-byte signature is wrapped as `0x00 || sig || pubkey`. `zeroclaw-sui/tests/kms_signature.rs` pins this against the recorded transaction, and `scripts/ef-agent/kms_sui_spike.py` reproduces it.

## 2026-11-24 — Seal decryption and GraphQL RPC landed; pilots planned

PR #4 landed `ef_keyspace_decrypt` with the `sidecars/seal-decrypt` child process, moved `[sui].rpc_url` to Sui GraphQL, and removed `[[sui.spend_caps]]`. The overview's status table now records it, and points at ROAD-66 for the plan to run ef-agent pilots on the cluster with KMS-held keys.

## 2026-11-23 — cortex onboarding

Bootstrapped `.cortex/` directory. Service registered with the Cortex knowledge ledger. The overview gives a project outline: what ef-agent is, the prepare/commit split, and how to add triex-mcp, the Sui wallet, Seal/Keyspace, and Cortex itself.
