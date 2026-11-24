//! A signature made by AWS KMS, accepted by Sui (ZERO-2).
//!
//! The fixture was recorded by the spike: an `ECC_NIST_EDWARDS25519` KMS key
//! signed `Blake2b-256(intent || tx_bytes)` with `ED25519_SHA_512` and message
//! type `RAW`, and devnet executed the transaction. These tests pin the two
//! facts a KMS signing backend depends on, without needing AWS or a network:
//!
//! - the 32-byte message KMS must be given is exactly `sui-crypto`'s
//!   `signing_digest()`, so no pre-hashing variant (`ED25519_PH_SHA_512`) is
//!   involved;
//! - KMS's raw 64-byte signature, wrapped as `flag || sig || pubkey`, verifies
//!   with `sui-crypto` and belongs to the address that sent the transaction.

use serde_json::Value;
use sui_crypto::SuiVerifier;
use sui_crypto::ed25519::Ed25519VerifyingKey;
use sui_sdk_types::{SimpleSignature, Transaction, UserSignature};

const FIXTURE: &str = include_str!("fixtures/kms_devnet_signature.json");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("fixture is JSON")
}

fn field<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("fixture field {key}"))
}

fn transaction(v: &Value) -> Transaction {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(field(v, "tx_bytes"))
        .expect("tx bytes are base64");
    bcs::from_bytes(&bytes).expect("tx bytes are a Transaction")
}

#[test]
fn the_message_kms_signed_is_the_sui_signing_digest() {
    let v = fixture();
    let digest = transaction(&v).signing_digest();
    assert_eq!(hex::encode(digest), field(&v, "signing_message_hex"));
}

#[test]
fn the_kms_signature_verifies_with_sui_crypto() {
    let v = fixture();
    let tx = transaction(&v);
    let signature = UserSignature::from_base64(field(&v, "signature")).expect("signature decodes");
    let UserSignature::Simple(SimpleSignature::Ed25519 { public_key, .. }) = &signature else {
        panic!("expected a simple Ed25519 signature, got {signature:?}");
    };
    let key = Ed25519VerifyingKey::new(public_key).expect("public key is a valid point");

    key.verify_transaction(&tx, &signature)
        .expect("KMS signature verifies");
    assert_eq!(
        public_key.derive_address().to_string(),
        field(&v, "address")
    );
    assert_eq!(tx.sender.to_string(), field(&v, "address"));
}

#[test]
fn the_kms_signature_does_not_verify_for_another_transaction() {
    let v = fixture();
    let mut tx = transaction(&v);
    tx.gas_payment.budget += 1;
    let signature = UserSignature::from_base64(field(&v, "signature")).expect("signature decodes");
    let UserSignature::Simple(SimpleSignature::Ed25519 { public_key, .. }) = &signature else {
        panic!("expected a simple Ed25519 signature");
    };
    let key = Ed25519VerifyingKey::new(public_key).expect("public key is a valid point");
    assert!(key.verify_transaction(&tx, &signature).is_err());
}
