//! The agent's key, and the only place it is used.
//!
//! Per ADR-013, a non-encryption consumer must not silently reuse ZeroClaw's
//! master encryption key. This type therefore takes key material explicitly
//! from its caller and reaches for no ambient source of its own: it never reads
//! `.secret_key`, never touches `SecretStore`, and derives nothing from the
//! master key. Choosing where an agent's wallet key actually lives is a custody
//! decision that ADR-013 leaves open, and this crate deliberately does not
//! prejudge it.
//!
//! Signing itself is delegated to `sui-crypto`. Sui signs a digest over an
//! intent-prefixed message, and a hand-rolled version that got the prefix wrong
//! would still verify against its own public key while being rejected on chain —
//! a failure that testing in isolation cannot catch.

use std::fmt;

use sui_crypto::SuiSigner;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_sdk_types::{Address, PersonalMessage, Transaction, UserSignature};
use zeroize::Zeroizing;

/// Why key material could not be loaded, or a signature could not be produced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignerError {
    #[error("private key must be 32 bytes, got {0}")]
    KeyLength(usize),
    #[error("private key is not valid `suiprivkey` bech32: {reason}")]
    Bech32 { reason: String },
    #[error("private key is not hex: {reason}")]
    Hex { reason: String },
    #[error("signing failed: {reason}")]
    Signing { reason: String },
}

/// An Ed25519 key that signs for exactly one Sui address.
///
/// `Debug` is implemented by hand to print the address only. A derived one
/// would put key material into any log line that formatted this struct.
pub struct AgentSigner {
    key: Ed25519PrivateKey,
    address: Address,
}

impl fmt::Debug for AgentSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentSigner")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl AgentSigner {
    /// Build from raw 32-byte Ed25519 seed material.
    ///
    /// The caller owns where these bytes came from; see the module note on
    /// ADR-013 before wiring this to any ambient secret store.
    pub fn from_seed(seed: &[u8]) -> Result<Self, SignerError> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| SignerError::KeyLength(seed.len()))?;
        let seed = Zeroizing::new(seed);
        let key = Ed25519PrivateKey::new(*seed);
        let address = key.public_key().derive_address();
        Ok(Self { key, address })
    }

    /// Build from a `suiprivkey1…` bech32 string, the format Sui wallets export.
    pub fn from_bech32(encoded: &str) -> Result<Self, SignerError> {
        let key = Ed25519PrivateKey::from_suiprivkey(encoded.trim()).map_err(|e| {
            SignerError::Bech32 {
                reason: e.to_string(),
            }
        })?;
        let address = key.public_key().derive_address();
        Ok(Self { key, address })
    }

    /// Build from 64 hex characters, with or without a `0x` prefix.
    pub fn from_hex(encoded: &str) -> Result<Self, SignerError> {
        let trimmed = encoded.trim();
        let body = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        if body.len() != 64 {
            return Err(SignerError::KeyLength(body.len() / 2));
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        let (pairs, _) = body.as_bytes().as_chunks::<2>();
        for (index, chunk) in pairs.iter().enumerate() {
            let pair = std::str::from_utf8(chunk).map_err(|e| SignerError::Hex {
                reason: e.to_string(),
            })?;
            seed[index] = u8::from_str_radix(pair, 16).map_err(|e| SignerError::Hex {
                reason: e.to_string(),
            })?;
        }
        Self::from_seed(seed.as_slice())
    }

    /// The address this key signs for.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Sign a fully assembled transaction, gas data included.
    ///
    /// The signature commits to the gas payment as well as the commands, so a
    /// transaction must not be re-gassed after this returns.
    pub fn sign_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<UserSignature, SignerError> {
        self.key
            .sign_transaction(transaction)
            .map_err(|e| SignerError::Signing {
                reason: e.to_string(),
            })
    }

    /// Sign a personal message.
    ///
    /// Present because Keyspace session keys need it. It is deliberately not
    /// exposed as an agent-callable tool: a general "sign this text" capability
    /// driven by model output is a standing phishing primitive, so any caller
    /// must constrain the message it passes here.
    pub fn sign_personal_message(
        &self,
        message: &PersonalMessage<'_>,
    ) -> Result<UserSignature, SignerError> {
        self.key
            .sign_personal_message(message)
            .map_err(|e| SignerError::Signing {
                reason: e.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [7u8; 32];

    #[test]
    fn the_same_seed_always_yields_the_same_address() {
        let a = AgentSigner::from_seed(&SEED).expect("loads");
        let b = AgentSigner::from_seed(&SEED).expect("loads");
        assert_eq!(a.address(), b.address());
    }

    #[test]
    fn different_seeds_yield_different_addresses() {
        let a = AgentSigner::from_seed(&SEED).expect("loads");
        let b = AgentSigner::from_seed(&[9u8; 32]).expect("loads");
        assert_ne!(a.address(), b.address());
    }

    #[test]
    fn hex_and_raw_seeds_agree() {
        let raw = AgentSigner::from_seed(&SEED).expect("loads");
        let hex = AgentSigner::from_hex(&"07".repeat(32)).expect("loads");
        assert_eq!(raw.address(), hex.address());
        let prefixed = AgentSigner::from_hex(&format!("0x{}", "07".repeat(32))).expect("loads");
        assert_eq!(raw.address(), prefixed.address());
    }

    #[test]
    fn wrong_length_keys_are_rejected() {
        assert!(matches!(
            AgentSigner::from_seed(&[0u8; 31]),
            Err(SignerError::KeyLength(31))
        ));
        assert!(AgentSigner::from_hex("abcd").is_err());
    }

    #[test]
    fn non_hex_is_rejected() {
        assert!(matches!(
            AgentSigner::from_hex(&"zz".repeat(32)),
            Err(SignerError::Hex { .. })
        ));
    }

    #[test]
    fn malformed_bech32_is_rejected() {
        assert!(matches!(
            AgentSigner::from_bech32("suiprivkey1nonsense"),
            Err(SignerError::Bech32 { .. })
        ));
    }

    #[test]
    fn debug_output_never_contains_key_material() {
        let signer = AgentSigner::from_seed(&SEED).expect("loads");
        let rendered = format!("{signer:?}");
        assert!(rendered.contains("AgentSigner"));
        assert!(!rendered.contains("07070707"), "key material leaked");
        // The address is public information and is useful in logs.
        assert!(rendered.contains(&signer.address().to_string()));
    }
}
