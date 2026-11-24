//! The Seal session key, and the one message this agent's wallet key signs for it.
//!
//! Reading a Keyspace entry needs a signature, but not over a transaction. Seal
//! asks the wallet to sign a short English sentence that names a package, a
//! lifetime, and an ephemeral public key. The key servers rebuild that exact
//! sentence from the certificate fields and check the signature against it, so
//! the string this module produces has to match theirs byte for byte — the
//! regression test below pins it against Mysten's own vector.
//!
//! # Why a message is signed at all, and why that is dangerous
//!
//! A signature over attacker-chosen text is a phishing primitive: the same
//! wallet key that moves funds is being asked to endorse arbitrary words. Sui's
//! intent framing means a personal-message signature can never be replayed as a
//! transaction signature — the two digests use different `IntentScope` values —
//! so the danger is not a stolen coin but a session granted to the wrong party,
//! for the wrong package, for too long.
//!
//! Everything in the message is therefore constructed here from configuration
//! and a freshly generated key, never taken from a caller, and
//! [`validate_session_message`] re-derives every field from the finished string
//! before it is handed to the signer. That check is redundant today by
//! construction; it exists so that it stays true if some future caller supplies
//! a message instead of building one.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_sdk_types::Address;
use zeroize::Zeroizing;

use super::SealError;

/// Text every session message opens with.
const MESSAGE_PREFIX: &str = "Accessing keys of package ";
const MESSAGE_FOR: &str = " for ";
const MESSAGE_MINS_FROM: &str = " mins from ";
const MESSAGE_SESSION_KEY: &str = ", session key ";

/// How far the timestamp inside a message may sit from the current clock.
///
/// A message is normally built microseconds before it is validated, so this is
/// slack for clock granularity rather than a real window. Keeping it tight is
/// what stops a pre-dated message — one minted long ago and replayed — from
/// being signed now and yielding a session that outlives its stated lifetime.
const MAX_TIMESTAMP_SKEW_SECS: i64 = 120;

/// An ephemeral Seal session: a throwaway Ed25519 key plus the message that
/// authorises it.
///
/// The secret half authorises nothing on its own — it signs key-server requests
/// that are only honoured alongside the wallet signature over [`Self::message`]
/// — which is why it is the one key allowed to leave this process.
pub struct SealSession {
    secret: Zeroizing<[u8; 32]>,
    public_b64: String,
    creation_time_ms: u64,
    ttl_min: u16,
    package: Address,
    message: String,
}

/// Deliberate: the whole point of this type is that it holds key material.
impl fmt::Debug for SealSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealSession")
            .field("package", &self.package)
            .field("public_b64", &self.public_b64)
            .field("ttl_min", &self.ttl_min)
            .finish_non_exhaustive()
    }
}

impl SealSession {
    /// Generate a session for `package`, valid `ttl_min` minutes from `now_ms`.
    pub fn generate(package: Address, ttl_min: u16, now_ms: u64) -> Result<Self, SealError> {
        if ttl_min == 0 {
            return Err(SealError::SessionTtlZero);
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut_slice()).map_err(|e| SealError::Entropy {
            reason: e.to_string(),
        })?;
        let public_b64 = B64.encode(Ed25519PrivateKey::new(*seed).public_key().inner());
        let message = session_message(package, ttl_min, now_ms, &public_b64)?;
        Ok(Self {
            secret: seed,
            public_b64,
            creation_time_ms: now_ms,
            ttl_min,
            package,
            message,
        })
    }

    /// The message the wallet key must sign.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Raw secret bytes, for handing to the decrypt process.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Base64 of the session public key, as it appears in the message and in
    /// the certificate's `session_vk`.
    pub fn public_b64(&self) -> &str {
        &self.public_b64
    }

    pub fn creation_time_ms(&self) -> u64 {
        self.creation_time_ms
    }

    pub fn ttl_min(&self) -> u16 {
        self.ttl_min
    }
}

/// Build the session message exactly as the key servers rebuild it.
///
/// `creation_time_ms` is milliseconds; Seal divides by 1000 and renders the
/// result with chrono's `DateTime<Utc>` Display, which is where the trailing
/// ` UTC` comes from.
pub fn session_message(
    package: Address,
    ttl_min: u16,
    creation_time_ms: u64,
    public_b64: &str,
) -> Result<String, SealError> {
    let secs = i64::try_from(creation_time_ms / 1000)
        .map_err(|_| SealError::TimestampRange { creation_time_ms })?;
    let when = DateTime::<Utc>::from_timestamp(secs, 0)
        .ok_or(SealError::TimestampRange { creation_time_ms })?;
    Ok(format!(
        "{MESSAGE_PREFIX}{package}{MESSAGE_FOR}{ttl_min}{MESSAGE_MINS_FROM}{when}{MESSAGE_SESSION_KEY}{public_b64}"
    ))
}

/// What a session message says, recovered from the string itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionClaims {
    pub package: Address,
    pub ttl_min: u16,
    pub creation_time_ms: u64,
    pub public_b64: String,
}

/// Re-derive every field of a session message and refuse anything unexpected.
///
/// This is the guard that keeps a "sign this text" capability from being a
/// general one. A string that is not exactly this template, for exactly the
/// configured package, within a bounded lifetime and a fresh timestamp, is not
/// signed at all.
pub fn validate_session_message(
    message: &str,
    expected_package: Address,
    max_ttl_min: u16,
    now_ms: u64,
    expected_public_b64: &str,
) -> Result<SessionClaims, SealError> {
    let claims = parse_session_message(message, expected_package, max_ttl_min, now_ms)?;
    // Binds the message to a key we already hold. Without this the template
    // could be satisfied by a message authorising somebody else's session key.
    if claims.public_b64 != expected_public_b64 {
        return Err(SealError::MessageForOtherSessionKey {
            found: claims.public_b64,
        });
    }
    Ok(claims)
}

/// Validate a session message proposed by the decrypt process.
///
/// Identical to [`validate_session_message`] except that the session key is not
/// compared against one we generated — on the decrypt path the SDK mints it
/// inside the child process, so the parent has nothing to compare against and
/// instead requires it to be a well-formed Ed25519 public key.
///
/// Every other check still applies, and they are the ones that matter: this is
/// what stops the child proposing a message that is not a Seal session, or is
/// for another package, or grants a longer session than the operator allows.
pub fn validate_proposed_session_message(
    message: &str,
    expected_package: Address,
    max_ttl_min: u16,
    now_ms: u64,
) -> Result<SessionClaims, SealError> {
    let claims = parse_session_message(message, expected_package, max_ttl_min, now_ms)?;
    let decoded =
        B64.decode(&claims.public_b64)
            .map_err(|_| SealError::MessageForOtherSessionKey {
                found: claims.public_b64.clone(),
            })?;
    if decoded.len() != 32 {
        return Err(SealError::MessageForOtherSessionKey {
            found: claims.public_b64,
        });
    }
    Ok(claims)
}

fn parse_session_message(
    message: &str,
    expected_package: Address,
    max_ttl_min: u16,
    now_ms: u64,
) -> Result<SessionClaims, SealError> {
    let rest =
        message
            .strip_prefix(MESSAGE_PREFIX)
            .ok_or_else(|| SealError::MessageNotASession {
                message: message.to_string(),
            })?;
    let (package_text, rest) = split_once_exact(rest, MESSAGE_FOR, message)?;
    let (ttl_text, rest) = split_once_exact(rest, MESSAGE_MINS_FROM, message)?;
    let (time_text, public_text) = split_once_exact(rest, MESSAGE_SESSION_KEY, message)?;

    // Parsed as an address rather than compared as text, so a differently
    // spelled but identical package is not mistaken for a different one — and
    // a differently spelled *different* package cannot slip through either.
    let package: Address = package_text
        .parse()
        .map_err(|_| SealError::MessageNotASession {
            message: message.to_string(),
        })?;
    if package != expected_package {
        return Err(SealError::MessageForOtherPackage {
            found: package.to_string(),
            expected: expected_package.to_string(),
        });
    }

    let ttl_min: u16 = ttl_text
        .parse()
        .map_err(|_| SealError::MessageNotASession {
            message: message.to_string(),
        })?;
    if ttl_min == 0 {
        return Err(SealError::SessionTtlZero);
    }
    if ttl_min > max_ttl_min {
        return Err(SealError::SessionTtlTooLong {
            requested: ttl_min,
            max: max_ttl_min,
        });
    }

    let when = DateTime::parse_from_str(&format!("{time_text} +0000"), "%Y-%m-%d %H:%M:%S UTC %z")
        .map_err(|_| SealError::MessageNotASession {
            message: message.to_string(),
        })?;
    let creation_secs = when.timestamp();
    let now_secs = i64::try_from(now_ms / 1000).map_err(|_| SealError::TimestampRange {
        creation_time_ms: now_ms,
    })?;
    if (now_secs - creation_secs).abs() > MAX_TIMESTAMP_SKEW_SECS {
        return Err(SealError::MessageNotFresh {
            creation_secs,
            now_secs,
        });
    }

    Ok(SessionClaims {
        package,
        ttl_min,
        creation_time_ms: (creation_secs as u64) * 1000,
        public_b64: public_text.to_string(),
    })
}

/// Split on the first occurrence of `sep`, refusing a second occurrence.
///
/// A repeated separator would mean the field before it is ambiguous, which is
/// exactly how a crafted description smuggles extra structure into a template.
fn split_once_exact<'a>(
    haystack: &'a str,
    sep: &str,
    whole: &str,
) -> Result<(&'a str, &'a str), SealError> {
    let (before, after) =
        haystack
            .split_once(sep)
            .ok_or_else(|| SealError::MessageNotASession {
                message: whole.to_string(),
            })?;
    if after.contains(sep) {
        return Err(SealError::MessageNotASession {
            message: whole.to_string(),
        });
    }
    Ok((before, after))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Mysten's own regression vector, copied from
    /// `key-server/src/signed_message.rs::test_signed_message_regression`.
    ///
    /// This is the single most load-bearing test in the module: if our string
    /// drifts from theirs by one character, every key-server fetch fails
    /// authentication, and the error at that point would not say why.
    #[test]
    fn matches_the_upstream_regression_vector() {
        let package =
            Address::from_str("0x0000c457b42d48924087ea3f22d35fd2fe9afdf5bdfe38cc51c0f14f3282f6d5")
                .expect("valid address");
        let built = session_message(
            package,
            30,
            1_622_548_800,
            "DX2rNYyNrapO+gBJp1sHQ2VVsQo2ghm7aA9wVxNJ13U=",
        )
        .expect("builds");
        assert_eq!(
            built,
            "Accessing keys of package \
             0x0000c457b42d48924087ea3f22d35fd2fe9afdf5bdfe38cc51c0f14f3282f6d5 \
             for 30 mins from 1970-01-19 18:42:28 UTC, session key \
             DX2rNYyNrapO+gBJp1sHQ2VVsQo2ghm7aA9wVxNJ13U="
        );
    }

    /// A message captured from the real `seal-decrypt` binary, which composes it
    /// via `seal-sdk-rs` — a crate pinned to an *older* `fastcrypto` and `crypto`
    /// than the regression vector above came from.
    ///
    /// The two halves of this feature therefore agree across a process boundary
    /// and across two upstream revisions. Without this, a format drift between
    /// those revisions would surface as the key servers rejecting every
    /// signature, with nothing pointing back at the message.
    #[test]
    fn validates_a_message_produced_by_the_sidecar() {
        let message = "Accessing keys of package \
             0x3af6edb64f575cb65a89f1c8f445a2e2aad05324a1586aad9e2651191bf4f99b for 10 mins \
             from 2026-09-11 13:40:55 UTC, session key \
             bfRYVJ9GYARqopWcLtvrlMusYymw+mxedCdDTNm3Abg=";
        let claims = validate_session_message(
            message,
            package(),
            10,
            1_789_134_055_000,
            "bfRYVJ9GYARqopWcLtvrlMusYymw+mxedCdDTNm3Abg=",
        )
        .expect("the sidecar's own message must satisfy our validator");
        assert_eq!(claims.ttl_min, 10);
        assert_eq!(claims.package, package());
    }

    fn package() -> Address {
        Address::from_str("0x3af6edb64f575cb65a89f1c8f445a2e2aad05324a1586aad9e2651191bf4f99b")
            .expect("valid address")
    }

    const NOW_MS: u64 = 1_789_000_000_000;

    fn valid() -> (String, String) {
        let session = SealSession::generate(package(), 10, NOW_MS).expect("generates");
        (
            session.message().to_string(),
            session.public_b64().to_string(),
        )
    }

    #[test]
    fn a_freshly_built_message_validates() {
        let (message, vk) = valid();
        let claims =
            validate_session_message(&message, package(), 10, NOW_MS, &vk).expect("validates");
        assert_eq!(claims.package, package());
        assert_eq!(claims.ttl_min, 10);
        assert_eq!(claims.public_b64, vk);
    }

    #[test]
    fn two_sessions_never_share_a_key() {
        let a = SealSession::generate(package(), 10, NOW_MS).expect("generates");
        let b = SealSession::generate(package(), 10, NOW_MS).expect("generates");
        assert_ne!(a.public_b64(), b.public_b64(), "session keys must be fresh");
    }

    #[test]
    fn a_message_for_another_package_is_refused() {
        let (message, vk) = valid();
        let other =
            Address::from_str("0x0000000000000000000000000000000000000000000000000000000000000002")
                .expect("valid address");
        assert!(matches!(
            validate_session_message(&message, other, 10, NOW_MS, &vk),
            Err(SealError::MessageForOtherPackage { .. })
        ));
    }

    #[test]
    fn a_ttl_above_the_ceiling_is_refused() {
        let session = SealSession::generate(package(), 60, NOW_MS).expect("generates");
        assert!(matches!(
            validate_session_message(
                session.message(),
                package(),
                10,
                NOW_MS,
                session.public_b64()
            ),
            Err(SealError::SessionTtlTooLong {
                requested: 60,
                max: 10
            })
        ));
    }

    #[test]
    fn a_stale_message_is_refused() {
        // Minted an hour ago: signing it now would yield a session whose stated
        // lifetime has already largely elapsed, or which was chosen by someone
        // other than this process.
        let session = SealSession::generate(package(), 10, NOW_MS - 3_600_000).expect("generates");
        assert!(matches!(
            validate_session_message(
                session.message(),
                package(),
                10,
                NOW_MS,
                session.public_b64()
            ),
            Err(SealError::MessageNotFresh { .. })
        ));
    }

    #[test]
    fn a_message_naming_a_different_session_key_is_refused() {
        let (message, _) = valid();
        let other = SealSession::generate(package(), 10, NOW_MS).expect("generates");
        assert!(matches!(
            validate_session_message(&message, package(), 10, NOW_MS, other.public_b64()),
            Err(SealError::MessageForOtherSessionKey { .. })
        ));
    }

    #[test]
    fn arbitrary_text_is_not_a_session_message() {
        // The phishing case: anything that is not this exact template must not
        // reach the signer, however plausible it reads.
        for text in [
            "Please sign in to continue",
            "Accessing keys of package but not really",
            "",
            "Transfer all funds to 0x2",
        ] {
            assert!(
                matches!(
                    validate_session_message(text, package(), 10, NOW_MS, "x"),
                    Err(SealError::MessageNotASession { .. })
                ),
                "must refuse: {text}"
            );
        }
    }

    #[test]
    fn a_duplicated_separator_is_refused() {
        // A description that itself contains the separator would otherwise make
        // the preceding field ambiguous.
        let forged = format!(
            "{MESSAGE_PREFIX}{}{MESSAGE_FOR}10{MESSAGE_MINS_FROM}1970-01-19 18:42:28 UTC\
             {MESSAGE_SESSION_KEY}a{MESSAGE_SESSION_KEY}b",
            package()
        );
        assert!(matches!(
            validate_session_message(&forged, package(), 10, NOW_MS, "a"),
            Err(SealError::MessageNotASession { .. })
        ));
    }

    #[test]
    fn a_zero_ttl_is_refused_at_generation() {
        assert!(matches!(
            SealSession::generate(package(), 0, NOW_MS),
            Err(SealError::SessionTtlZero)
        ));
    }

    #[test]
    fn debug_does_not_print_the_secret() {
        let session = SealSession::generate(package(), 10, NOW_MS).expect("generates");
        let rendered = format!("{session:?}");
        let secret_hex = hex::encode(session.secret_bytes());
        assert!(!rendered.contains(&secret_hex));
        assert!(!rendered.contains(&B64.encode(session.secret_bytes())));
    }
}
