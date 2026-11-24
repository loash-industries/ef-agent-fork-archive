//! The `seal_approve` transaction, and the little of the ciphertext needed to build it.
//!
//! Seal's key servers do not take the agent's word for what it may read. They
//! dry-run a programmable transaction calling `keyspace::seal_approve` against
//! the on-chain ACL, and only release key shares if it succeeds. This module
//! builds that transaction.
//!
//! It is never signed and never submitted. A bare `ProgrammableTransaction`
//! carries no gas and no sender, so it is not a submittable object at all — it
//! is an argument. That is worth stating plainly because this crate otherwise
//! only ever *inspects* transactions and refuses them; this is the one place it
//! constructs one.

use sui_sdk_types::{
    Address, Argument, Command, Identifier, Input, MoveCall, ProgrammableTransaction, SharedInput,
};

use super::SealError;

/// Module and function the key servers expect to see called.
const APPROVE_MODULE: &str = "keyspace";
const APPROVE_FUNCTION: &str = "seal_approve";

/// A shared object as the transaction must reference it.
///
/// `initial_shared_version` is not the object's current version: Sui identifies
/// a shared input by the version at which it *became* shared. Passing the
/// current version yields a transaction the validators reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedObject {
    pub id: Address,
    pub initial_shared_version: u64,
}

/// What the ciphertext header says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedHeader {
    /// The Seal package the entry was encrypted under.
    pub package: Address,
    /// The policy id: the Keyspace id followed by a per-entry nonce. This is
    /// what `seal_approve` is asked to approve, and it is **not** the entry's
    /// object id from the Keyspace metadata.
    pub policy_id: Vec<u8>,
}

/// Read the header of a BCS-encoded Seal `EncryptedObject`.
///
/// Only the first two fields are decoded, because only they are needed — and
/// decoding no more than that keeps this crate free of Seal's crypto types.
/// The layout is `version: u8`, `package_id: [u8; 32]`, `id: vector<u8>`.
///
/// The point of reading the package from the bytes is to be able to contradict
/// configuration: an entry encrypted under some other package must not be sent
/// to key servers under a session that names ours.
pub fn parse_encrypted_header(bytes: &[u8]) -> Result<EncryptedHeader, SealError> {
    let mut cursor = 0usize;
    let _version = *bytes.get(cursor).ok_or(SealError::CiphertextTruncated)?;
    cursor += 1;

    let package_bytes: [u8; 32] = bytes
        .get(cursor..cursor + 32)
        .ok_or(SealError::CiphertextTruncated)?
        .try_into()
        .map_err(|_| SealError::CiphertextTruncated)?;
    cursor += 32;
    let package = Address::new(package_bytes);

    let (len, consumed) = read_uleb128(&bytes[cursor..])?;
    cursor += consumed;
    let policy_id = bytes
        .get(cursor..cursor + len)
        .ok_or(SealError::CiphertextTruncated)?
        .to_vec();

    Ok(EncryptedHeader { package, policy_id })
}

/// BCS encodes vector lengths as ULEB128.
fn read_uleb128(bytes: &[u8]) -> Result<(usize, usize), SealError> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (index, byte) in bytes.iter().enumerate() {
        // A length needing more than 5 groups is not one this ever produces, and
        // continuing would risk shifting past the width of the accumulator.
        if shift > 28 {
            return Err(SealError::CiphertextMalformed);
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((
                usize::try_from(value).map_err(|_| SealError::CiphertextMalformed)?,
                index + 1,
            ));
        }
        shift += 7;
    }
    Err(SealError::CiphertextTruncated)
}

/// Build the `seal_approve` call the key servers will dry-run.
///
/// Mirrors
/// `entry fun seal_approve(id: vector<u8>, keyspace: &Keyspace, dao: &DAO, ctx: &TxContext)`.
/// Both objects are taken immutably, so they are shared inputs marked read-only
/// — asking for mutability the function does not need would make the request
/// conflict with concurrent readers for no benefit.
pub fn build_seal_approve(
    package: Address,
    policy_id: &[u8],
    keyspace: SharedObject,
    org_unit: SharedObject,
) -> Result<ProgrammableTransaction, SealError> {
    let id_argument = bcs::to_bytes(&policy_id.to_vec()).map_err(|e| SealError::PtbEncoding {
        reason: e.to_string(),
    })?;

    let inputs = vec![
        Input::Pure(id_argument),
        Input::Shared(SharedInput::new(
            keyspace.id,
            keyspace.initial_shared_version,
            false,
        )),
        Input::Shared(SharedInput::new(
            org_unit.id,
            org_unit.initial_shared_version,
            false,
        )),
    ];

    let module = Identifier::new(APPROVE_MODULE).map_err(|e| SealError::PtbEncoding {
        reason: e.to_string(),
    })?;
    let function = Identifier::new(APPROVE_FUNCTION).map_err(|e| SealError::PtbEncoding {
        reason: e.to_string(),
    })?;

    Ok(ProgrammableTransaction {
        inputs,
        commands: vec![Command::MoveCall(MoveCall {
            package,
            module,
            function,
            type_arguments: Vec::new(),
            // `ctx` is supplied by the runtime, not passed as an argument.
            arguments: vec![Argument::Input(0), Argument::Input(1), Argument::Input(2)],
        })],
    })
}

/// [`build_seal_approve`], already BCS-encoded.
///
/// Callers hand these bytes straight to the decrypt process, and this keeps the
/// BCS version pinned in one crate rather than spread across the callers.
pub fn build_seal_approve_bytes(
    package: Address,
    policy_id: &[u8],
    keyspace: SharedObject,
    org_unit: SharedObject,
) -> Result<Vec<u8>, SealError> {
    let ptb = build_seal_approve(package, policy_id, keyspace, org_unit)?;
    bcs::to_bytes(&ptb).map_err(|e| SealError::PtbEncoding {
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// The real header of the "locations" entry in Keyspace `0x1d93…db38`,
    /// fetched from the Backblaze URI the Keyspace metadata names.
    const REAL_HEADER_HEX: &str = "003af6edb64f575cb65a89f1c8f445a2e2aad05324a1586aad9e2651191bf4f99b\
251d932469c860d6bfd194a8f27a9a24f4410975ea2274d10c4d343bb6e9c9db38e8d71386c6\
01b012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e9801010098";

    fn keyspace_id() -> Address {
        Address::from_str("0x1d932469c860d6bfd194a8f27a9a24f4410975ea2274d10c4d343bb6e9c9db38")
            .expect("valid address")
    }

    fn package() -> Address {
        Address::from_str("0x3af6edb64f575cb65a89f1c8f445a2e2aad05324a1586aad9e2651191bf4f99b")
            .expect("valid address")
    }

    #[test]
    fn reads_the_header_of_a_real_entry() {
        let bytes = hex::decode(REAL_HEADER_HEX).expect("valid hex");
        let header = parse_encrypted_header(&bytes).expect("parses");
        assert_eq!(header.package, package());
        // 32-byte Keyspace id followed by a 5-byte nonce.
        assert_eq!(header.policy_id.len(), 37);
        assert_eq!(&header.policy_id[..32], keyspace_id().inner());
    }

    #[test]
    fn the_policy_id_is_not_the_entry_object_id() {
        // The Keyspace metadata calls the entry `0xe462…357b`; using that as the
        // policy id would produce a `seal_approve` the key servers reject, and
        // the error would be about approval rather than about the wrong id.
        let bytes = hex::decode(REAL_HEADER_HEX).expect("valid hex");
        let header = parse_encrypted_header(&bytes).expect("parses");
        let entry_object_id =
            hex::decode("e46224c5db991310426c07efa77956989286dd27d77c7ebbc33ed66b3e50357b")
                .expect("valid hex");
        assert_ne!(header.policy_id, entry_object_id);
    }

    #[test]
    fn a_truncated_ciphertext_is_refused() {
        let bytes = hex::decode(REAL_HEADER_HEX).expect("valid hex");
        for cut in [0usize, 1, 10, 33, 40] {
            assert!(
                matches!(
                    parse_encrypted_header(&bytes[..cut]),
                    Err(SealError::CiphertextTruncated)
                ),
                "must refuse a {cut}-byte ciphertext"
            );
        }
    }

    #[test]
    fn builds_a_three_argument_approve_call() {
        let ptb = build_seal_approve(
            package(),
            &[1, 2, 3],
            SharedObject {
                id: keyspace_id(),
                initial_shared_version: 912_301_848,
            },
            SharedObject {
                id: Address::from_str(
                    "0xe7f89ba655ae448ddf8509abc1e18fb02525f2e6952223b242e72cbd7369c79b",
                )
                .expect("valid address"),
                initial_shared_version: 903_315_760,
            },
        )
        .expect("builds");

        assert_eq!(ptb.inputs.len(), 3);
        assert_eq!(ptb.commands.len(), 1);
        let Command::MoveCall(call) = &ptb.commands[0] else {
            panic!("expected a MoveCall");
        };
        assert_eq!(call.package, package());
        assert_eq!(call.module.as_str(), "keyspace");
        assert_eq!(call.function.as_str(), "seal_approve");
        assert_eq!(call.arguments.len(), 3);
    }

    #[test]
    fn the_shared_inputs_use_the_initial_version_not_the_current_one() {
        // Sui identifies a shared input by the version at which it became
        // shared; the current version would be rejected by validators.
        let ptb = build_seal_approve(
            package(),
            &[1],
            SharedObject {
                id: keyspace_id(),
                initial_shared_version: 912_301_848,
            },
            SharedObject {
                id: keyspace_id(),
                initial_shared_version: 903_315_760,
            },
        )
        .expect("builds");
        let encoded = bcs::to_bytes(&ptb).expect("serialises");
        // Both versions appear verbatim in the encoding.
        assert!(
            encoded
                .windows(8)
                .any(|w| w == 912_301_848u64.to_le_bytes()),
            "keyspace initial version must be encoded"
        );
    }

    #[test]
    fn the_transaction_round_trips_through_bcs() {
        // The sidecar hands these bytes to the key servers, so they must decode
        // back into the same transaction.
        let ptb = build_seal_approve(
            package(),
            &[9, 9, 9],
            SharedObject {
                id: keyspace_id(),
                initial_shared_version: 1,
            },
            SharedObject {
                id: keyspace_id(),
                initial_shared_version: 2,
            },
        )
        .expect("builds");
        let encoded = bcs::to_bytes(&ptb).expect("serialises");
        let decoded: ProgrammableTransaction = bcs::from_bytes(&encoded).expect("round trips");
        assert_eq!(decoded, ptb);
    }
}
