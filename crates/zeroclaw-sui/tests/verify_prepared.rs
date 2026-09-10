//! Verification behaviour, anchored on a transaction the real builder produced.
//!
//! The happy-path fixture is a genuine `prepare_create_account` response from
//! the deployed Trinary Exchange MCP server, kept verbatim so the decoder is
//! exercised against bytes the ecosystem actually emits rather than against
//! bytes this repo invented. Its sender is the synthetic `0x1111…` address, so
//! no real account appears in the tree.
//!
//! The hostile cases are crafted locally, because a builder that behaves will
//! never produce them — and those are exactly the cases that must fail.

use std::str::FromStr;
use std::time::Duration;

use base64::Engine as _;
use sui_sdk_types::{
    Address, Argument, Command, Input, MoveCall, ProgrammableTransaction, TransactionKind,
    TransferObjects,
};
use zeroclaw_sui::{MoveTarget, PreparedTransaction, SubmitPolicy, VerifyError, verify};

const FIXTURE: &str = include_str!("fixtures/create_account.json");

/// The synthetic sender the fixture was prepared for.
const AGENT: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
/// An address that is not the agent.
const STRANGER: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
/// The TriEx package the fixture calls.
const TRIEX_PKG: &str = "0x291b9da738dffedd18d7c5049e5e6792270202e03f3c9d9db4c7097670bf6eb2";

fn address(raw: &str) -> Address {
    Address::from_str(raw).expect("valid address")
}

fn fixture() -> PreparedTransaction {
    PreparedTransaction::from_json(FIXTURE).expect("fixture parses")
}

/// A policy that admits exactly what the fixture does, evaluated just after it
/// was built.
fn permissive_policy() -> SubmitPolicy {
    SubmitPolicy::deny_all(address(AGENT)).allow_target(
        format!("{TRIEX_PKG}::balance_manager::new")
            .parse()
            .expect("target parses"),
    )
}

fn just_after_build(prepared: &PreparedTransaction) -> u64 {
    prepared.built_at_ms + 1_000
}

// ── Happy path ──────────────────────────────────────────────────────────────

#[test]
fn real_builder_output_verifies() {
    let prepared = fixture();
    let now = just_after_build(&prepared);
    let verified = verify(&prepared, &permissive_policy(), now).expect("fixture should verify");

    assert_eq!(verified.sender, address(AGENT));
    assert_eq!(verified.targets.len(), 1);
    assert_eq!(
        verified.targets[0].canonical(),
        format!("{TRIEX_PKG}::balance_manager::new")
    );
}

#[test]
fn decoded_target_carries_the_padded_package_form() {
    // Recorded because it is the trap an allowlist is most likely to fall into:
    // the bytes always yield the 32-byte form regardless of how the target was
    // written upstream.
    let prepared = fixture();
    let verified =
        verify(&prepared, &permissive_policy(), just_after_build(&prepared)).expect("verifies");
    let rendered = verified.targets[0].canonical();
    let package = rendered.split("::").next().expect("has a package");
    assert_eq!(package.len(), 66, "expected 0x + 64 hex digits: {package}");
}

#[test]
fn the_fixture_really_does_contain_a_transfer_back_to_the_sender() {
    // Guards the guard: if this fixture ever stopped containing a
    // TransferObjects, `transfer_to_a_third_party_is_refused` below would still
    // pass while testing nothing.
    let prepared = fixture();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&prepared.tx_kind_bytes)
        .expect("base64 decodes");
    let kind = bcs::from_bytes::<TransactionKind>(&raw).expect("bcs decodes");
    let TransactionKind::ProgrammableTransaction(pt) = kind else {
        panic!("fixture should be a programmable transaction");
    };
    assert!(
        pt.commands
            .iter()
            .any(|c| matches!(c, Command::TransferObjects(_))),
        "fixture no longer transfers, so the recipient check is untested"
    );
}

// ── Default-closed ──────────────────────────────────────────────────────────

#[test]
fn empty_allowlist_refuses_a_perfectly_valid_transaction() {
    let prepared = fixture();
    let policy = SubmitPolicy::deny_all(address(AGENT));
    let err = verify(&prepared, &policy, just_after_build(&prepared)).expect_err("must refuse");
    assert!(matches!(err, VerifyError::TargetNotAllowed { .. }), "{err}");
}

#[test]
fn allowing_a_neighbouring_function_does_not_admit_this_one() {
    let prepared = fixture();
    let policy = SubmitPolicy::deny_all(address(AGENT)).allow_target(
        format!("{TRIEX_PKG}::balance_manager::destroy")
            .parse()
            .expect("parses"),
    );
    let err = verify(&prepared, &policy, just_after_build(&prepared)).expect_err("must refuse");
    assert!(matches!(err, VerifyError::TargetNotAllowed { .. }), "{err}");
}

#[test]
fn allowing_the_same_function_on_another_package_does_not_admit_this_one() {
    let prepared = fixture();
    let policy = SubmitPolicy::deny_all(address(AGENT))
        .allow_target("0x2::balance_manager::new".parse().expect("parses"));
    let err = verify(&prepared, &policy, just_after_build(&prepared)).expect_err("must refuse");
    assert!(matches!(err, VerifyError::TargetNotAllowed { .. }), "{err}");
}

// ── Sender binding ──────────────────────────────────────────────────────────

#[test]
fn a_payload_prepared_for_someone_else_is_refused() {
    let prepared = fixture();
    let policy = SubmitPolicy::deny_all(address(STRANGER)).allow_target(
        format!("{TRIEX_PKG}::balance_manager::new")
            .parse()
            .expect("parses"),
    );
    let err = verify(&prepared, &policy, just_after_build(&prepared)).expect_err("must refuse");
    assert!(matches!(err, VerifyError::SenderMismatch { .. }), "{err}");
}

// ── Freshness ───────────────────────────────────────────────────────────────

#[test]
fn a_stale_payload_is_refused() {
    let prepared = fixture();
    let policy = permissive_policy().with_max_age(Duration::from_secs(60));
    let now = prepared.built_at_ms + 61_000;
    let err = verify(&prepared, &policy, now).expect_err("must refuse");
    assert!(matches!(err, VerifyError::Stale { .. }), "{err}");
}

#[test]
fn freshness_boundary_is_inclusive() {
    let prepared = fixture();
    let policy = permissive_policy().with_max_age(Duration::from_secs(60));
    verify(&prepared, &policy, prepared.built_at_ms + 60_000).expect("exactly at the limit is ok");
    verify(&prepared, &policy, prepared.built_at_ms + 60_001).expect_err("one past is not");
}

#[test]
fn a_payload_from_the_future_is_refused() {
    let prepared = fixture();
    let policy = permissive_policy();
    // Well beyond the 5s skew allowance.
    let now = prepared.built_at_ms - 60_000;
    let err = verify(&prepared, &policy, now).expect_err("must refuse");
    assert!(matches!(err, VerifyError::BuiltInFuture { .. }), "{err}");
}

#[test]
fn small_clock_skew_is_tolerated() {
    let prepared = fixture();
    let policy = permissive_policy();
    verify(&prepared, &policy, prepared.built_at_ms - 1_000).expect("1s of skew is fine");
}

// ── Byte integrity ──────────────────────────────────────────────────────────

#[test]
fn trailing_bytes_are_refused() {
    // A transaction that decodes cleanly must not be able to carry extra data
    // along with it.
    let prepared = fixture();
    let mut raw = base64::engine::general_purpose::STANDARD
        .decode(&prepared.tx_kind_bytes)
        .expect("decodes");
    raw.push(0x00);
    let tampered = retarget_bytes(&prepared, &raw);
    let err =
        verify(&tampered, &permissive_policy(), just_after_build(&prepared)).expect_err("refuse");
    assert!(matches!(err, VerifyError::Bcs { .. }), "{err}");
}

#[test]
fn corrupt_base64_is_refused() {
    let mut prepared = fixture();
    prepared.tx_kind_bytes = "not valid base64!!!".to_string();
    let err =
        verify(&prepared, &permissive_policy(), just_after_build(&prepared)).expect_err("refuse");
    assert!(matches!(err, VerifyError::Base64 { .. }), "{err}");
}

#[test]
fn empty_bytes_are_refused() {
    let mut prepared = fixture();
    prepared.tx_kind_bytes = String::new();
    let err =
        verify(&prepared, &permissive_policy(), just_after_build(&prepared)).expect_err("refuse");
    assert!(matches!(err, VerifyError::EmptyTransaction), "{err}");
}

// ── Intent cross-check ──────────────────────────────────────────────────────

#[test]
fn a_builder_that_understates_its_calls_is_refused() {
    let mut prepared = fixture();
    prepared.intent.targets.clear();
    let err =
        verify(&prepared, &permissive_policy(), just_after_build(&prepared)).expect_err("refuse");
    assert!(matches!(err, VerifyError::IntentMismatch { .. }), "{err}");
}

#[test]
fn a_builder_that_overstates_its_calls_is_refused() {
    let mut prepared = fixture();
    prepared.intent.targets.push("0x2::coin::zero".to_string());
    let err =
        verify(&prepared, &permissive_policy(), just_after_build(&prepared)).expect_err("refuse");
    assert!(matches!(err, VerifyError::IntentMismatch { .. }), "{err}");
}

#[test]
fn intent_written_in_short_package_form_still_matches() {
    // The cross-check compares canonically, so a builder that abbreviates its
    // own declaration is not punished for a spelling difference.
    let kind = programmable(
        vec![],
        vec![Command::MoveCall(MoveCall {
            package: address("0x2"),
            module: "coin".parse().expect("identifier"),
            function: "zero".parse().expect("identifier"),
            type_arguments: vec![],
            arguments: vec![],
        })],
    );
    let prepared = crafted(kind, vec!["0x2::coin::zero".to_string()]);
    let policy = SubmitPolicy::deny_all(address(AGENT))
        .allow_target("0x2::coin::zero".parse().expect("parses"));
    verify(&prepared, &policy, prepared.built_at_ms).expect("short form should match");
}

// ── Hostile commands ────────────────────────────────────────────────────────

#[test]
fn transfer_to_a_third_party_is_refused() {
    // The core theft scenario: the Move call is allowlisted and the intent is
    // truthful, but the object is handed to someone else.
    let kind = programmable(
        vec![Input::Pure(
            bcs::to_bytes(&address(STRANGER)).expect("encodes"),
        )],
        vec![
            Command::MoveCall(MoveCall {
                package: address(TRIEX_PKG),
                module: "balance_manager".parse().expect("identifier"),
                function: "new".parse().expect("identifier"),
                type_arguments: vec![],
                arguments: vec![],
            }),
            Command::TransferObjects(TransferObjects {
                objects: vec![Argument::Result(0)],
                address: Argument::Input(0),
            }),
        ],
    );
    let prepared = crafted(kind, vec![format!("{TRIEX_PKG}::balance_manager::new")]);
    let err =
        verify(&prepared, &permissive_policy(), prepared.built_at_ms).expect_err("must refuse");
    match err {
        VerifyError::TransferToThirdParty { recipient, .. } => {
            assert_eq!(recipient, address(STRANGER).to_string());
        }
        other => panic!("expected a third-party transfer refusal, got {other}"),
    }
}

#[test]
fn transfer_to_a_computed_recipient_is_refused() {
    // A recipient that depends on a runtime result cannot be read from the
    // bytes, so it cannot be approved from the bytes either.
    let kind = programmable(
        vec![],
        vec![
            Command::MoveCall(MoveCall {
                package: address(TRIEX_PKG),
                module: "balance_manager".parse().expect("identifier"),
                function: "new".parse().expect("identifier"),
                type_arguments: vec![],
                arguments: vec![],
            }),
            Command::TransferObjects(TransferObjects {
                objects: vec![Argument::Result(0)],
                address: Argument::Result(0),
            }),
        ],
    );
    let prepared = crafted(kind, vec![format!("{TRIEX_PKG}::balance_manager::new")]);
    let err =
        verify(&prepared, &permissive_policy(), prepared.built_at_ms).expect_err("must refuse");
    assert!(
        matches!(err, VerifyError::ComputedTransferRecipient { .. }),
        "{err}"
    );
}

#[test]
fn transfer_referencing_a_missing_input_is_refused() {
    let kind = programmable(
        vec![],
        vec![Command::TransferObjects(TransferObjects {
            objects: vec![Argument::Gas],
            address: Argument::Input(7),
        })],
    );
    let prepared = crafted(kind, vec![]);
    let err =
        verify(&prepared, &permissive_policy(), prepared.built_at_ms).expect_err("must refuse");
    assert!(matches!(err, VerifyError::InputOutOfRange { .. }), "{err}");
}

#[test]
fn an_unallowlisted_call_hidden_behind_an_allowlisted_one_is_refused() {
    let kind = programmable(
        vec![],
        vec![
            Command::MoveCall(MoveCall {
                package: address(TRIEX_PKG),
                module: "balance_manager".parse().expect("identifier"),
                function: "new".parse().expect("identifier"),
                type_arguments: vec![],
                arguments: vec![],
            }),
            Command::MoveCall(MoveCall {
                package: address(TRIEX_PKG),
                module: "balance_manager".parse().expect("identifier"),
                function: "withdraw_all".parse().expect("identifier"),
                type_arguments: vec![],
                arguments: vec![],
            }),
        ],
    );
    let prepared = crafted(
        kind,
        vec![
            format!("{TRIEX_PKG}::balance_manager::new"),
            format!("{TRIEX_PKG}::balance_manager::withdraw_all"),
        ],
    );
    let err =
        verify(&prepared, &permissive_policy(), prepared.built_at_ms).expect_err("must refuse");
    match err {
        VerifyError::TargetNotAllowed { index, target } => {
            assert_eq!(index, 1);
            assert!(
                target.ends_with("::balance_manager::withdraw_all"),
                "{target}"
            );
        }
        other => panic!("expected the second call to be refused, got {other}"),
    }
}

#[test]
fn a_transaction_with_no_commands_is_refused() {
    let prepared = crafted(programmable(vec![], vec![]), vec![]);
    let err =
        verify(&prepared, &permissive_policy(), prepared.built_at_ms).expect_err("must refuse");
    assert!(matches!(err, VerifyError::NoCommands), "{err}");
}

#[test]
fn too_many_commands_are_refused() {
    let call = Command::MoveCall(MoveCall {
        package: address(TRIEX_PKG),
        module: "balance_manager".parse().expect("identifier"),
        function: "new".parse().expect("identifier"),
        type_arguments: vec![],
        arguments: vec![],
    });
    let mut policy = permissive_policy();
    policy.max_commands = 2;
    let prepared = crafted(
        programmable(vec![], vec![call.clone(), call.clone(), call]),
        vec![format!("{TRIEX_PKG}::balance_manager::new")],
    );
    let err = verify(&prepared, &policy, prepared.built_at_ms).expect_err("must refuse");
    assert!(matches!(err, VerifyError::TooManyCommands { .. }), "{err}");
}

// ── Spend ceilings ──────────────────────────────────────────────────────────

#[test]
fn a_declared_spend_with_no_configured_cap_is_refused() {
    let prepared = with_spend(fixture(), "currency", "CRED", "1000000");
    let err =
        verify(&prepared, &permissive_policy(), just_after_build(&prepared)).expect_err("refuse");
    assert!(
        matches!(err, VerifyError::SpendNotPermitted { .. }),
        "{err}"
    );
}

#[test]
fn a_spend_over_its_cap_is_refused() {
    let prepared = with_spend(fixture(), "currency", "CRED", "1000001");
    let policy = permissive_policy().allow_spend("currency", "CRED", 1_000_000);
    let err = verify(&prepared, &policy, just_after_build(&prepared)).expect_err("refuse");
    assert!(matches!(err, VerifyError::SpendExceedsCap { .. }), "{err}");
}

#[test]
fn a_spend_at_its_cap_is_allowed() {
    let prepared = with_spend(fixture(), "currency", "CRED", "1000000");
    let policy = permissive_policy().allow_spend("currency", "CRED", 1_000_000);
    verify(&prepared, &policy, just_after_build(&prepared)).expect("exactly at the cap is ok");
}

#[test]
fn a_spend_of_an_unrecognized_kind_is_refused() {
    // An unknown kind must not slip past the ceiling it was meant to describe.
    let prepared = with_spend(fixture(), "warehouse_receipt", "CRED", "1");
    let policy = permissive_policy().allow_spend("currency", "CRED", u128::MAX);
    let err = verify(&prepared, &policy, just_after_build(&prepared)).expect_err("refuse");
    assert!(
        matches!(err, VerifyError::SpendNotPermitted { .. }),
        "{err}"
    );
}

#[test]
fn a_cap_on_one_asset_does_not_cover_another() {
    let prepared = with_spend(fixture(), "currency", "SUI", "1");
    let policy = permissive_policy().allow_spend("currency", "CRED", u128::MAX);
    let err = verify(&prepared, &policy, just_after_build(&prepared)).expect_err("refuse");
    assert!(
        matches!(err, VerifyError::SpendNotPermitted { .. }),
        "{err}"
    );
}

#[test]
fn a_non_numeric_spend_amount_is_refused() {
    let prepared = with_spend(fixture(), "currency", "CRED", "lots");
    let policy = permissive_policy().allow_spend("currency", "CRED", u128::MAX);
    let err = verify(&prepared, &policy, just_after_build(&prepared)).expect_err("refuse");
    assert!(
        matches!(err, VerifyError::UnparseableSpendAmount { .. }),
        "{err}"
    );
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn programmable(inputs: Vec<Input>, commands: Vec<Command>) -> TransactionKind {
    TransactionKind::ProgrammableTransaction(ProgrammableTransaction { inputs, commands })
}

/// Build a prepared payload around a locally constructed transaction.
fn crafted(kind: TransactionKind, targets: Vec<String>) -> PreparedTransaction {
    let bytes = bcs::to_bytes(&kind).expect("encodes");
    let payload = serde_json::json!({
        "txKindBytes": base64::engine::general_purpose::STANDARD.encode(&bytes),
        "sender": AGENT,
        "intent": { "action": "crafted", "params": {}, "targets": targets },
        "pinnedObjects": [],
        "builtAtMs": 1_789_076_412_502u64,
        "notes": [],
    });
    PreparedTransaction::from_json(&payload.to_string()).expect("crafted payload parses")
}

/// Re-wrap a payload around different transaction bytes, leaving intent intact.
fn retarget_bytes(base: &PreparedTransaction, raw: &[u8]) -> PreparedTransaction {
    let payload = serde_json::json!({
        "txKindBytes": base64::engine::general_purpose::STANDARD.encode(raw),
        "sender": base.sender,
        "intent": {
            "action": base.intent.action,
            "params": base.intent.params,
            "targets": base.intent.targets,
        },
        "pinnedObjects": [],
        "builtAtMs": base.built_at_ms,
        "notes": [],
    });
    PreparedTransaction::from_json(&payload.to_string()).expect("parses")
}

/// Attach a declared worst-case spend to an existing payload.
fn with_spend(
    base: PreparedTransaction,
    kind: &str,
    asset: &str,
    amount: &str,
) -> PreparedTransaction {
    let payload = serde_json::json!({
        "txKindBytes": base.tx_kind_bytes,
        "sender": base.sender,
        "intent": {
            "action": base.intent.action,
            "params": base.intent.params,
            "targets": base.intent.targets,
            "worstCaseSpend": { "kind": kind, "asset": asset, "amount": amount },
        },
        "pinnedObjects": [],
        "builtAtMs": base.built_at_ms,
        "notes": [],
    });
    PreparedTransaction::from_json(&payload.to_string()).expect("parses")
}

/// Unused-import guard: keeps `MoveTarget` in scope for the doc-level contract
/// that verified targets are comparable values rather than strings.
#[test]
fn verified_targets_are_structured_values() {
    let prepared = fixture();
    let verified =
        verify(&prepared, &permissive_policy(), just_after_build(&prepared)).expect("verifies");
    let expected: MoveTarget = format!("{TRIEX_PKG}::balance_manager::new")
        .parse()
        .expect("parses");
    assert_eq!(verified.targets[0], expected);
}
