//! The commit path end to end, against a mock gas station.
//!
//! This exercises everything except the network: verification, reservation,
//! transaction assembly, real Ed25519 signing, and submission. What it cannot
//! establish is whether a Sui validator would accept the result — no
//! transaction has ever been submitted to a real chain — so treat a green run
//! here as "the pieces fit", not "this works on chain".

use std::str::FromStr;

use base64::Engine as _;
use sui_crypto::SuiVerifier;
use sui_crypto::ed25519::{Ed25519PrivateKey, Ed25519Verifier};
use sui_sdk_types::{
    Address, Argument, Command, Input, MoveCall, ProgrammableTransaction, Transaction,
    TransactionKind, TransferObjects,
};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};
use zeroclaw_sui::{
    AgentSigner, GasStation, GasStationError, PreparedTransaction, SubmitError, SubmitPolicy,
    SubmitRequest, submit,
};

const TRIEX_PKG: &str = "0x291b9da738dffedd18d7c5049e5e6792270202e03f3c9d9db4c7097670bf6eb2";
const SPONSOR: &str = "0x3333333333333333333333333333333333333333333333333333333333333333";
const COIN: &str = "0x4444444444444444444444444444444444444444444444444444444444444444";
const DIGEST: &str = "11111111111111111111111111111111";
const TOKEN: &str = "test-bearer-token";

/// Build a payload that mirrors the real `create_account` shape — a
/// `balance_manager::new` call whose result is transferred back to the sender —
/// but addressed to the test key.
///
/// The committed fixture cannot be reused here: its transfer recipient is baked
/// into the transaction bytes as a pure input, so pointing the JSON `sender`
/// field at a different key leaves the bytes paying out to the original address,
/// and verification correctly refuses it. (That refusal is itself covered in
/// `verify_prepared.rs`.) Decoding of genuine builder bytes is tested there;
/// what this file needs is a transaction the test key can legitimately sign.
fn signer_and_prepared() -> (AgentSigner, PreparedTransaction) {
    let signer = AgentSigner::from_seed(&[7u8; 32]).expect("key loads");
    let me = signer.address();

    let kind = TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
        inputs: vec![Input::Pure(bcs::to_bytes(&me).expect("address encodes"))],
        commands: vec![
            Command::MoveCall(MoveCall {
                package: Address::from_str(TRIEX_PKG).expect("package parses"),
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
    });

    let engine = base64::engine::general_purpose::STANDARD;
    let payload = serde_json::json!({
        "txKindBytes": engine.encode(bcs::to_bytes(&kind).expect("kind encodes")),
        "sender": me.to_string(),
        "intent": {
            "action": "create_account",
            "params": { "sender": me.to_string() },
            "targets": [format!("{TRIEX_PKG}::balance_manager::new")],
        },
        "pinnedObjects": [],
        "builtAtMs": 1_789_076_412_502u64,
        "notes": [],
    });
    let prepared =
        PreparedTransaction::from_json(&payload.to_string()).expect("crafted payload parses");
    (signer, prepared)
}

fn policy(sender: Address) -> SubmitPolicy {
    SubmitPolicy::deny_all(sender).allow_target(
        format!("{TRIEX_PKG}::balance_manager::new")
            .parse()
            .expect("target parses"),
    )
}

fn request<'a>(prepared: &'a PreparedTransaction, policy: &'a SubmitPolicy) -> SubmitRequest<'a> {
    SubmitRequest {
        prepared,
        policy,
        max_gas_budget: 100_000_000,
        gas_price: 1_000,
        now_ms: prepared.built_at_ms + 1_000,
    }
}

fn reserve_ok() -> serde_json::Value {
    // Flat, exactly as signer-api answers: no `{result, error}` envelope, and
    // the budget comes from the service rather than from us.
    serde_json::json!({
        "sponsor_address": SPONSOR,
        "reservation_id": 42u64,
        "gas_coins": [{ "objectId": COIN, "version": "7", "digest": DIGEST }],
        "gas_budget": 5_000_000u64,
        "expires_at": "2026-09-11T00:00:00.000Z",
    })
}

fn execute_ok() -> serde_json::Value {
    serde_json::json!({
        "digest": "8vV1AbCdEfGhJkLmNpQrStUvWxYz1234567890aBcDeF",
        "effects": { "status": { "status": "success" } },
    })
}

async fn mock_station(reserve: ResponseTemplate, execute: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/sponsorship/reserve"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(reserve)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/sponsorship/execute"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(execute)
        .mount(&server)
        .await;
    server
}

// ── The happy path ──────────────────────────────────────────────────────────

#[tokio::test]
async fn a_verified_payload_is_signed_and_submitted() {
    let (signer, prepared) = signer_and_prepared();
    let policy = policy(signer.address());
    let server = mock_station(
        ResponseTemplate::new(200).set_body_json(reserve_ok()),
        ResponseTemplate::new(200).set_body_json(execute_ok()),
    )
    .await;

    let station = GasStation::new(server.uri(), TOKEN);
    let submitted = submit(request(&prepared, &policy), &signer, &station)
        .await
        .expect("submission should succeed");

    assert_eq!(submitted.reservation_id, 42);
    assert_eq!(submitted.gas_budget, 5_000_000);
    assert!(!submitted.outcome.digest.is_empty());
    assert_eq!(submitted.targets.len(), 1);
    assert_eq!(
        submitted.targets[0].canonical(),
        format!("{TRIEX_PKG}::balance_manager::new")
    );
    assert!(submitted.outcome.effects.is_some());
}

/// The load-bearing assertion of this file: recover the exact bytes and
/// signature that were put on the wire, and check the signature verifies
/// against the agent's own public key over that transaction.
#[tokio::test]
async fn the_submitted_signature_verifies_over_the_submitted_transaction() {
    let (signer, prepared) = signer_and_prepared();
    let policy = policy(signer.address());
    let server = mock_station(
        ResponseTemplate::new(200).set_body_json(reserve_ok()),
        ResponseTemplate::new(200).set_body_json(execute_ok()),
    )
    .await;
    let station = GasStation::new(server.uri(), TOKEN);
    submit(request(&prepared, &policy), &signer, &station)
        .await
        .expect("submission succeeds");

    let executed: Vec<&Request> = server
        .received_requests()
        .await
        .expect("requests recorded")
        .iter()
        .filter(|r| r.url.path() == "/v1/sponsorship/execute")
        .cloned()
        .collect::<Vec<_>>()
        .leak()
        .iter()
        .collect();
    assert_eq!(executed.len(), 1, "exactly one submission");

    let body: serde_json::Value = serde_json::from_slice(&executed[0].body).expect("body is JSON");
    let engine = base64::engine::general_purpose::STANDARD;
    let tx_bytes = engine
        .decode(body["tx_bytes"].as_str().expect("tx_bytes present"))
        .expect("tx_bytes is base64");
    let sig_bytes = engine
        .decode(body["user_sig"].as_str().expect("user_sig present"))
        .expect("user_sig is base64");

    let transaction: Transaction = bcs::from_bytes(&tx_bytes).expect("tx_bytes is a Transaction");
    let signature =
        sui_sdk_types::UserSignature::from_bytes(&sig_bytes).expect("user_sig is a UserSignature");

    // The signature must verify over this exact transaction. A wrong intent
    // prefix or a re-serialized body would fail here.
    Ed25519Verifier::new()
        .verify_transaction(&transaction, &signature)
        .expect("signature must verify over the submitted transaction");

    // Verification alone only proves the signature matches the key carried
    // inside it, so assert that key is ours: otherwise any well-formed
    // signature from any key would satisfy the check above.
    let sui_sdk_types::UserSignature::Simple(sui_sdk_types::SimpleSignature::Ed25519 {
        public_key,
        ..
    }) = &signature
    else {
        panic!("expected a simple Ed25519 signature");
    };
    assert_eq!(
        public_key.derive_address(),
        signer.address(),
        "signed with a key that is not this agent's"
    );
    assert_eq!(*public_key, Ed25519PrivateKey::new([7u8; 32]).public_key());

    // And the gas the signature commits to is the gas the station reserved.
    assert_eq!(transaction.sender, signer.address());
    assert_eq!(
        transaction.gas_payment.owner,
        Address::from_str(SPONSOR).expect("sponsor parses")
    );
    assert_eq!(transaction.gas_payment.budget, 5_000_000);
    assert_eq!(transaction.gas_payment.price, 1_000);
    assert_eq!(transaction.gas_payment.objects.len(), 1);
    assert!(matches!(
        transaction.kind,
        TransactionKind::ProgrammableTransaction(_)
    ));
    assert_eq!(body["reservation_id"], 42);
}

// ── Refusals happen before gas is spent ─────────────────────────────────────

#[tokio::test]
async fn an_unverifiable_payload_never_reserves_gas() {
    let (signer, prepared) = signer_and_prepared();
    // Deny-all policy: the transaction is fine, but nothing is allowlisted.
    let policy = SubmitPolicy::deny_all(signer.address());
    let server = mock_station(
        ResponseTemplate::new(200).set_body_json(reserve_ok()),
        ResponseTemplate::new(200).set_body_json(execute_ok()),
    )
    .await;
    let station = GasStation::new(server.uri(), TOKEN);

    let err = submit(request(&prepared, &policy), &signer, &station)
        .await
        .expect_err("must refuse");
    assert!(matches!(err, SubmitError::Verify(_)), "{err}");

    let calls = server.received_requests().await.expect("recorded");
    assert!(
        calls.is_empty(),
        "verification must fail before any gas-station call, saw {} call(s)",
        calls.len()
    );
}

#[tokio::test]
async fn a_key_that_does_not_match_the_policy_is_refused_before_anything_else() {
    let (signer, prepared) = signer_and_prepared();
    let other = AgentSigner::from_seed(&[9u8; 32]).expect("key loads");
    let policy = policy(other.address());
    let server = mock_station(
        ResponseTemplate::new(200).set_body_json(reserve_ok()),
        ResponseTemplate::new(200).set_body_json(execute_ok()),
    )
    .await;
    let station = GasStation::new(server.uri(), TOKEN);

    let err = submit(request(&prepared, &policy), &signer, &station)
        .await
        .expect_err("must refuse");
    assert!(
        matches!(err, SubmitError::SignerAddressMismatch { .. }),
        "{err}"
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "a misconfigured key must not reach the network"
    );
}

// ── Gas-station failure modes ───────────────────────────────────────────────

#[tokio::test]
async fn a_reserve_refusal_names_the_unapproved_function() {
    // signer-api refuses with a flat `{message, error, statusCode}` body. The
    // message is the operator-useful part and must survive to the caller.
    let (signer, prepared) = signer_and_prepared();
    let policy = policy(signer.address());
    let server = mock_station(
        ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "message": "Move function 'balance_manager::new' is not approved for sponsorship",
            "error": "Forbidden",
            "statusCode": 403,
        })),
        ResponseTemplate::new(200).set_body_json(execute_ok()),
    )
    .await;
    let station = GasStation::new(server.uri(), TOKEN);

    let err = submit(request(&prepared, &policy), &signer, &station)
        .await
        .expect_err("must refuse");
    match err {
        SubmitError::GasStation(GasStationError::Refused { status, message }) => {
            assert_eq!(status, 403);
            assert!(
                message.contains("not approved for sponsorship"),
                "{message}"
            );
        }
        other => panic!("expected a refusal, got {other}"),
    }
}

#[tokio::test]
async fn an_execution_refusal_is_surfaced() {
    let (signer, prepared) = signer_and_prepared();
    let policy = policy(signer.address());
    let server = mock_station(
        ResponseTemplate::new(200).set_body_json(reserve_ok()),
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "error": "reservation expired",
        })),
    )
    .await;
    let station = GasStation::new(server.uri(), TOKEN);

    let err = submit(request(&prepared, &policy), &signer, &station)
        .await
        .expect_err("must refuse");
    match err {
        SubmitError::GasStation(GasStationError::ExecutionFailed { reason }) => {
            assert_eq!(reason, "reservation expired");
        }
        other => panic!("expected a refusal, got {other}"),
    }
}

#[tokio::test]
async fn an_empty_reservation_is_refused_rather_than_signed() {
    let (signer, prepared) = signer_and_prepared();
    let policy = policy(signer.address());
    let server = mock_station(
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sponsor_address": SPONSOR,
            "reservation_id": 1u64,
            "gas_coins": [],
            "gas_budget": 5_000_000u64,
            "expires_at": "2026-09-11T00:00:00.000Z",
        })),
        ResponseTemplate::new(200).set_body_json(execute_ok()),
    )
    .await;
    let station = GasStation::new(server.uri(), TOKEN);

    let err = submit(request(&prepared, &policy), &signer, &station)
        .await
        .expect_err("must refuse");
    assert!(
        matches!(err, SubmitError::GasStation(GasStationError::NoGasCoins)),
        "{err}"
    );
}

#[tokio::test]
async fn an_http_error_is_surfaced_not_swallowed() {
    let (signer, prepared) = signer_and_prepared();
    let policy = policy(signer.address());
    let server = mock_station(
        ResponseTemplate::new(503).set_body_string("upstream down"),
        ResponseTemplate::new(200).set_body_json(execute_ok()),
    )
    .await;
    let station = GasStation::new(server.uri(), TOKEN);

    let err = submit(request(&prepared, &policy), &signer, &station)
        .await
        .expect_err("must refuse");
    match err {
        SubmitError::GasStation(GasStationError::Refused { status, .. }) => {
            assert_eq!(status, 503);
        }
        other => panic!("expected an HTTP status error, got {other}"),
    }
}

#[tokio::test]
async fn an_unusable_gas_coin_is_refused() {
    let (signer, prepared) = signer_and_prepared();
    let policy = policy(signer.address());
    let server = mock_station(
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sponsor_address": SPONSOR,
            "reservation_id": 1u64,
            "gas_coins": [{ "objectId": "not-an-object-id", "version": "1", "digest": DIGEST }],
            "gas_budget": 5_000_000u64,
            "expires_at": "2026-09-11T00:00:00.000Z",
        })),
        ResponseTemplate::new(200).set_body_json(execute_ok()),
    )
    .await;
    let station = GasStation::new(server.uri(), TOKEN);

    let err = submit(request(&prepared, &policy), &signer, &station)
        .await
        .expect_err("must refuse");
    assert!(
        matches!(
            err,
            SubmitError::GasStation(GasStationError::GasCoin { .. })
        ),
        "{err}"
    );
}

// ── Request shape ───────────────────────────────────────────────────────────

#[tokio::test]
async fn the_reservation_request_matches_the_service_contract() {
    let (signer, prepared) = signer_and_prepared();
    let policy = policy(signer.address());
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/sponsorship/reserve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(reserve_ok()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/sponsorship/execute"))
        .respond_with(ResponseTemplate::new(200).set_body_json(execute_ok()))
        .mount(&server)
        .await;
    let station = GasStation::new(server.uri(), TOKEN);
    submit(request(&prepared, &policy), &signer, &station)
        .await
        .expect("succeeds");

    let calls = server.received_requests().await.expect("recorded");
    let reserve = calls
        .iter()
        .find(|r| r.url.path() == "/v1/sponsorship/reserve")
        .expect("reserve was called");
    let body: serde_json::Value = serde_json::from_slice(&reserve.body).expect("JSON");
    // reserve carries the transaction itself; the service derives the budget.
    let tx_bytes = body["tx_bytes"].as_str().expect("tx_bytes present");
    let raw = base64::engine::general_purpose::STANDARD
        .decode(tx_bytes)
        .expect("tx_bytes is base64");
    let unsigned: Transaction = bcs::from_bytes(&raw).expect("decodes as a Transaction");
    assert!(
        body.get("gas_budget").is_none(),
        "budget is the service's call"
    );
    // Gas is a placeholder at this point: the sponsor is not known yet.
    assert_eq!(unsigned.gas_payment.budget, 0);
    assert!(unsigned.gas_payment.objects.is_empty());
    assert_eq!(unsigned.sender, signer.address());
}

#[tokio::test]
async fn a_sponsor_budget_above_the_ceiling_is_refused_before_signing() {
    // The service sets the budget, so the only defence is refusing one that is
    // larger than the operator sanctioned — and refusing it before signing.
    let (signer, prepared) = signer_and_prepared();
    let policy = policy(signer.address());
    let server = mock_station(
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sponsor_address": SPONSOR,
            "reservation_id": 9u64,
            "gas_coins": [{ "objectId": COIN, "version": "7", "digest": DIGEST }],
            "gas_budget": 900_000_000u64,
            "expires_at": "2026-09-11T00:00:00.000Z",
        })),
        ResponseTemplate::new(200).set_body_json(execute_ok()),
    )
    .await;
    let station = GasStation::new(server.uri(), TOKEN);

    let err = submit(request(&prepared, &policy), &signer, &station)
        .await
        .expect_err("must refuse");
    match err {
        SubmitError::GasBudgetTooHigh { budget, max } => {
            assert_eq!(budget, 900_000_000);
            assert_eq!(max, 100_000_000);
        }
        other => panic!("expected a budget refusal, got {other}"),
    }

    let calls = server.received_requests().await.expect("recorded");
    assert!(
        calls
            .iter()
            .all(|r| r.url.path() != "/v1/sponsorship/execute"),
        "must not submit after refusing the budget"
    );
}

#[tokio::test]
async fn a_move_abort_reported_in_a_200_is_not_a_success() {
    // The service answers 200 for a transaction that executed and aborted.
    // Reading only the status code would report this as submitted.
    let (signer, prepared) = signer_and_prepared();
    let policy = policy(signer.address());
    let server = mock_station(
        ResponseTemplate::new(200).set_body_json(reserve_ok()),
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "digest": "8vV1AbCdEfGhJkLmNpQrStUvWxYz1234567890aBcDeF",
            "effects": { "status": { "status": "failure", "error": "MoveAbort(x, 3)" } },
        })),
    )
    .await;
    let station = GasStation::new(server.uri(), TOKEN);

    let err = submit(request(&prepared, &policy), &signer, &station)
        .await
        .expect_err("must surface the abort");
    match err {
        SubmitError::GasStation(GasStationError::ExecutionFailed { reason }) => {
            assert_eq!(reason, "MoveAbort(x, 3)");
        }
        other => panic!("expected an on-chain failure, got {other}"),
    }
}
