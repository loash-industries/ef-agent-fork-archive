"""ZERO-2 spike: sign a Sui transaction with an AWS KMS Ed25519 key.

    kms_sui.py address <key-id>
    kms_sui.py sign <key-id> <tx-bytes-base64>

`sign` prints the Sui serialized signature (base64 of flag || sig || pubkey)
after verifying it locally against the key's public half.
"""
import base64
import hashlib
import json
import subprocess
import sys

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)

PROFILE = ["--profile", "triex-admin", "--region", "us-east-2"]
ED25519_FLAG = b"\x00"
# IntentScope::TransactionData = 0, IntentVersion::V0 = 0, AppId::Sui = 0.
TX_INTENT = b"\x00\x00\x00"


def aws(*args):
    out = subprocess.run(["aws", "kms", *args, *PROFILE, "--output", "json"],
                         check=True, capture_output=True, text=True).stdout
    return json.loads(out)


def public_key(key_id):
    der = base64.b64decode(aws("get-public-key", "--key-id", key_id)["PublicKey"])
    pk = load_der_public_key(der)
    return pk, pk.public_bytes(Encoding.Raw, PublicFormat.Raw)


def address(raw_pk):
    return "0x" + hashlib.blake2b(ED25519_FLAG + raw_pk, digest_size=32).hexdigest()


def signing_message(tx_bytes):
    """What Ed25519 signs for a Sui transaction: Blake2b-256(intent || tx)."""
    return hashlib.blake2b(TX_INTENT + tx_bytes, digest_size=32).digest()


def main():
    cmd, key_id = sys.argv[1], sys.argv[2]
    pk, raw_pk = public_key(key_id)
    if cmd == "address":
        print(address(raw_pk))
        return
    tx_bytes = base64.b64decode(sys.argv[3])
    msg = signing_message(tx_bytes)
    resp = aws("sign", "--key-id", key_id, "--message", base64.b64encode(msg).decode(),
               "--message-type", "RAW", "--signing-algorithm", "ED25519_SHA_512")
    sig = base64.b64decode(resp["Signature"])
    assert len(sig) == 64, f"expected a raw 64-byte Ed25519 signature, got {len(sig)}"
    pk.verify(sig, msg)  # raises InvalidSignature on mismatch
    print("verified locally; message (hex):", msg.hex(), file=sys.stderr)
    print(base64.b64encode(ED25519_FLAG + sig + raw_pk).decode())


if __name__ == "__main__":
    main()
