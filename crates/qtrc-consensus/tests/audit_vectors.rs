//! Audit test vectors: the exact bytes every HYDRA-X signature covers, and
//! known-answer checks for the AND-composition.
//!
//! The vectors live in `audit/vectors.json` at the repository root.
//!
//! * `cargo test -p qtrc-consensus --test audit_vectors` checks the code
//!   against the file: every encoding must match byte for byte, every
//!   stored signature must verify, every negative case must be rejected.
//! * `AUDIT_VECTORS_WRITE=1 cargo test -p qtrc-consensus --test audit_vectors -- --nocapture`
//!   regenerates the file. Do this only for an intended consensus change,
//!   and review the diff.
//!
//! ML-DSA-87 signing in PQClean is randomized (hedged), so the ML-DSA
//! component of a stored signature is not reproducible; the check is that
//! it verifies. The SLH-DSA component is deterministic (non-hedged).

use qtrc_bft::types::{NilOrVal, Round, VoteType};
use qtrc_bft::{BlockId, Height, Proposal, ValAddr, Value, Vote};
use qtrc_common::block::{BlockHash, BlockHeader};
use qtrc_common::tx::{signing_domain_prefix, Transaction, TxHash, CHAIN_ID};
use qtrc_crypto::{Address, HydraXKeypair, HydraXSignature};
use serde_json::{json, Value as Json};
use sha3::{Digest, Sha3_256};

fn file() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../audit/vectors.json")
}

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

fn unhex(v: &Json) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

fn addr(byte: u8) -> Address {
    Address([byte; 32])
}

/// Every encoding vector: name, the inputs as stated in the file, and the
/// bytes the code produces for them.
fn encodings() -> Vec<(&'static str, Json, Vec<u8>)> {
    let mut out = Vec::new();

    out.push(("signing_domain_prefix", json!({ "domain": "QTR-HYDRAX-V2", "chain_id": CHAIN_ID }), signing_domain_prefix()));

    let (from, to) = (addr(0x11), addr(0x22));
    out.push((
        "tx_payload_plain",
        json!({ "from": h(&from.0), "to": h(&to.0), "amount": 1_500_000u64, "nonce": 7u64, "data": "" }),
        Transaction::signing_payload(&from, &to, 1_500_000, 7),
    ));
    let data = b"\x01sentinel-op-bytes".to_vec();
    out.push((
        "tx_payload_with_data",
        json!({ "from": h(&from.0), "to": h(&from.0), "amount": 0u64, "nonce": 8u64, "data": h(&data) }),
        Transaction::signing_payload_with_data(&from, &from, 0, 8, &data),
    ));

    let header = BlockHeader {
        height: 42,
        prev_hash: BlockHash([0x33; 32]),
        merkle_root: TxHash([0x44; 32]),
        timestamp: 1_790_000_000,
        proposer: addr(0x55),
        state_root: Some([0x66; 32]),
        witness_root: Some([0x77; 32]),
    };
    out.push((
        "block_header_signing_bytes",
        json!({ "header_json": serde_json::to_string(&header).unwrap(), "note": "domain prefix || \"BLK\" || serde_json::to_vec(header)" }),
        header.signing_bytes(),
    ));
    let legacy_header = BlockHeader { state_root: None, witness_root: None, ..header.clone() };
    out.push((
        "block_header_signing_bytes_pre_activation",
        json!({ "header_json": serde_json::to_string(&legacy_header).unwrap(), "note": "state_root and witness_root absent before their activation heights" }),
        legacy_header.signing_bytes(),
    ));

    let val = ValAddr::from(&addr(0x88));
    let id = BlockId([0x99; 32]);
    let prevote_nil = Vote { typ: VoteType::Prevote, height: Height(42), round: Round::new(0), value: NilOrVal::Nil, validator: val, extension: None };
    out.push(("bft_prevote_nil", json!({ "height": 42, "round": 0, "value": "nil", "validator": h(&addr(0x88).0) }), prevote_nil.sign_bytes()));
    let precommit = Vote { typ: VoteType::Precommit, height: Height(42), round: Round::new(3), value: NilOrVal::Val(id), validator: val, extension: None };
    out.push(("bft_precommit_value", json!({ "height": 42, "round": 3, "value": h(&id.0), "validator": h(&addr(0x88).0) }), precommit.sign_bytes()));
    let proposal = Proposal { height: Height(42), round: Round::new(3), value: Value(id), pol_round: Round::Nil, proposer: val };
    out.push(("bft_proposal", json!({ "height": 42, "round": 3, "value": h(&id.0), "pol_round": -1, "proposer": h(&addr(0x88).0) }), proposal.sign_bytes()));

    let salt = [0xaa; 32];
    let commitment = qtrc_sentinel::recovery_commitment(CHAIN_ID.as_bytes(), &addr(0x11), &addr(0xbb), &addr(0xcc), &salt);
    out.push((
        "sentinel_commitment",
        json!({ "account": h(&addr(0x11).0), "recovery_address": h(&addr(0xbb).0), "cold_dest": h(&addr(0xcc).0), "salt": h(&salt), "note": "SHA3-256 of length-prefixed fields; this is a commitment, not a signed message" }),
        commitment.to_vec(),
    ));
    out.push((
        "sentinel_recovery_message_v3",
        json!({ "account": h(&addr(0x11).0), "commitment": h(&commitment), "epoch": 2u64, "note": "full message, signed directly" }),
        qtrc_sentinel::recovery_message(CHAIN_ID.as_bytes(), &addr(0x11), &commitment, 2),
    ));
    out.push((
        "sentinel_recovery_message_legacy",
        json!({ "account": h(&addr(0x11).0), "commitment": h(&commitment), "epoch": 2u64, "note": "pre-v3 32-byte digest; verified only below recovery_v3_from_height" }),
        qtrc_sentinel::recovery_message_legacy(CHAIN_ID.as_bytes(), &addr(0x11), &commitment, 2).to_vec(),
    ));
    out
}

fn sig_json(s: &HydraXSignature) -> Json {
    json!({ "ml_dsa_sig": h(&s.ml_dsa_sig), "slh_dsa_sig": h(&s.slh_dsa_sig) })
}

fn sig_from(kp: &HydraXKeypair, v: &Json) -> HydraXSignature {
    HydraXSignature { ml_dsa_sig: unhex(&v["ml_dsa_sig"]), slh_dsa_sig: unhex(&v["slh_dsa_sig"]), verifying_key: kp.verifying_key.clone() }
}

fn write() {
    let enc: Vec<Json> = encodings()
        .into_iter()
        .map(|(name, inputs, bytes)| json!({ "name": name, "inputs": inputs, "bytes": h(&bytes), "len": bytes.len(), "sha3_256": h(&Sha3_256::digest(&bytes)) }))
        .collect();

    let a = HydraXKeypair::generate();
    let b = HydraXKeypair::generate();
    let msg = Transaction::signing_payload(&a.address(), &addr(0x22), 1_500_000, 7);
    let sa = a.sign(&msg);
    let sb = b.sign(&msg);
    assert!(sa.verify(&msg).is_ok() && sb.verify(&msg).is_ok());

    let doc = json!({
        "version": 1,
        "chain_id": CHAIN_ID,
        "warning": "TEST KEYS ONLY. The secret keys below are public; never fund these addresses.",
        "encodings": enc,
        "and_composition": {
            "schemes": { "ml_dsa": "ML-DSA-87 (FIPS 204, pqcrypto-mldsa)", "slh_dsa": "SLH-DSA-SHA2-256s (FIPS 205, fips205), pure mode, empty context, deterministic" },
            "sizes": { "ml_dsa_pk": a.verifying_key.ml_dsa_pk_bytes().len(), "slh_dsa_pk": a.verifying_key.slh_dsa_pk_bytes().len(), "ml_dsa_sig": sa.ml_dsa_sig.len(), "slh_dsa_sig": sa.slh_dsa_sig.len() },
            "address_rule": "address = BLAKE3(ml_dsa_pk || slh_dsa_pk)",
            "message": h(&msg),
            "message_is": "tx_payload_plain with from = key_a address",
            "key_a": { "keyfile": h(&a.to_bytes()), "address": a.address().as_hex() },
            "key_b": { "keyfile": h(&b.to_bytes()), "address": b.address().as_hex() },
            "sig_a": sig_json(&sa),
            "sig_b": sig_json(&sb),
            "cases": [
                { "name": "valid", "key": "a", "ml_dsa": "sig_a", "slh_dsa": "sig_a", "expect": "accept" },
                { "name": "ml_dsa_from_other_key", "key": "a", "ml_dsa": "sig_b", "slh_dsa": "sig_a", "expect": "reject_ml_dsa" },
                { "name": "slh_dsa_from_other_key", "key": "a", "ml_dsa": "sig_a", "slh_dsa": "sig_b", "expect": "reject_slh_dsa" },
                { "name": "ml_dsa_bit_flip", "key": "a", "ml_dsa": "sig_a^flip", "slh_dsa": "sig_a", "expect": "reject_ml_dsa" },
                { "name": "slh_dsa_bit_flip", "key": "a", "ml_dsa": "sig_a", "slh_dsa": "sig_a^flip", "expect": "reject_slh_dsa" },
                { "name": "slh_dsa_truncated", "key": "a", "ml_dsa": "sig_a", "slh_dsa": "sig_a^truncate", "expect": "reject_slh_dsa" },
                { "name": "message_changed", "key": "a", "ml_dsa": "sig_a", "slh_dsa": "sig_a", "message": "flip_last_byte", "expect": "reject" }
            ]
        }
    });
    let path = file();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
}

#[test]
fn audit_vectors() {
    if std::env::var("AUDIT_VECTORS_WRITE").is_ok() {
        write();
    }
    let doc: Json = serde_json::from_slice(&std::fs::read(file()).expect("audit/vectors.json missing")).unwrap();
    assert_eq!(doc["chain_id"], CHAIN_ID);

    // 1. Encodings, byte for byte.
    let stored = doc["encodings"].as_array().unwrap();
    let produced = encodings();
    assert_eq!(stored.len(), produced.len(), "vector count changed");
    for (s, (name, _, bytes)) in stored.iter().zip(produced) {
        assert_eq!(s["name"], name);
        assert_eq!(unhex(&s["bytes"]), bytes, "encoding changed: {name}");
        assert_eq!(s["len"], bytes.len());
    }

    // 2. AND-composition known answers.
    let ac = &doc["and_composition"];
    let a = HydraXKeypair::from_bytes(&unhex(&ac["key_a"]["keyfile"])).unwrap();
    let b = HydraXKeypair::from_bytes(&unhex(&ac["key_b"]["keyfile"])).unwrap();
    assert_eq!(a.address().as_hex(), ac["key_a"]["address"].as_str().unwrap());
    let msg = unhex(&ac["message"]);
    assert_eq!(msg, Transaction::signing_payload(&a.address(), &addr(0x22), 1_500_000, 7));

    let sa = sig_from(&a, &ac["sig_a"]);
    let sb = sig_from(&b, &ac["sig_b"]);
    // SLH-DSA is deterministic: re-signing gives the stored component.
    assert_eq!(a.sign(&msg).slh_dsa_sig, sa.slh_dsa_sig, "SLH-DSA component not reproducible");

    let flip = |mut v: Vec<u8>| {
        v[100] ^= 1;
        v
    };
    let pick = |which: &str, ml: bool| -> Vec<u8> {
        let base = if which.starts_with("sig_b") { &sb } else { &sa };
        let v = if ml { base.ml_dsa_sig.clone() } else { base.slh_dsa_sig.clone() };
        match which.split('^').nth(1) {
            Some("flip") => flip(v),
            Some("truncate") => v[..v.len() - 1].to_vec(),
            _ => v,
        }
    };
    for c in ac["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let sig = HydraXSignature {
            ml_dsa_sig: pick(c["ml_dsa"].as_str().unwrap(), true),
            slh_dsa_sig: pick(c["slh_dsa"].as_str().unwrap(), false),
            verifying_key: a.verifying_key.clone(),
        };
        let mut m = msg.clone();
        if c["message"] == "flip_last_byte" {
            *m.last_mut().unwrap() ^= 1;
        }
        let r = sig.verify(&m);
        let ok = match c["expect"].as_str().unwrap() {
            "accept" => r.is_ok(),
            "reject_ml_dsa" => matches!(r, Err(qtrc_crypto::CryptoError::MlDsaInvalid)),
            "reject_slh_dsa" => matches!(r, Err(qtrc_crypto::CryptoError::SlhDsaInvalid)),
            "reject" => r.is_err(),
            other => panic!("unknown expectation {other}"),
        };
        assert!(ok, "case {name}: got {r:?}");
    }

    // 3. A full transaction: the signature's key must also derive `from`.
    let tx = Transaction { from: a.address(), to: addr(0x22), amount: 1_500_000, nonce: 7, timestamp: 0, signature: sa.clone(), data: vec![] };
    assert!(tx.verify().is_ok());
    let wrong_from = Transaction { from: b.address(), ..tx };
    assert!(wrong_from.verify().is_err(), "valid signature under a key that is not `from` must be rejected");
}
