//! Adversarial tooling used by the v2.3.0 sweep (not part of the product).
//! Build: `cargo build --release -p qtrc-consensus --example qtr_attack`.
//! Prints signed transaction JSON for the RPC, with optional mutations.
//!
//! qtr_attack tx KEY TO AMOUNT NONCE [op...] [--mut M]
//!   op: none | setg REC_KEY COLD SALT_HEX DELAY ALLOW | rot REC_KEY COLD SALT_HEX
//!       | fin ID | rec ACCOUNT REC_KEY COLD SALT_HEX EPOCH | raw HEX | junk LEN
//!   --mut: garbage_sig | other_key | wrong_domain | flip_amount | short_sig
//! qtr_attack addr KEY
//! qtr_attack bench

use qtrc_common::sentinel::SentinelOp;
use qtrc_common::tx::{Transaction, CHAIN_ID};
use qtrc_crypto::{Address, HydraXKeypair};
use std::time::Instant;

fn load(path: &str) -> HydraXKeypair {
    HydraXKeypair::from_bytes(&std::fs::read(path).expect("read key")).expect("key")
}

fn addr(s: &str) -> Address {
    Address::from_hex(s).expect("addr")
}

fn salt(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a[1].as_str() {
        "addr" => println!("{}", load(&a[2]).address().as_hex()),
        "bench" => bench(),
        "tx" => {
            let kp = load(&a[2]);
            let to = addr(&a[3]);
            let amount: u64 = a[4].parse().unwrap();
            let nonce: u64 = a[5].parse().unwrap();
            let mut i = 6;
            let mut data = Vec::new();
            let mut muts = Vec::new();
            while i < a.len() {
                match a[i].as_str() {
                    "--mut" => {
                        muts.push(a[i + 1].clone());
                        i += 2;
                    }
                    "setg" => {
                        let rec = load(&a[i + 1]);
                        let c = qtrc_sentinel::recovery_commitment(
                            CHAIN_ID.as_bytes(), &kp.address(), &rec.address(), &addr(&a[i + 2]), &salt(&a[i + 3]));
                        data = SentinelOp::SetGuardian {
                            commitment: c,
                            delay_blocks: a[i + 4].parse().unwrap(),
                            allowance_per_window: a[i + 5].parse().unwrap(),
                        }
                        .encode();
                        i += 6;
                    }
                    "rot" => {
                        let rec = load(&a[i + 1]);
                        let c = qtrc_sentinel::recovery_commitment(
                            CHAIN_ID.as_bytes(), &kp.address(), &rec.address(), &addr(&a[i + 2]), &salt(&a[i + 3]));
                        data = SentinelOp::RotateGuardian { commitment: c }.encode();
                        i += 4;
                    }
                    "fin" => {
                        data = SentinelOp::Finalize { id: a[i + 1].parse().unwrap() }.encode();
                        i += 2;
                    }
                    "rec" => {
                        let account = addr(&a[i + 1]);
                        let rec = load(&a[i + 2]);
                        let cold = addr(&a[i + 3]);
                        let s = salt(&a[i + 4]);
                        let epoch: u64 = a[i + 5].parse().unwrap();
                        let c = qtrc_sentinel::recovery_commitment(CHAIN_ID.as_bytes(), &account, &rec.address(), &cold, &s);
                        let msg = qtrc_sentinel::recovery_message(CHAIN_ID.as_bytes(), &account, &c, epoch);
                        data = SentinelOp::Recover { cold_dest: cold, salt: s, proof: Box::new(rec.sign(&msg)) }.encode();
                        i += 6;
                    }
                    "raw" => {
                        data = unhex(&a[i + 1]);
                        i += 2;
                    }
                    "junk" => {
                        let n: usize = a[i + 1].parse().unwrap();
                        data = b"QSN1".to_vec();
                        data.resize(n, 0xAB);
                        i += 2;
                    }
                    "none" => i += 1,
                    other => panic!("unknown arg {other}"),
                }
            }
            let from = kp.address();
            let mut payload = Transaction::signing_payload_with_data(&from, &to, amount, nonce, &data);
            if muts.iter().any(|m| m == "wrong_domain") {
                // v1-style: drop the domain prefix
                let p = qtrc_common::tx::signing_domain_prefix();
                payload = payload[p.len()..].to_vec();
            }
            let signer = if muts.iter().any(|m| m == "other_key") { HydraXKeypair::generate() } else { kp };
            let mut sig = signer.sign(&payload);
            if muts.iter().any(|m| m == "garbage_sig") {
                for b in sig.ml_dsa_sig.iter_mut() { *b = 0x5a; }
                for b in sig.slh_dsa_sig.iter_mut() { *b = 0xa5; }
            }
            if muts.iter().any(|m| m == "slh_only_garbage") {
                sig.slh_dsa_sig[100] ^= 1;
            }
            if muts.iter().any(|m| m == "short_sig") {
                sig.slh_dsa_sig.truncate(10);
            }
            let mut tx = Transaction { from, to, amount, nonce, timestamp: 0, signature: sig, data };
            if muts.iter().any(|m| m == "flip_amount") {
                tx.amount += 1;
            }
            println!("{}", serde_json::to_string(&tx).unwrap());
        }
        other => panic!("unknown cmd {other}"),
    }
}

fn bench() {
    let kp = HydraXKeypair::generate();
    let to = HydraXKeypair::generate().address();
    let t = Instant::now();
    let n = 3;
    let mut txs = Vec::new();
    for i in 0..n {
        let payload = Transaction::signing_payload(&kp.address(), &to, 1, i);
        txs.push(Transaction { from: kp.address(), to: to.clone(), amount: 1, nonce: i, timestamp: 0, signature: kp.sign(&payload), data: vec![] });
    }
    println!("sign (HYDRA-X): {:?} per tx", t.elapsed() / n as u32);
    let t = Instant::now();
    for _ in 0..20 {
        for tx in &txs { tx.verify().unwrap(); }
    }
    println!("verify valid tx: {:?} per tx", t.elapsed() / (20 * n as u32));
    let mut bad = txs[0].clone();
    for b in bad.signature.slh_dsa_sig.iter_mut() { *b = 0; }
    let t = Instant::now();
    for _ in 0..60 { let _ = bad.verify(); }
    println!("verify tx with garbage SLH leg (ML ok): {:?}", t.elapsed() / 60);
    let mut bad2 = txs[0].clone();
    for b in bad2.signature.ml_dsa_sig.iter_mut() { *b = 0; }
    let t = Instant::now();
    for _ in 0..60 { let _ = bad2.verify(); }
    println!("verify tx with garbage ML leg (sequential, ML first): {:?}", t.elapsed() / 60);
    let js = serde_json::to_string(&txs[0]).unwrap();
    println!("plain tx JSON size: {} bytes", js.len());
    let t = Instant::now();
    for _ in 0..50 { let _: Transaction = serde_json::from_str(&js).unwrap(); }
    println!("JSON parse of a tx: {:?}", t.elapsed() / 50);
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
