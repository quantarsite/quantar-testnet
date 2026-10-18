//! HYDRA-X v2 de ponta a ponta: o núcleo assina, o mempool (hx-mempool)
//! verifica as duas pernas FIPS, o bloco aplica o saldo, e uma assinatura
//! feita sem o domínio v2 é rejeitada.

use qtrc_common::genesis::{Genesis, MICRO_QTR};
use qtrc_common::tx::{signing_domain_prefix, Transaction, CHAIN_ID};
use qtrc_consensus::ConsensusEngine;
use qtrc_crypto::{Address, HydraXKeypair};

fn transfer(kp: &HydraXKeypair, to: &Address, amount: u64, nonce: u64) -> Transaction {
    let from = kp.address();
    let payload = Transaction::signing_payload(&from, to, amount, nonce);
    Transaction {
        from,
        to: to.clone(),
        amount,
        nonce,
        timestamp: 1_792_281_600,
        signature: kp.sign(&payload),
    }
}

#[test]
fn domain_prefix_matches_hx_mempool() {
    assert_eq!(signing_domain_prefix(), hx_mempool::types::signing_domain_prefix());
    assert_eq!(CHAIN_ID, hx_mempool::types::CHAIN_ID);
}

#[test]
fn faucet_transfer_goes_through_mempool_and_block() {
    let faucet = HydraXKeypair::generate();
    let user = HydraXKeypair::generate().address();

    let genesis = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    assert_eq!(genesis.chain_id, "quantar-testnet-2");
    assert_eq!(genesis.allocations.len(), 1);

    let engine = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::generate());

    let amount = 500 * MICRO_QTR;
    engine
        .submit_tx(transfer(&faucet, &user, amount, 0))
        .expect("tx assinada no v2 deve passar pelo mempool");

    let block = engine.propose_block().expect("propose");
    assert_eq!(block.transactions.len(), 1);
    engine.commit_block(block).expect("commit");

    let state = engine.state.read();
    assert_eq!(state.account(&user).balance, amount);
    assert_eq!(state.account(&faucet.address()).nonce, 1);
}

#[test]
fn v1_style_signature_without_domain_is_rejected() {
    let faucet = HydraXKeypair::generate();
    let user = HydraXKeypair::generate().address();
    let genesis = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let engine = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::generate());

    // Assina o layout antigo (sem prefixo de domínio e chain id).
    let mut tx = transfer(&faucet, &user, MICRO_QTR, 0);
    let prefix_len = signing_domain_prefix().len();
    let v1_payload = Transaction::signing_payload(&tx.from, &tx.to, tx.amount, tx.nonce)[prefix_len..].to_vec();
    tx.signature = faucet.sign(&v1_payload);

    assert!(tx.verify().is_err(), "verify local tem que rejeitar");
    assert!(engine.submit_tx(tx).is_err(), "mempool tem que rejeitar");
}

#[test]
fn genesis_without_faucet_address_has_no_allocation() {
    assert!(Genesis::testnet_with_faucet(None).allocations.is_empty());
    assert!(Genesis::testnet_with_faucet(Some("nao-e-hex")).allocations.is_empty());
}
