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

#[test]
fn tx_id_is_not_malleable_and_matches_mempool() {
    let faucet = HydraXKeypair::generate();
    let user = HydraXKeypair::generate().address();
    let genesis = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let engine = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::generate());

    let tx = transfer(&faucet, &user, MICRO_QTR, 0);
    let id = tx.hash();

    // Mudar o timestamp (campo não assinado) não pode mudar o ID.
    let mut relayed = tx.clone();
    relayed.timestamp += 12_345;
    assert!(relayed.verify().is_ok(), "assinatura continua valida");
    assert_eq!(relayed.hash(), id, "ID nao pode depender do timestamp");

    // Uma segunda assinatura valida do mesmo payload também não muda o ID.
    let mut resigned = tx.clone();
    resigned.signature = faucet.sign(&Transaction::signing_payload(&tx.from, &tx.to, tx.amount, tx.nonce));
    assert_eq!(resigned.hash(), id);

    // O ID devolvido pelo mempool é o mesmo do núcleo.
    let mempool_id = engine.submit_tx(tx).expect("submit");
    assert_eq!(mempool_id, id);
}

#[test]
fn invalid_tx_is_dropped_instead_of_halting_the_chain() {
    let faucet = HydraXKeypair::generate();
    let user = HydraXKeypair::generate().address();
    let genesis = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let engine = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::generate());

    engine.submit_tx(transfer(&faucet, &user, 10 * MICRO_QTR, 0)).expect("tx 0");
    // Nonce repetido: tem que ser descartada, sem travar o bloco.
    engine.submit_tx(transfer(&faucet, &user, 20 * MICRO_QTR, 0)).expect("tx dup nonce");
    // Sem saldo: também descartada.
    let broke = HydraXKeypair::generate();
    engine.submit_tx(transfer(&broke, &user, MICRO_QTR, 0)).expect("tx sem saldo");

    let block = engine.propose_block().expect("propose");
    assert_eq!(block.transactions.len(), 1, "so a tx valida entra");
    engine.commit_block(block).expect("commit");

    let state = engine.state.read();
    assert_eq!(state.height, 1);
    assert_eq!(state.account(&user).balance, 10 * MICRO_QTR);
    drop(state);
    assert!(engine.mempool.read().is_empty(), "invalidas nao voltam para a fila");

    // E a chain segue: o próximo bloco funciona normalmente.
    assert_eq!(engine.next_nonce(&faucet.address()), 1);
    engine.submit_tx(transfer(&faucet, &user, MICRO_QTR, 1)).expect("tx 1");
    engine.commit_block(engine.propose_block().expect("propose 2")).expect("commit 2");
    assert_eq!(engine.state.read().height, 2);
}

#[test]
fn tampered_block_is_rejected_and_state_untouched() {
    let faucet = HydraXKeypair::generate();
    let user = HydraXKeypair::generate().address();
    let genesis = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let engine = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::generate());

    engine.submit_tx(transfer(&faucet, &user, MICRO_QTR, 0)).expect("tx");
    let mut block = engine.propose_block().expect("propose");
    // Enfia uma tx depois da assinatura do proponente: a raiz Merkle não bate.
    block.transactions.push(transfer(&faucet, &user, 5 * MICRO_QTR, 1));
    assert!(engine.commit_block(block).is_err());

    let state = engine.state.read();
    assert_eq!(state.height, 0);
    assert_eq!(state.account(&user).balance, 0);
}

#[test]
fn next_nonce_counts_pending_transactions() {
    let faucet = HydraXKeypair::generate();
    let user = HydraXKeypair::generate().address();
    let genesis = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let engine = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::generate());

    assert_eq!(engine.next_nonce(&faucet.address()), 0);
    engine.submit_tx(transfer(&faucet, &user, MICRO_QTR, 0)).expect("tx 0");
    engine.submit_tx(transfer(&faucet, &user, MICRO_QTR, 1)).expect("tx 1");
    assert_eq!(engine.next_nonce(&faucet.address()), 2);

    engine.commit_block(engine.propose_block().expect("propose")).expect("commit");
    assert_eq!(engine.next_nonce(&faucet.address()), 2);
    assert_eq!(engine.state.read().account(&user).balance, 2 * MICRO_QTR);
}

#[test]
fn unsigned_block_is_rejected() {
    let faucet = HydraXKeypair::generate();
    let user = HydraXKeypair::generate().address();
    let genesis = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let engine = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::generate());

    engine.submit_tx(transfer(&faucet, &user, MICRO_QTR, 0)).expect("tx");
    let mut block = engine.propose_block().expect("propose");
    block.validator_sigs.clear();
    assert!(engine.commit_block(block).is_err(), "bloco sem assinatura do proponente");
}

#[test]
fn replay_rebuilds_same_state() {
    let faucet = HydraXKeypair::generate();
    let user = HydraXKeypair::generate().address();
    let genesis = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));

    let a = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::generate());
    let mut blocks = vec![];
    for n in 0..3 {
        a.submit_tx(transfer(&faucet, &user, MICRO_QTR, n)).expect("tx");
        let b = a.propose_block().expect("propose");
        blocks.push(b.clone());
        a.commit_block(b).expect("commit");
    }

    // Um node novo, mesmo gênesis, reaplicando os blocos gravados.
    let b = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::generate());
    for blk in blocks {
        b.replay_block(blk).expect("replay");
    }
    let (sa, sb) = (a.state.read(), b.state.read());
    assert_eq!(sa.height, 3);
    assert_eq!(sb.height, sa.height);
    assert_eq!(sb.block_hash, sa.block_hash);
    assert_eq!(sb.account(&user).balance, 3 * MICRO_QTR);
}
