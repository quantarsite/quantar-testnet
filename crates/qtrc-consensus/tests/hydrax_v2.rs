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
        data: vec![],
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
fn bad_txs_are_refused_at_the_door() {
    let faucet = HydraXKeypair::generate();
    let user = HydraXKeypair::generate().address();
    let genesis = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let engine = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::generate());

    engine.submit_tx(transfer(&faucet, &user, 10 * MICRO_QTR, 0)).expect("tx 0");
    // Nonce repetido, nonce pulado, conta sem saldo: recusadas antes de custar CPU.
    assert!(engine.submit_tx(transfer(&faucet, &user, 20 * MICRO_QTR, 0)).is_err(), "nonce repetido");
    assert!(engine.submit_tx(transfer(&faucet, &user, MICRO_QTR, 5)).is_err(), "nonce pulado");
    let broke = HydraXKeypair::generate();
    assert!(engine.submit_tx(transfer(&broke, &user, MICRO_QTR, 0)).is_err(), "sem saldo");
    assert_eq!(engine.mempool.read().len(), 1);

    engine.commit_block(engine.propose_block().expect("propose")).expect("commit");
    assert_eq!(engine.state.read().account(&user).balance, 10 * MICRO_QTR);
}

#[test]
fn invalid_tx_that_slips_in_is_dropped_not_halting_the_chain() {
    let faucet = HydraXKeypair::generate();
    let user = HydraXKeypair::generate().address();
    let genesis = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let engine = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::generate());

    engine.submit_tx(transfer(&faucet, &user, 10 * MICRO_QTR, 0)).expect("tx 0");
    // Força uma tx inválida direto na fila (simula algo que escapou da entrada).
    engine.mempool.write().push(qtrc_consensus::mempool::Entry::new(transfer(&faucet, &user, 20 * MICRO_QTR, 0), false));

    let block = engine.propose_block().expect("propose");
    assert_eq!(block.transactions.len(), 1, "so a tx valida entra");
    engine.commit_block(block).expect("commit");
    assert!(engine.mempool.read().is_empty());

    engine.submit_tx(transfer(&faucet, &user, MICRO_QTR, 1)).expect("tx 1");
    engine.commit_block(engine.propose_block().expect("propose 2")).expect("commit 2");
    assert_eq!(engine.state.read().height, 2);
}

#[test]
fn nonce_stays_correct_while_a_block_is_being_built() {
    // Revisão independente, achado H1: durante a montagem do bloco o faucet
    // recebia um nonce já usado e a tx sumia em silêncio.
    let faucet = HydraXKeypair::generate();
    let user = HydraXKeypair::generate().address();
    let genesis = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let engine = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::generate());

    engine.submit_tx(transfer(&faucet, &user, MICRO_QTR, 0)).expect("tx 0");
    let block = engine.propose_block().expect("propose");
    // Bloco montado, ainda não confirmado: a tx 0 continua contando.
    assert_eq!(engine.next_nonce(&faucet.address()), 1);
    // Uma tx diferente com o mesmo nonce 0 tem que ser recusada...
    assert!(engine.submit_tx(transfer(&faucet, &user, 7 * MICRO_QTR, 0)).is_err(), "nonce 0 ja em uso");
    // ...e reenviar a mesma tx é idempotente (mesmo ID, não duplica).
    let again = engine.submit_tx(transfer(&faucet, &user, MICRO_QTR, 0)).expect("reenvio identico");
    assert_eq!(again, block.transactions[0].hash());
    assert!(engine.mempool.read().is_empty());
    engine.submit_tx(transfer(&faucet, &user, MICRO_QTR, 1)).expect("tx 1 durante a montagem");

    engine.commit_block(block).expect("commit");
    engine.commit_block(engine.propose_block().expect("propose 2")).expect("commit 2");
    assert_eq!(engine.state.read().account(&user).balance, 2 * MICRO_QTR);
}

#[test]
fn failed_own_block_puts_txs_back_in_order() {
    let faucet = HydraXKeypair::generate();
    let user = HydraXKeypair::generate().address();
    let genesis = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let engine = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::generate());

    engine.submit_tx(transfer(&faucet, &user, MICRO_QTR, 0)).expect("tx 0");
    let mut block = engine.propose_block().expect("propose");
    block.validator_sigs.clear(); // força a falha do commit
    assert!(engine.commit_block(block).is_err());
    assert_eq!(engine.mempool.read().len(), 1, "a tx volta para a fila");
    engine.commit_block(engine.propose_block().expect("propose de novo")).expect("commit");
    assert_eq!(engine.state.read().account(&user).balance, MICRO_QTR);
}

#[test]
fn dropped_tx_can_be_resubmitted() {
    // Achado M2: depois de descartada, a tx nunca mais entrava ("OK" falso).
    let faucet = HydraXKeypair::generate();
    let user = HydraXKeypair::generate().address();
    let genesis = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let engine = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::generate());

    let tx = transfer(&faucet, &user, MICRO_QTR, 0);
    engine.submit_tx(tx.clone()).expect("primeira vez");
    engine.mempool.write().clear(); // some da fila, mas o hx-mempool ainda lembra
    engine.submit_tx(tx).expect("reenvio");
    assert_eq!(engine.mempool.read().len(), 1, "o reenvio tem que entrar de verdade");
}

#[test]
fn per_sender_cap_and_disk_guard() {
    let faucet = HydraXKeypair::generate();
    let user = HydraXKeypair::generate().address();
    let genesis = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let engine = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::generate());

    for n in 0..qtrc_consensus::MAX_PENDING_PER_SENDER as u64 {
        engine.submit_tx(transfer(&faucet, &user, 1, n)).expect("dentro do limite");
    }
    let over = qtrc_consensus::MAX_PENDING_PER_SENDER as u64;
    assert!(engine.submit_tx(transfer(&faucet, &user, 1, over)).is_err(), "passou do limite por conta");

    let other = HydraXKeypair::generate();
    let engine2 = ConsensusEngine::new(
        Genesis::testnet_with_faucet(Some(&other.address().as_hex())).initial_state(),
        HydraXKeypair::generate(),
    );
    engine2.set_accepting(false);
    assert!(engine2.submit_tx(transfer(&other, &user, 1, 0)).is_err(), "disco cheio recusa");
    engine2.set_accepting(true);
    engine2.submit_tx(transfer(&other, &user, 1, 0)).expect("volta a aceitar");
}

#[test]
fn block_from_a_different_key_is_rejected() {
    // Achado M1: aceitava bloco assinado por qualquer chave.
    use qtrc_common::block::ValidatorSig;
    let faucet = HydraXKeypair::generate();
    let user = HydraXKeypair::generate().address();
    let genesis = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let engine = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::generate());
    let attacker = HydraXKeypair::generate();

    engine.submit_tx(transfer(&faucet, &user, MICRO_QTR, 0)).expect("tx");
    let honest = engine.propose_block().expect("propose");

    // 1) atacante se declara proponente e assina com a própria chave
    let mut b1 = honest.clone();
    b1.header.proposer = attacker.address();
    b1.validator_sigs = vec![ValidatorSig {
        validator: attacker.address(),
        signature: attacker.sign(&b1.header.signing_bytes()),
    }];
    assert!(engine.commit_block(b1).is_err(), "proponente errado");

    // 2) atacante finge ser o node, mas assina com a chave dele
    let mut b2 = honest.clone();
    b2.validator_sigs = vec![ValidatorSig {
        validator: engine.address.clone(),
        signature: attacker.sign(&b2.header.signing_bytes()),
    }];
    assert!(engine.commit_block(b2).is_err(), "assinatura de outra chave");
    assert_eq!(engine.state.read().height, 0);

    engine.commit_block(honest).expect("o bloco honesto continua valido");
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

    // O node reinicia com a mesma chave (arquivo de chave persistente).
    let node_key = HydraXKeypair::generate().to_bytes();
    let a = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::from_bytes(&node_key).unwrap());
    let mut blocks = vec![];
    for n in 0..3 {
        a.submit_tx(transfer(&faucet, &user, MICRO_QTR, n)).expect("tx");
        let b = a.propose_block().expect("propose");
        blocks.push(b.clone());
        a.commit_block(b).expect("commit");
    }

    // Um node novo, mesmo gênesis, reaplicando os blocos gravados.
    let b = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::from_bytes(&node_key).unwrap());
    for blk in blocks {
        b.replay_block(blk).expect("replay");
    }
    let (sa, sb) = (a.state.read(), b.state.read());
    assert_eq!(sa.height, 3);
    assert_eq!(sb.height, sa.height);
    assert_eq!(sb.block_hash, sa.block_hash);
    assert_eq!(sb.account(&user).balance, 3 * MICRO_QTR);
}

#[test]
fn fee_is_charged_on_top_and_burned() {
    use qtrc_common::tx::TX_FEE;
    let faucet = HydraXKeypair::generate();
    let user = HydraXKeypair::generate();
    let genesis = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let engine = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::generate());
    let start = engine.state.read().account(&faucet.address()).balance;

    engine.submit_tx(transfer(&faucet, &user.address(), 50 * MICRO_QTR, 0)).expect("tx");
    engine.commit_block(engine.propose_block().expect("propose")).expect("commit");

    let st = engine.state.read();
    assert_eq!(TX_FEE, MICRO_QTR / 100, "0,01 QTR");
    assert_eq!(st.account(&user.address()).balance, 50 * MICRO_QTR, "destino recebe o valor cheio");
    assert_eq!(st.account(&faucet.address()).balance, start - 50 * MICRO_QTR - TX_FEE);
    assert_eq!(st.burned, TX_FEE, "taxa queimada");
    let total: u64 = st.accounts.values().map(|a| a.balance).sum();
    assert_eq!(total + st.burned, start, "supply + queimado = supply inicial");
}

#[test]
fn whole_balance_cannot_be_sent_without_the_fee() {
    use qtrc_common::tx::TX_FEE;
    let faucet = HydraXKeypair::generate();
    let user = HydraXKeypair::generate();
    let other = HydraXKeypair::generate().address();
    let genesis = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let engine = ConsensusEngine::new(genesis.initial_state(), HydraXKeypair::generate());

    engine.submit_tx(transfer(&faucet, &user.address(), 50 * MICRO_QTR, 0)).expect("abastece");
    engine.commit_block(engine.propose_block().expect("p")).expect("c");

    assert!(engine.submit_tx(transfer(&user, &other, 50 * MICRO_QTR, 0)).is_err(), "sem sobra para a taxa");
    engine.submit_tx(transfer(&user, &other, 50 * MICRO_QTR - TX_FEE, 0)).expect("valor menos a taxa");
    // A segunda pendente também precisa da própria taxa.
    assert!(engine.submit_tx(transfer(&user, &other, 1, 1)).is_err());
    engine.commit_block(engine.propose_block().expect("p2")).expect("c2");
    assert_eq!(engine.state.read().account(&user.address()).balance, 0);
}

#[test]
fn fee_activates_at_the_configured_height_and_replays_the_same() {
    use qtrc_common::tx::TX_FEE;
    let faucet = HydraXKeypair::generate();
    let user = HydraXKeypair::generate().address();
    let genesis = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex()));
    let node_key = HydraXKeypair::generate().to_bytes();

    // Chain que já existia antes da taxa: taxa só a partir do bloco 3.
    let mut st = genesis.initial_state();
    st.fee_from_height = 3;
    let a = ConsensusEngine::new(st.clone(), HydraXKeypair::from_bytes(&node_key).unwrap());
    let mut blocks = vec![];
    for n in 0..4 {
        a.submit_tx(transfer(&faucet, &user, MICRO_QTR, n)).expect("tx");
        let b = a.propose_block().expect("propose");
        blocks.push(b.clone());
        a.commit_block(b).expect("commit");
    }
    assert_eq!(a.state.read().burned, 2 * TX_FEE, "blocos 3 e 4 pagam, 1 e 2 não");

    let b = ConsensusEngine::new(st, HydraXKeypair::from_bytes(&node_key).unwrap());
    for blk in blocks {
        b.replay_block(blk).expect("replay");
    }
    let (sa, sb) = (a.state.read(), b.state.read());
    assert_eq!(sb.block_hash, sa.block_hash);
    assert_eq!(sb.burned, sa.burned);
    assert_eq!(
        sb.account(&faucet.address()).balance,
        sa.account(&faucet.address()).balance
    );
}
