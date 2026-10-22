//! Pending transactions: the queue for the next block plus the ones taken
//! out for the block being built ("in flight"), with indexes so admission
//! checks cost the same however full the queue is.
//!
//! Limits are by count and by bytes. Sentinel recoveries get room of their
//! own on top of both, and go first when a block is built: a thief holding
//! the main key must not be able to delay a recovery, by flooding the
//! queue, until a time-locked transfer unlocks. Finalize gets no such room
//! on purpose, since the thief is the one who wants to finalize.

use qtrc_common::tx::{Transaction, TxHash};
use qtrc_crypto::Address;
use std::collections::{HashMap, HashSet};

/// Most ordinary transactions waiting, across all senders.
pub const MAX_MEMPOOL: usize = 5_000;
/// Most bytes of ordinary transactions waiting. A HYDRA-X transaction is
/// about 38 KB before its data, so this is roughly 1,700 plain transfers,
/// several blocks' worth, while keeping the queue (and hx-mempool's copy of
/// the signatures) far below the droplet's memory.
pub const MAX_MEMPOOL_BYTES: usize = 64 * 1024 * 1024;
/// Recoveries admitted on top of the ordinary limits.
pub const RECOVERY_RESERVE: usize = 64;

/// Bytes a transaction holds in memory: the HYDRA-X signature (ML-DSA-87
/// and SLH-DSA-SHA2-256s signatures and public keys) plus its data.
pub fn tx_bytes(tx: &Transaction) -> usize {
    const SIG_AND_KEYS: usize = 4_627 + 2_592 + 29_792 + 64;
    const FIXED: usize = 256;
    SIG_AND_KEYS + FIXED + tx.data.len()
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub tx: Transaction,
    pub hash: TxHash,
    pub recover: bool,
    bytes: usize,
}

impl Entry {
    pub fn new(tx: Transaction, recover: bool) -> Self {
        let hash = tx.hash();
        Self::with_hash(tx, hash, recover)
    }

    pub fn with_hash(tx: Transaction, hash: TxHash, recover: bool) -> Self {
        let bytes = tx_bytes(&tx);
        Entry { tx, hash, recover, bytes }
    }
}

#[derive(Debug)]
pub enum Full {
    Count,
    Bytes,
    RecoveryReserve,
}

#[derive(Default, Debug)]
pub struct Mempool {
    queue: Vec<Entry>,
    inflight: Vec<Entry>,
    /// Hashes in the queue or in flight.
    hashes: HashSet<TxHash>,
    /// (count, total amount) per sender, queue and in flight.
    senders: HashMap<Address, (usize, u64)>,
    ordinary: usize,
    ordinary_bytes: usize,
    recovers: usize,
}

impl Mempool {
    /// Transactions waiting for a block (not counting the one being built).
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn contains(&self, hash: &TxHash) -> bool {
        self.hashes.contains(hash)
    }

    /// (count, total amount) of `addr`'s transactions queued or in flight.
    pub fn pending_for(&self, addr: &Address) -> (usize, u64) {
        self.senders.get(addr).copied().unwrap_or((0, 0))
    }

    /// Room for this transaction? Checked before its signature is verified.
    pub fn has_room(&self, tx: &Transaction, recover: bool) -> Result<(), Full> {
        if recover {
            return if self.recovers < RECOVERY_RESERVE { Ok(()) } else { Err(Full::RecoveryReserve) };
        }
        if self.ordinary >= MAX_MEMPOOL {
            return Err(Full::Count);
        }
        if self.ordinary_bytes + tx_bytes(tx) > MAX_MEMPOOL_BYTES {
            return Err(Full::Bytes);
        }
        Ok(())
    }

    pub fn push(&mut self, e: Entry) {
        if !self.hashes.insert(e.hash.clone()) {
            return;
        }
        self.track(&e, true);
        self.queue.push(e);
    }

    fn track(&mut self, e: &Entry, add: bool) {
        let s = self.senders.entry(e.tx.from.clone()).or_insert((0, 0));
        if add {
            s.0 += 1;
            s.1 = s.1.saturating_add(e.tx.amount);
        } else {
            s.0 -= 1;
            s.1 = s.1.saturating_sub(e.tx.amount);
        }
        if s.0 == 0 {
            self.senders.remove(&e.tx.from);
        }
        match (e.recover, add) {
            (true, true) => self.recovers += 1,
            (true, false) => self.recovers -= 1,
            (false, true) => {
                self.ordinary += 1;
                self.ordinary_bytes += e.bytes;
            }
            (false, false) => {
                self.ordinary -= 1;
                self.ordinary_bytes -= e.bytes;
            }
        }
    }

    pub fn inflight_is_empty(&self) -> bool {
        self.inflight.is_empty()
    }

    pub fn inflight_hashes(&self) -> Vec<TxHash> {
        self.inflight.iter().map(|e| e.hash.clone()).collect()
    }

    /// Move up to `max` transactions to in flight for a new block. Senders
    /// with a recovery waiting go first, all their transactions in nonce
    /// order; then everyone else in arrival order.
    pub fn take_for_block(&mut self, max: usize) -> Vec<Entry> {
        let urgent: HashSet<Address> =
            self.queue.iter().filter(|e| e.recover).map(|e| e.tx.from.clone()).collect();
        let (mut first, rest): (Vec<Entry>, Vec<Entry>) =
            std::mem::take(&mut self.queue).into_iter().partition(|e| urgent.contains(&e.tx.from));
        first.extend(rest);
        let keep = first.split_off(first.len().min(max));
        self.queue = keep;
        self.inflight = first.clone();
        first
    }

    /// Drop in-flight transactions that turned out invalid.
    pub fn drop_inflight(&mut self, hashes: &HashSet<TxHash>) {
        let (gone, kept): (Vec<Entry>, Vec<Entry>) =
            std::mem::take(&mut self.inflight).into_iter().partition(|e| hashes.contains(&e.hash));
        self.inflight = kept;
        for e in gone {
            self.hashes.remove(&e.hash);
            self.track(&e, false);
        }
    }

    /// Put in-flight transactions held for a later block back at the front.
    pub fn hold(&mut self, hashes: &HashSet<TxHash>) {
        let (held, kept): (Vec<Entry>, Vec<Entry>) =
            std::mem::take(&mut self.inflight).into_iter().partition(|e| hashes.contains(&e.hash));
        self.inflight = kept;
        let rest = std::mem::take(&mut self.queue);
        self.queue = held;
        self.queue.extend(rest);
    }

    /// End the in-flight phase. On failure the transactions go back to the
    /// front of the queue; on success they are done and their hashes are
    /// returned so the caller can forget their signatures.
    pub fn finish_inflight(&mut self, committed: bool) -> Vec<TxHash> {
        let txs = std::mem::take(&mut self.inflight);
        if !committed {
            let rest = std::mem::take(&mut self.queue);
            self.queue = txs;
            self.queue.extend(rest);
            return Vec::new();
        }
        txs.into_iter()
            .map(|e| {
                self.hashes.remove(&e.hash);
                self.track(&e, false);
                e.hash
            })
            .collect()
    }

    /// Forget every queued and in-flight transaction. Tests only.
    #[doc(hidden)]
    pub fn clear(&mut self) {
        *self = Mempool::default();
    }

    /// Bulk insert without admission checks. Tests and benchmarks only.
    #[doc(hidden)]
    pub fn force_fill(&mut self, entries: impl IntoIterator<Item = Entry>) {
        for e in entries {
            self.hashes.insert(e.hash.clone());
            self.track(&e, true);
            self.queue.push(e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qtrc_crypto::HydraXKeypair;

    fn tx(kp: &HydraXKeypair, nonce: u64, amount: u64) -> Transaction {
        let from = kp.address();
        let to = HydraXKeypair::generate().address();
        let p = Transaction::signing_payload(&from, &to, amount, nonce);
        Transaction { from, to, amount, nonce, timestamp: 0, signature: kp.sign(&p), data: vec![] }
    }

    #[test]
    fn indexes_follow_every_move() {
        let a = HydraXKeypair::generate();
        let b = HydraXKeypair::generate();
        let mut m = Mempool::default();
        let (a0, a1, b0) = (tx(&a, 0, 5), tx(&a, 1, 7), tx(&b, 0, 1));
        m.push(Entry::new(a0.clone(), false));
        m.push(Entry::new(a1.clone(), false));
        m.push(Entry::new(b0.clone(), true));
        m.push(Entry::new(a0.clone(), false)); // duplicate ignored
        assert_eq!(m.len(), 3);
        assert_eq!(m.pending_for(&a.address()), (2, 12));

        // b has a recovery: b goes first.
        let taken = m.take_for_block(2);
        assert_eq!(taken[0].hash, b0.hash());
        assert_eq!(taken[1].hash, a0.hash());
        assert_eq!(m.len(), 1);
        assert!(m.contains(&a0.hash()), "in flight still counts as pending");
        assert_eq!(m.pending_for(&a.address()), (2, 12));

        m.drop_inflight(&[a0.hash()].into_iter().collect());
        assert!(!m.contains(&a0.hash()));
        assert_eq!(m.pending_for(&a.address()), (1, 7));

        let done = m.finish_inflight(true);
        assert_eq!(done, vec![b0.hash()]);
        assert_eq!(m.pending_for(&b.address()), (0, 0));
        assert_eq!((m.ordinary, m.recovers), (1, 0));

        let again = m.take_for_block(10);
        assert_eq!(again.len(), 1);
        assert!(m.finish_inflight(false).is_empty());
        assert_eq!(m.len(), 1, "failed block puts txs back");
    }

    #[test]
    fn recoveries_have_room_when_ordinary_txs_fill_the_queue() {
        let a = HydraXKeypair::generate();
        let t = tx(&a, 0, 1);
        let mut m = Mempool::default();
        let filler: Vec<Entry> = (0..MAX_MEMPOOL)
            .map(|i| {
                let mut e = Entry::new(t.clone(), false);
                e.hash = TxHash([(i % 251) as u8; 32]);
                e.hash.0[1..9].copy_from_slice(&(i as u64).to_be_bytes());
                e
            })
            .collect();
        m.force_fill(filler);
        assert!(matches!(m.has_room(&t, false), Err(Full::Count) | Err(Full::Bytes)));
        assert!(m.has_room(&t, true).is_ok());
    }

    #[test]
    fn byte_limit_counts_data() {
        let a = HydraXKeypair::generate();
        let mut big = tx(&a, 0, 1);
        big.data = vec![0u8; 48 * 1024];
        let n = MAX_MEMPOOL_BYTES / tx_bytes(&big);
        let mut m = Mempool::default();
        m.force_fill((0..n).map(|i| {
            let mut e = Entry::new(big.clone(), false);
            e.hash.0[..8].copy_from_slice(&(i as u64).to_be_bytes());
            e
        }));
        assert!(n < MAX_MEMPOOL);
        assert!(matches!(m.has_room(&big, false), Err(Full::Bytes)));
    }
}
