//! Chain state — accounts, validator set and Sentinel vaults.

use crate::block::{Block, BlockHash};
use crate::sentinel::SentinelOp;
use crate::tx::{Transaction, TxError, CHAIN_ID, TX_FEE};

/// Largest `data` payload a transaction may carry (a recovery is ~37 KB).
pub const MAX_DATA_LEN: usize = 48 * 1024;
use qtrc_crypto::Address;
use qtrc_sentinel::{self as sn, Credit, Outcome, Policy, RecoveryFormat, SentinelError, Vault};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Per-account state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountState {
    /// Balance in micro-QTR. For an account with a Sentinel vault this
    /// mirrors the vault's balance, including funds reserved by pending
    /// transfers.
    pub balance: u64,
    /// Next expected nonce
    pub nonce:   u64,
}

/// Registered validator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub address: Address,
    pub stake:   u64,
}

/// Full chain state — everything needed to validate the next block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainState {
    pub height:     u64,
    pub block_hash: BlockHash,
    pub accounts:   HashMap<String, AccountState>, // key = address hex
    pub validators: Vec<ValidatorInfo>,
    /// First block height that charges `TX_FEE`. A chain created before
    /// fees existed keeps its old blocks valid by activating them later.
    #[serde(default = "fees_from_genesis")]
    pub fee_from_height: u64,
    /// Total micro-QTR burned in fees so far
    #[serde(default)]
    pub burned: u64,
    /// First block height that accepts Sentinel operations. A chain that
    /// already has blocks activates it at a later height, like fees.
    #[serde(default = "never")]
    pub sentinel_from_height: u64,
    /// First block height whose header must carry the state root.
    #[serde(default = "never")]
    pub state_root_from_height: u64,
    /// First block height whose header must carry the witness root.
    #[serde(default = "never")]
    pub witness_root_from_height: u64,
    /// First block height whose Sentinel recoveries are signed over the
    /// full recovery message instead of a 32-byte digest of it.
    #[serde(default = "never")]
    pub recovery_v3_from_height: u64,
    /// First block height decided by the validators voting (BFT): from it
    /// on, any validator may propose and every block needs a commit proof.
    #[serde(default = "never")]
    pub bft_from_height: u64,
    /// Sentinel vaults, key = address hex. Ordered for determinism.
    #[serde(default)]
    pub vaults: BTreeMap<String, Vault>,
    /// Keys of accounts and vaults touched since the last `take_touched`,
    /// so the state tree can be updated instead of rebuilt. Every change
    /// to `accounts` and `vaults` in block application goes through the
    /// journal, which is where these come from. Not part of the state.
    #[serde(skip)]
    pub touched: BTreeSet<String>,
}

fn fees_from_genesis() -> u64 {
    1
}

fn never() -> u64 {
    u64::MAX
}

/// Original values of everything a transaction touched, so a failed
/// transaction leaves the state exactly as it found it.
#[derive(Default)]
struct Journal {
    accounts: HashMap<String, Option<AccountState>>,
    vaults:   HashMap<String, Option<Vault>>,
    burned:   u64,
}

fn sentinel_err(e: SentinelError) -> TxError {
    TxError::Sentinel(e.to_string())
}

impl ChainState {
    pub fn account(&self, addr: &Address) -> AccountState {
        self.accounts
            .get(&addr.as_hex())
            .cloned()
            .unwrap_or_default()
    }

    /// The account's Sentinel vault, if it has one.
    pub fn vault(&self, addr: &Address) -> Option<&Vault> {
        self.vaults.get(&addr.as_hex())
    }

    /// Balance the account can spend right now (excludes funds reserved
    /// by pending Sentinel transfers).
    pub fn spendable(&self, addr: &Address) -> u64 {
        match self.vault(addr) {
            Some(v) => v.available(),
            None => self.account(addr).balance,
        }
    }

    /// Fee charged for a transaction included at block `height`.
    pub fn fee_at(&self, height: u64) -> u64 {
        if height >= self.fee_from_height { TX_FEE } else { 0 }
    }

    /// Whether the block at `height` must carry a state root.
    pub fn bft_active_at(&self, height: u64) -> bool {
        height >= self.bft_from_height
    }

    pub fn state_root_active_at(&self, height: u64) -> bool {
        height >= self.state_root_from_height
    }

    /// Whether the header at `height` must carry the witness root.
    pub fn witness_root_active_at(&self, height: u64) -> bool {
        height >= self.witness_root_from_height
    }

    /// Recovery message encoding verified at block `height`.
    pub fn recovery_format_at(&self, height: u64) -> RecoveryFormat {
        if height >= self.recovery_v3_from_height { RecoveryFormat::Full } else { RecoveryFormat::LegacyDigest }
    }

    /// Whether Sentinel operations are accepted at block `height`.
    pub fn sentinel_active_at(&self, height: u64) -> bool {
        height >= self.sentinel_from_height
    }

    /// Format checks shared by mempool admission and block application.
    /// Returns the decoded operation, or `None` for a plain transfer.
    pub fn parse_op(&self, tx: &Transaction, height: u64) -> Result<Option<SentinelOp>, TxError> {
        if tx.data.is_empty() {
            return Ok(None);
        }
        if !self.sentinel_active_at(height) {
            return Err(TxError::Sentinel(format!(
                "Sentinel is not active before block {}",
                self.sentinel_from_height
            )));
        }
        if tx.data.len() > MAX_DATA_LEN {
            return Err(TxError::Sentinel(format!("data larger than {MAX_DATA_LEN} bytes")));
        }
        let op = SentinelOp::decode(&tx.data).map_err(TxError::Sentinel)?;
        if tx.amount != 0 {
            return Err(TxError::Sentinel("operation must carry amount 0".into()));
        }
        if op.is_owner_op() && tx.to != tx.from {
            return Err(TxError::Sentinel("guardian operations must be sent to yourself".into()));
        }
        Ok(Some(op))
    }

    /// Whether the fee of `tx` is taken from the recovered amount instead of
    /// the sender's spendable balance: a guarded account submitting its own
    /// recovery, whose unlocked balance a thief may have drained.
    pub fn fee_from_recovery(op: &SentinelOp, tx: &Transaction) -> bool {
        matches!(op, SentinelOp::Recover { .. }) && tx.from == tx.to
    }

    /// Read-only check that a Sentinel operation would succeed on the
    /// current state. Used by mempool admission so operations that cannot
    /// apply are refused before they take a slot.
    pub fn check_op(&self, tx: &Transaction, op: &SentinelOp) -> Result<(), TxError> {
        let active = |a: &Address| -> Result<&Vault, TxError> {
            let v = self.vault(a).ok_or_else(no_vault)?;
            if v.is_recovered() { Err(sentinel_err(SentinelError::Recovered)) } else { Ok(v) }
        };
        match op {
            SentinelOp::SetGuardian { delay_blocks, allowance_per_window, .. } => {
                if self.vault(&tx.from).is_some() {
                    return Err(TxError::Sentinel("account already has a vault; use RotateGuardian".into()));
                }
                Policy::new(*delay_blocks, *allowance_per_window).map_err(sentinel_err)?;
            }
            SentinelOp::RotateGuardian { .. } => {
                active(&tx.from)?;
            }
            SentinelOp::Finalize { id } => {
                if !active(&tx.to)?.pending().iter().any(|p| p.id == *id) {
                    return Err(sentinel_err(SentinelError::NotFound));
                }
            }
            SentinelOp::Recover { cold_dest, salt, proof } => {
                sn::ensure_recovery_target(self.vault(cold_dest)).map_err(sentinel_err)?;
                active(&tx.to)?
                    .check_recovery_with(
                        self.recovery_format_at(self.height + 1),
                        CHAIN_ID.as_bytes(),
                        cold_dest,
                        salt,
                        proof.as_ref(),
                    )
                    .map_err(sentinel_err)?;
            }
        }
        Ok(())
    }

    /// Read-only check that a plain transfer from a guarded account would be
    /// accepted by its vault (amount, queue room, unlocked funds).
    pub fn check_guarded_transfer(&self, tx: &Transaction, fee: u64) -> Result<(), TxError> {
        let Some(v) = self.vault(&tx.from) else { return Ok(()) };
        let mut v = v.clone();
        v.charge_fee(fee).map_err(sentinel_err)?;
        v.transfer(self.height + 1, tx.to.clone(), tx.amount).map(|_| ()).map_err(sentinel_err)
    }

    /// Apply a single verified transaction as part of block `self.height + 1`.
    ///
    /// * A plain transfer from an unguarded account is all or nothing: on
    ///   error the state is unchanged and the transaction is left out of
    ///   the block, as before. From a guarded account it follows the
    ///   two-phase rule below.
    /// * A Sentinel operation that passes the format, nonce and fee checks
    ///   is always included: the fee and nonce are charged even if the
    ///   operation itself then fails (its effects are rolled back). That
    ///   makes failing operations cost the same as successful ones.
    pub fn apply_tx(&mut self, tx: &Transaction) -> Result<(), TxError> {
        let mut j = Journal { burned: self.burned, ..Journal::default() };
        let result = self.apply_tx_inner(tx, &mut j);
        // Marking a key that ends up unchanged only costs a re-hash.
        self.touched.extend(j.accounts.keys().cloned());
        self.touched.extend(j.vaults.keys().cloned());
        match result {
            Ok(()) => Ok(()),
            Err(e) => {
                self.rollback(j);
                Err(e)
            }
        }
    }

    /// Keys touched since the last call, clearing the set.
    pub fn take_touched(&mut self) -> BTreeSet<String> {
        std::mem::take(&mut self.touched)
    }

    fn rollback(&mut self, j: Journal) {
        for (k, orig) in j.accounts {
            match orig {
                Some(a) => { self.accounts.insert(k, a); }
                None => { self.accounts.remove(&k); }
            }
        }
        for (k, orig) in j.vaults {
            match orig {
                Some(v) => { self.vaults.insert(k, v); }
                None => { self.vaults.remove(&k); }
            }
        }
        self.burned = j.burned;
    }

    fn acct(&mut self, j: &mut Journal, key: &str) -> &mut AccountState {
        j.accounts.entry(key.to_string()).or_insert_with(|| self.accounts.get(key).cloned());
        self.accounts.entry(key.to_string()).or_default()
    }

    fn vault_mut(&mut self, j: &mut Journal, key: &str) -> Option<&mut Vault> {
        j.vaults.entry(key.to_string()).or_insert_with(|| self.vaults.get(key).cloned());
        self.vaults.get_mut(key)
    }

    /// Mirror a vault's balance into its account.
    fn sync(&mut self, j: &mut Journal, key: &str) {
        if let Some(bal) = self.vaults.get(key).map(Vault::balance) {
            self.acct(j, key).balance = bal;
        }
    }

    fn apply_tx_inner(&mut self, tx: &Transaction, j: &mut Journal) -> Result<(), TxError> {
        let height = self.height + 1;
        let fee = self.fee_at(height);
        let op = self.parse_op(tx, height)?;

        let from = tx.from.as_hex();
        let expected = self.account(&tx.from).nonce;
        if tx.nonce != expected {
            return Err(TxError::InvalidNonce { expected, got: tx.nonce });
        }

        let Some(op) = op else {
            self.debit_fee(j, &from, fee)?;
            self.acct(j, &from).nonce += 1;
            self.burned = self.burned.saturating_add(fee);
            if !self.vaults.contains_key(&from) {
                // Unguarded account: all or nothing, exactly as before
                // Sentinel existed, so old blocks replay unchanged.
                return self.plain_transfer(j, tx, height);
            }
            // Guarded account: a transfer the vault refuses (zero amount,
            // full queue, locked funds) is still included and pays.
            let mut j2 = Journal { burned: self.burned, ..Journal::default() };
            match self.plain_transfer(&mut j2, tx, height) {
                Ok(()) => merge(j, j2),
                Err(_) => self.rollback(j2),
            }
            return Ok(());
        };

        // Phase 1: nonce and fee. Failing here leaves the tx out of the block.
        let deferred = Self::fee_from_recovery(&op, tx);
        if deferred && self.vault(&tx.from).map_or(0, Vault::balance) < fee {
            return Err(TxError::InsufficientBalance { need: fee, have: self.vault(&tx.from).map_or(0, Vault::balance) });
        }
        if !deferred {
            self.debit_fee(j, &from, fee)?;
            self.burned = self.burned.saturating_add(fee);
        }
        self.acct(j, &from).nonce += 1;

        // Phase 2: the operation. Its effects are rolled back on failure,
        // but the tx stays in the block and keeps what phase 1 charged.
        let mut j2 = Journal { burned: self.burned, ..Journal::default() };
        match self.apply_op(tx, op, height, fee, deferred, &mut j2) {
            Ok(()) => {
                merge(j, j2);
                Ok(())
            }
            Err(e) => {
                self.rollback(j2);
                if deferred {
                    // The recovery did not happen, so there is no recovered
                    // amount to take the fee from: charge it normally, or
                    // leave the tx out if the account cannot pay.
                    self.debit_fee(j, &from, fee).map_err(|_| e)?;
                    self.burned = self.burned.saturating_add(fee);
                }
                Ok(())
            }
        }
    }

    fn apply_op(
        &mut self,
        tx: &Transaction,
        op: SentinelOp,
        height: u64,
        fee: u64,
        fee_from_recovered: bool,
        j: &mut Journal,
    ) -> Result<(), TxError> {
        let from = tx.from.as_hex();
        match op {
            SentinelOp::SetGuardian { commitment, delay_blocks, allowance_per_window } => {
                if self.vaults.contains_key(&from) {
                    return Err(TxError::Sentinel(
                        "account already has a vault; use RotateGuardian".into(),
                    ));
                }
                let policy = Policy::new(delay_blocks, allowance_per_window).map_err(sentinel_err)?;
                let balance = self.acct(j, &from).balance;
                j.vaults.entry(from.clone()).or_insert(None);
                self.vaults.insert(from, Vault::new(tx.from.clone(), balance, Some(commitment), policy));
                Ok(())
            }
            SentinelOp::RotateGuardian { commitment } => {
                let v = self.vault_mut(j, &from).ok_or_else(no_vault)?;
                v.request_rotation(height, commitment).map_err(sentinel_err)?;
                Ok(())
            }
            SentinelOp::Finalize { id } => {
                let target = tx.to.as_hex();
                let v = self.vault_mut(j, &target).ok_or_else(no_vault)?;
                let paid = v.finalize(height, id).map_err(sentinel_err)?;
                self.sync(j, &target);
                if let Some((dest, amount)) = paid {
                    self.credit(j, &dest, amount)?;
                }
                Ok(())
            }
            SentinelOp::Recover { cold_dest, salt, proof } => {
                sn::ensure_recovery_target(self.vaults.get(&cold_dest.as_hex())).map_err(sentinel_err)?;
                let target = tx.to.as_hex();
                let format = self.recovery_format_at(height);
                let v = self.vault_mut(j, &target).ok_or_else(no_vault)?;
                let (dest, mut amount) = v
                    .recover_with(format, CHAIN_ID.as_bytes(), &cold_dest, &salt, proof.as_ref())
                    .map_err(sentinel_err)?;
                self.sync(j, &target);
                if fee_from_recovered {
                    amount = amount.checked_sub(fee).ok_or(TxError::InsufficientBalance { need: fee, have: amount })?;
                    self.burned = self.burned.saturating_add(fee);
                }
                // Path compression: vaults that forwarded to the account just
                // recovered now forward straight to its destination, so
                // forwarding is always a single hop.
                let pointing: Vec<String> = self
                    .vaults
                    .iter()
                    .filter(|(_, v)| v.recovered_to() == Some(&tx.to))
                    .map(|(k, _)| k.clone())
                    .collect();
                for k in pointing {
                    if let Some(v) = self.vault_mut(j, &k) {
                        v.redirect_forward(dest.clone());
                    }
                }
                self.credit(j, &dest, amount)
            }
        }
    }

    /// Debit a fee, from the vault's available balance when there is one.
    fn debit_fee(&mut self, j: &mut Journal, key: &str, fee: u64) -> Result<(), TxError> {
        if let Some(v) = self.vault_mut(j, key) {
            let have = v.available();
            v.charge_fee(fee).map_err(|e| match e {
                SentinelError::InsufficientFunds => TxError::InsufficientBalance { need: fee, have },
                other => sentinel_err(other),
            })?;
            self.sync(j, key);
            return Ok(());
        }
        let a = self.acct(j, key);
        if a.balance < fee {
            return Err(TxError::InsufficientBalance { need: fee, have: a.balance });
        }
        a.balance -= fee;
        Ok(())
    }

    fn plain_transfer(&mut self, j: &mut Journal, tx: &Transaction, height: u64) -> Result<(), TxError> {
        let from = tx.from.as_hex();
        if let Some(v) = self.vault_mut(j, &from) {
            let have = v.available();
            let outcome = v.transfer(height, tx.to.clone(), tx.amount).map_err(|e| match e {
                SentinelError::InsufficientFunds => TxError::InsufficientBalance { need: tx.amount, have },
                other => sentinel_err(other),
            })?;
            self.sync(j, &from);
            if let Outcome::Settled { to, amount } = outcome {
                self.credit(j, &to, amount)?;
            }
            return Ok(());
        }
        let a = self.acct(j, &from);
        if a.balance < tx.amount {
            return Err(TxError::InsufficientBalance { need: tx.amount, have: a.balance });
        }
        a.balance -= tx.amount;
        self.credit(j, &tx.to, tx.amount)
    }

    /// Credit an account, following Sentinel forwarding to the final holder.
    fn credit(&mut self, j: &mut Journal, to: &Address, amount: u64) -> Result<(), TxError> {
        let vaults = &self.vaults;
        let target = sn::resolve_forward(to, |a| vaults.get(&a.as_hex()).and_then(|v| v.recovered_to().cloned()))
            .map_err(sentinel_err)?;
        let key = target.as_hex();
        if let Some(v) = self.vault_mut(j, &key) {
            match v.credit(amount).map_err(sentinel_err)? {
                Credit::Held => {}
                Credit::Forward(_) => {
                    return Err(TxError::Sentinel("forwarding did not resolve".into()));
                }
            }
            self.sync(j, &key);
            return Ok(());
        }
        let a = self.acct(j, &key);
        a.balance = a.balance.checked_add(amount).ok_or_else(|| TxError::Sentinel("balance overflow".into()))?;
        Ok(())
    }

    /// Apply a full block to produce the next state.
    pub fn apply_block(&mut self, block: &Block) -> Result<(), TxError> {
        for tx in &block.transactions {
            self.apply_tx(tx)?;
        }
        self.height     = block.header.height;
        self.block_hash = block.hash();
        Ok(())
    }
}

/// Merge a successful phase-2 journal into the outer one, keeping the
/// outer (older) original for keys both touched.
fn merge(outer: &mut Journal, inner: Journal) {
    for (k, v) in inner.accounts {
        outer.accounts.entry(k).or_insert(v);
    }
    for (k, v) in inner.vaults {
        outer.vaults.entry(k).or_insert(v);
    }
}

fn no_vault() -> TxError {
    TxError::Sentinel("account has no Sentinel vault".into())
}
