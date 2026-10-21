//! Chain state — accounts, validator set and Sentinel vaults.

use crate::block::{Block, BlockHash};
use crate::sentinel::SentinelOp;
use crate::tx::{Transaction, TxError, CHAIN_ID, TX_FEE};
use qtrc_crypto::Address;
use qtrc_sentinel::{self as sn, Credit, Outcome, Policy, SentinelError, Vault};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

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
    /// Sentinel vaults, key = address hex. Ordered for determinism.
    #[serde(default)]
    pub vaults: BTreeMap<String, Vault>,
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

    /// Whether Sentinel operations are accepted at block `height`.
    pub fn sentinel_active_at(&self, height: u64) -> bool {
        height >= self.sentinel_from_height
    }

    /// Apply a single verified transaction as part of block `self.height + 1`.
    /// All or nothing: on error the state is unchanged.
    pub fn apply_tx(&mut self, tx: &Transaction) -> Result<(), TxError> {
        let mut j = Journal { burned: self.burned, ..Journal::default() };
        let result = self.apply_tx_inner(tx, &mut j);
        if result.is_err() {
            self.rollback(j);
        }
        result
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

        let op = if tx.data.is_empty() {
            None
        } else {
            if !self.sentinel_active_at(height) {
                return Err(TxError::Sentinel(format!(
                    "Sentinel is not active before block {}",
                    self.sentinel_from_height
                )));
            }
            let op = SentinelOp::decode(&tx.data).map_err(TxError::Sentinel)?;
            if tx.amount != 0 {
                return Err(TxError::Sentinel("operation must carry amount 0".into()));
            }
            if op.is_owner_op() && tx.to != tx.from {
                return Err(TxError::Sentinel("guardian operations must be sent to yourself".into()));
            }
            Some(op)
        };

        let from = tx.from.as_hex();
        let expected = self.account(&tx.from).nonce;
        if tx.nonce != expected {
            return Err(TxError::InvalidNonce { expected, got: tx.nonce });
        }

        self.debit_fee(j, &from, fee)?;
        self.acct(j, &from).nonce += 1;
        self.burned = self.burned.saturating_add(fee);

        match op {
            None => self.plain_transfer(j, tx, height),
            Some(SentinelOp::SetGuardian { commitment, delay_blocks, allowance_per_window }) => {
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
            Some(SentinelOp::RotateGuardian { commitment }) => {
                let v = self.vault_mut(j, &from).ok_or_else(no_vault)?;
                v.request_rotation(height, commitment).map_err(sentinel_err)?;
                Ok(())
            }
            Some(SentinelOp::Finalize { id }) => {
                let target = tx.to.as_hex();
                let v = self.vault_mut(j, &target).ok_or_else(no_vault)?;
                let paid = v.finalize(height, id).map_err(sentinel_err)?;
                self.sync(j, &target);
                if let Some((dest, amount)) = paid {
                    self.credit(j, &dest, amount)?;
                }
                Ok(())
            }
            Some(SentinelOp::Recover { cold_dest, salt, proof }) => {
                sn::ensure_recovery_target(self.vaults.get(&cold_dest.as_hex())).map_err(sentinel_err)?;
                let target = tx.to.as_hex();
                let v = self.vault_mut(j, &target).ok_or_else(no_vault)?;
                let (dest, amount) = v
                    .recover(CHAIN_ID.as_bytes(), &cold_dest, &salt, proof.as_ref())
                    .map_err(sentinel_err)?;
                self.sync(j, &target);
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

fn no_vault() -> TxError {
    TxError::Sentinel("account has no Sentinel vault".into())
}
