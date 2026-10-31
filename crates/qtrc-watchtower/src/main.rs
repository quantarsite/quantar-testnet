//! # qtrc-watchtower
//!
//! Watches Sentinel-guarded accounts through the node RPC and submits a
//! recovery the moment something hostile shows up (a large transfer to an
//! unknown address, a theft split into parts, a queue flood, a guardian
//! rotation nobody announced).
//!
//! The decision is the audited `qtrc_sentinel::watchtower::tick`, run on a
//! copy of the on-chain vault. If it says "recover", the same recovery is
//! sent to the chain.
//!
//! Trust model: the watchtower holds no key of the accounts it protects.
//! It holds each account's recovery kit (the commitment opening plus a
//! recovery signature made in advance) and a small wallet of its own that
//! pays the recovery fees. A compromised watchtower can force a recovery,
//! which sends everything to the owner's own cold address; it cannot send
//! funds anywhere else.
//!
//! The config file is read again on every cycle, so accounts and kits can
//! be added or replaced without a restart.
//!
//! ```json
//! {
//!   "rpc": "http://127.0.0.1:8545",
//!   "payer_key": "/etc/quantar/watchtower.key",
//!   "poll_secs": 5,
//!   "webhook": "https://discord.com/api/webhooks/...",
//!   "accounts": [
//!     { "label": "treasury",
//!       "kit": "/etc/quantar/kits/treasury.kit.json",
//!       "recover_at": "100",
//!       "trusted": ["<64-hex address>"] }
//!   ]
//! }
//! ```

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use qtrc_common::genesis::MICRO_QTR;
use qtrc_common::sentinel::SentinelOp;
use qtrc_common::tx::{Transaction, CHAIN_ID};
use qtrc_crypto::{Address, HydraXKeypair, HydraXSignature};
use qtrc_sentinel::watchtower::{tick_with, Action, Finding, RecoveryKit, Severity, Subject, WatchPolicy};
use qtrc_sentinel::{Policy, RecoveryFormat, Vault};
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "qtrc-watchtower", version, about = "Sentinel watchtower: recovers guarded accounts automatically")]
struct Cli {
    /// Config file (JSON)
    #[arg(long, env = "QTR_WATCHTOWER_CONFIG", default_value = "/etc/quantar/watchtower.json")]
    config: PathBuf,
    /// Run one cycle and exit (for tests and cron)
    #[arg(long)]
    once: bool,
}

// ---------------------------------------------------------------------------
// Config and kit files
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug, Clone)]
struct Config {
    rpc: String,
    /// Wallet that pays recovery fees (needs a little QTR)
    payer_key: PathBuf,
    #[serde(default = "default_poll")]
    poll_secs: u64,
    /// Optional URL that receives a JSON POST for every alert
    /// (`{"text": ..., "content": ...}`: works with Slack and Discord)
    #[serde(default)]
    webhook: Option<String>,
    accounts: Vec<WatchEntry>,
}

fn default_poll() -> u64 {
    5
}

#[derive(Deserialize, Debug, Clone)]
struct WatchEntry {
    #[serde(default)]
    label: Option<String>,
    /// Kit written by `qtrc-wallet guardian setup|rotate`
    kit: PathBuf,
    /// QTR in flight to unknown addresses that triggers a recovery
    recover_at: String,
    /// Addresses that never count as hostile (own wallets, exchange)
    #[serde(default)]
    trusted: Vec<String>,
    /// Commitment (64 hex) of a rotation the owner announced
    #[serde(default)]
    expected_rotation: Option<String>,
    /// Loosening policy change the owner announced (`qtrc-wallet guardian
    /// policy`). Any other queued policy change triggers a recovery.
    #[serde(default)]
    expected_policy: Option<ExpectedPolicy>,
}

/// Policy as written in the config: allowance in QTR, like `recover_at`.
#[derive(Deserialize, Debug, Clone)]
struct ExpectedPolicy {
    delay_blocks: u64,
    allowance: String,
}

/// Same format `qtrc-wallet` writes.
#[derive(Deserialize, Debug, Clone)]
struct KitFile {
    chain_id: String,
    account: String,
    cold_dest: String,
    salt: String,
    epoch: u64,
    proof: HydraXSignature,
}

/// Everything needed to judge and protect one account.
struct Watched {
    name: String,
    account: Address,
    policy: WatchPolicy,
    kit: RecoveryKit<HydraXSignature>,
    kit_epoch: u64,
}

fn load_config(path: &Path) -> Result<Config> {
    let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let cfg: Config = serde_json::from_slice(&bytes).with_context(|| format!("invalid config {}", path.display()))?;
    if cfg.poll_secs == 0 {
        bail!("poll_secs must be at least 1");
    }
    Ok(cfg)
}

fn load_watched(entry: &WatchEntry) -> Result<Watched> {
    let kit: KitFile = serde_json::from_slice(
        &std::fs::read(&entry.kit).with_context(|| format!("cannot read kit {}", entry.kit.display()))?,
    )
    .with_context(|| format!("invalid kit {}", entry.kit.display()))?;
    if kit.chain_id != CHAIN_ID {
        bail!("kit {} is for {}, this watchtower runs {CHAIN_ID}", entry.kit.display(), kit.chain_id);
    }
    let account = parse_address(&kit.account)?;
    let cold_dest = parse_address(&kit.cold_dest)?;
    let salt: [u8; 32] = hex::decode(&kit.salt)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("invalid salt in kit {}", entry.kit.display()))?;
    let trusted = entry.trusted.iter().map(|a| parse_address(a)).collect::<Result<Vec<_>>>()?;
    let expected_rotation = match &entry.expected_rotation {
        Some(h) => Some(
            hex::decode(h)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| anyhow!("expected_rotation must be 64 hex characters"))?,
        ),
        None => None,
    };
    let expected_policy = match &entry.expected_policy {
        Some(p) => Some(
            Policy::new(p.delay_blocks, parse_qtr(&p.allowance)?)
                .map_err(|e| anyhow!("expected_policy: {e}"))?,
        ),
        None => None,
    };
    Ok(Watched {
        name: entry.label.clone().unwrap_or_else(|| short(&account)),
        account,
        policy: WatchPolicy { trusted, recover_at: parse_qtr(&entry.recover_at)?, expected_rotation, expected_policy },
        kit: RecoveryKit { cold_dest, salt, proof: kit.proof },
        kit_epoch: kit.epoch,
    })
}

// ---------------------------------------------------------------------------
// Decision (pure: tested below)
// ---------------------------------------------------------------------------

/// What the watchtower should do about one vault right now. Runs the
/// audited `tick` on a copy, so nothing here can diverge from it.
fn decide(vault: &Vault, w: &Watched, height: u64, format: RecoveryFormat) -> Action {
    let mut copy = vault.clone();
    tick_with(format, &mut copy, &w.policy, &w.kit, CHAIN_ID.as_bytes(), height)
}

/// Stable text for a set of findings, so the same situation alerts once.
fn alert_key(kind: &str, findings: &[Finding]) -> String {
    let mut k = kind.to_string();
    for f in findings {
        let s = match &f.subject {
            Subject::Pending(id) => format!("p{id}"),
            Subject::Settled { height, amount, .. } => format!("s{height}:{amount}"),
        };
        k.push_str(&format!("|{s}:{:?}", f.severity));
    }
    k
}

fn describe(f: &Finding) -> String {
    match &f.subject {
        Subject::Pending(id) => format!("{} (queued #{id}, {} blocks left)", f.reason, f.blocks_left),
        Subject::Settled { amount, to, .. } => {
            format!("{}: {} QTR to {}", f.reason, format_qtr(*amount), short(to))
        }
    }
}

// ---------------------------------------------------------------------------
// Node RPC
// ---------------------------------------------------------------------------

struct Rpc {
    http: Client,
    base: String,
}

impl Rpc {
    fn get(&self, path: &str) -> Result<(u16, Value)> {
        let resp = self.http.get(format!("{}{path}", self.base)).send().with_context(|| format!("node unreachable ({path})"))?;
        let code = resp.status().as_u16();
        Ok((code, resp.json().unwrap_or(Value::Null)))
    }

    /// Current height, and the recovery message encoding the node verifies
    /// in its next block (legacy digest on a node from before v3).
    fn height(&self) -> Result<(u64, RecoveryFormat)> {
        let (code, s) = self.get("/status")?;
        if code != 200 {
            bail!("status returned {code}");
        }
        if s["chain_id"].as_str() != Some(CHAIN_ID) {
            bail!("node runs {}, watchtower runs {CHAIN_ID}", s["chain_id"]);
        }
        if s["sentinel_from_height"].is_null() {
            bail!("node does not support Sentinel");
        }
        let height = s["height"].as_u64().ok_or_else(|| anyhow!("status has no height"))?;
        let format = match s["recovery_v3_from_height"].as_u64() {
            Some(v3) if height + 1 >= v3 => RecoveryFormat::Full,
            _ => RecoveryFormat::LegacyDigest,
        };
        Ok((height, format))
    }

    /// The account's vault, or None if it has no guardian.
    fn vault(&self, a: &Address) -> Result<Option<Vault>> {
        let (code, body) = self.get(&format!("/vault/{}", a.as_hex()))?;
        match code {
            404 => Ok(None),
            200 => {
                let v: Vault = serde_json::from_value(body["vault"].clone()).context("unexpected vault format")?;
                v.validate().map_err(|e| anyhow!("node returned an inconsistent vault: {e}"))?;
                Ok(Some(v))
            }
            other => bail!("vault query returned {other}"),
        }
    }

    fn account(&self, a: &Address) -> Result<(u64, u64)> {
        let (code, body) = self.get(&format!("/account/{}", a.as_hex()))?;
        if code != 200 {
            bail!("account query returned {code}");
        }
        let bal = body["balance"].as_u64().unwrap_or(0);
        let nonce = body["next_nonce"].as_u64().or_else(|| body["nonce"].as_u64()).ok_or_else(|| anyhow!("no nonce"))?;
        Ok((bal, nonce))
    }

    fn submit_recovery(&self, payer: &HydraXKeypair, w: &Watched) -> Result<String> {
        let from = payer.address();
        let (balance, nonce) = self.account(&from)?;
        if balance == 0 {
            bail!("watchtower wallet {} has no QTR for the recovery fee", from.as_hex());
        }
        let op = SentinelOp::Recover {
            cold_dest: w.kit.cold_dest.clone(),
            salt: w.kit.salt,
            proof: Box::new(w.kit.proof.clone()),
        };
        let data = op.encode();
        let payload = Transaction::signing_payload_with_data(&from, &w.account, 0, nonce, &data);
        let tx = Transaction {
            from,
            to: w.account.clone(),
            amount: 0,
            nonce,
            timestamp: chrono::Utc::now().timestamp(),
            signature: payer.sign(&payload),
            data,
        };
        tx.verify().map_err(|e| anyhow!("local signature check failed: {e}"))?;
        let resp = self.http.post(format!("{}/tx", self.base)).json(&tx).send().context("node unreachable")?;
        let ok = resp.status().is_success();
        let body: Value = resp.json().unwrap_or_default();
        if !ok {
            bail!("node rejected the recovery: {}", body["error"].as_str().unwrap_or("unknown error"));
        }
        Ok(body["tx_hash"].as_str().unwrap_or("?").to_string())
    }
}

// ---------------------------------------------------------------------------
// Service loop
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Memory {
    /// Last alert sent per account (only changes are reported)
    last_alert: HashMap<String, String>,
    /// Recovery submitted per account: height it was sent at
    submitted: HashMap<String, u64>,
}

/// Blocks to wait for a submitted recovery before trying again.
const RESUBMIT_AFTER: u64 = 3;

struct Service {
    rpc: Rpc,
    payer: HydraXKeypair,
    webhook: Option<String>,
    mem: Memory,
}

impl Service {
    fn alert(&mut self, account: &str, key: String, text: String, loud: bool) {
        if self.mem.last_alert.get(account) == Some(&key) {
            return;
        }
        self.mem.last_alert.insert(account.to_string(), key);
        if loud { error!("{text}") } else { warn!("{text}") }
        if let Some(url) = &self.webhook {
            let body = serde_json::json!({ "text": text, "content": text });
            if let Err(e) = self.rpc.http.post(url).json(&body).send() {
                warn!("webhook failed: {e}");
            }
        }
    }

    fn clear(&mut self, account: &str) {
        self.mem.last_alert.remove(account);
    }

    fn cycle(&mut self, cfg: &Config) -> Result<()> {
        let (height, recovery) = self.rpc.height()?;
        for entry in &cfg.accounts {
            let w = match load_watched(entry) {
                Ok(w) => w,
                Err(e) => {
                    let k = entry.kit.display().to_string();
                    self.alert(&k, format!("bad:{e}"), format!("⚠️ watchtower: cannot load {k}: {e:#}"), true);
                    continue;
                }
            };
            if let Err(e) = self.check(&w, height, recovery) {
                warn!(account = %w.name, "check failed: {e:#}");
            }
        }
        Ok(())
    }

    fn check(&mut self, w: &Watched, height: u64, recovery: RecoveryFormat) -> Result<()> {
        let key = w.account.as_hex();
        let Some(vault) = self.rpc.vault(&w.account)? else {
            self.alert(&key, "noguardian".into(), format!("⚠️ {}: account has no guardian; nothing to protect", w.name), false);
            return Ok(());
        };
        if let Some(to) = vault.recovered_to() {
            if self.mem.submitted.remove(&key).is_some() {
                info!(account = %w.name, "recovery confirmed on chain");
            }
            self.alert(&key, "recovered".into(), format!("✅ {}: recovered, everything forwards to {}", w.name, short(to)), false);
            return Ok(());
        }
        match decide(&vault, w, height, recovery) {
            Action::Idle => self.clear(&key),
            Action::NoGuardian => {
                self.alert(&key, "noguardian".into(), format!("⚠️ {}: account has no guardian", w.name), false);
            }
            Action::Notify(findings) => {
                let lines: Vec<String> = findings.iter().map(describe).collect();
                self.alert(
                    &key,
                    alert_key("notify", &findings),
                    format!("👀 {}: suspicious activity below the recovery threshold:\n{}", w.name, lines.join("\n")),
                    false,
                );
            }
            Action::KitStale(findings) => {
                let hostile = findings.iter().any(|f| f.severity == Severity::Recover);
                let why = if vault.epoch() != w.kit_epoch {
                    format!("kit is for epoch {}, vault is at {}", w.kit_epoch, vault.epoch())
                } else {
                    "kit does not open the vault's commitment".to_string()
                };
                let text = if hostile {
                    format!(
                        "🚨 {}: ATTACK IN PROGRESS and the kit cannot recover ({why}). Recover manually now with the recovery key: qtrc-wallet recover {} --kit <kit> --recovery-key <key>",
                        w.name,
                        w.account.as_hex()
                    )
                } else {
                    format!("⚠️ {}: watchtower disarmed, {why}. Send it the new kit.", w.name)
                };
                self.alert(&key, alert_key("stale", &findings), text, hostile);
            }
            Action::Recovered { cause, .. } => {
                if let Some(at) = self.mem.submitted.get(&key) {
                    if height < at + RESUBMIT_AFTER {
                        return Ok(()); // already sent, waiting for a block
                    }
                    warn!(account = %w.name, "recovery not confirmed after {RESUBMIT_AFTER} blocks, sending again");
                }
                match self.rpc.submit_recovery(&self.payer, w) {
                    Ok(tx) => {
                        self.mem.submitted.insert(key.clone(), height);
                        self.alert(
                            &key,
                            format!("recovering:{height}"),
                            format!(
                                "🛡️ {}: {}. Recovery submitted, everything goes to {}. tx {tx}",
                                w.name,
                                describe(&cause),
                                short(&w.kit.cold_dest)
                            ),
                            true,
                        );
                    }
                    Err(e) => {
                        self.alert(
                            &key,
                            format!("submitfail:{e}"),
                            format!("🚨 {}: {} but the recovery could not be sent: {e:#}", w.name, describe(&cause)),
                            true,
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

fn main() {
    tracing_subscriber::fmt().with_target(false).init();
    if let Err(e) = run(Cli::parse()) {
        error!("{e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let mut cfg = load_config(&cli.config)?;
    let payer = load_key(&cfg.payer_key)?;
    let http = Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("qtrc-watchtower/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let mut svc = Service {
        rpc: Rpc { http, base: cfg.rpc.trim_end_matches('/').to_string() },
        payer,
        webhook: cfg.webhook.clone(),
        mem: Memory::default(),
    };
    info!(
        accounts = cfg.accounts.len(),
        payer = %svc.payer.address().as_hex(),
        "watchtower started"
    );
    loop {
        if let Err(e) = svc.cycle(&cfg) {
            warn!("cycle failed: {e:#}");
        }
        if cli.once {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(cfg.poll_secs));
        // Pick up new accounts or kits without a restart.
        match load_config(&cli.config) {
            Ok(new) => {
                svc.webhook = new.webhook.clone();
                cfg = new;
            }
            Err(e) => warn!("keeping previous config: {e:#}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn load_key(path: &Path) -> Result<HydraXKeypair> {
    let bytes = zeroize::Zeroizing::new(std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?);
    HydraXKeypair::from_bytes(&bytes).map_err(|e| anyhow!("invalid key file {}: {e}", path.display()))
}

fn parse_address(s: &str) -> Result<Address> {
    let a = s.trim();
    if a.len() != 64 || !a.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid address {a}: expected 64 hex characters");
    }
    Address::from_hex(&a.to_lowercase()).map_err(|e| anyhow!("invalid address: {e}"))
}

fn parse_qtr(input: &str) -> Result<u64> {
    let s = input.trim();
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if (whole.is_empty() && frac.is_empty())
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
        || frac.len() > 6
    {
        bail!("invalid QTR amount '{input}'");
    }
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().context("amount too large")? };
    let frac: u64 = if frac.is_empty() { 0 } else { format!("{frac:0<6}").parse()? };
    whole.checked_mul(MICRO_QTR).and_then(|w| w.checked_add(frac)).ok_or_else(|| anyhow!("amount too large"))
}

fn format_qtr(micro: u64) -> String {
    let (w, f) = (micro / MICRO_QTR, micro % MICRO_QTR);
    if f == 0 { w.to_string() } else { format!("{w}.{}", format!("{f:06}").trim_end_matches('0')) }
}

fn short(a: &Address) -> String {
    let h = a.as_hex();
    format!("{}…{}", &h[..8], &h[56..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use qtrc_sentinel::{recovery_commitment, recovery_message, Policy};

    const SALT: [u8; 32] = [7u8; 32];

    struct Fixture {
        vault: Vault,
        watched: Watched,
        thief: Address,
        exchange: Address,
    }

    /// A guarded account with a real HYDRA-X recovery key and its kit.
    fn fixture() -> Fixture {
        let account = HydraXKeypair::generate().address();
        let recovery = HydraXKeypair::generate();
        let cold = HydraXKeypair::generate().address();
        let c = recovery_commitment(CHAIN_ID.as_bytes(), &account, &recovery.address(), &cold, &SALT);
        let proof = recovery.sign(&recovery_message(CHAIN_ID.as_bytes(), &account, &c, 0));
        let exchange = Address([2u8; 32]);
        Fixture {
            vault: Vault::new(account.clone(), 1_000 * MICRO_QTR, Some(c), Policy::new(20, 5 * MICRO_QTR).unwrap()),
            watched: Watched {
                name: "test".into(),
                account,
                policy: WatchPolicy { trusted: vec![exchange.clone()], recover_at: 100 * MICRO_QTR, expected_rotation: None, expected_policy: None },
                kit: RecoveryKit { cold_dest: cold, salt: SALT, proof },
                kit_epoch: 0,
            },
            thief: Address([6u8; 32]),
            exchange,
        }
    }

    #[test]
    fn decisions_follow_the_audited_tick() {
        let f = fixture();
        let w = &f.watched;

        // Quiet vault.
        assert_eq!(decide(&f.vault, w, 10, RecoveryFormat::Full), Action::Idle);

        // Large transfer to the trusted exchange: left alone.
        let mut v = f.vault.clone();
        v.transfer(10, f.exchange.clone(), 500 * MICRO_QTR).unwrap();
        assert_eq!(decide(&v, w, 11, RecoveryFormat::Full), Action::Idle);

        // Small unknown transfer: alert only.
        let mut v = f.vault.clone();
        v.transfer(10, f.thief.clone(), 50 * MICRO_QTR).unwrap();
        assert!(matches!(decide(&v, w, 11, RecoveryFormat::Full), Action::Notify(_)));

        // Large unknown transfer: recover, and the decision does not touch
        // the vault it was given.
        let mut v = f.vault.clone();
        v.transfer(10, f.thief.clone(), 500 * MICRO_QTR).unwrap();
        let before = serde_json::to_value(&v).unwrap();
        assert!(matches!(decide(&v, w, 11, RecoveryFormat::Full), Action::Recovered { .. }));
        assert_eq!(serde_json::to_value(&v).unwrap(), before);
    }

    #[test]
    fn stale_kit_is_reported_with_the_attack() {
        let f = fixture();
        let mut w = f.watched;
        w.kit.salt = [0u8; 32]; // does not open the commitment
        let mut v = f.vault.clone();
        v.transfer(10, f.thief.clone(), 500 * MICRO_QTR).unwrap();
        let Action::KitStale(findings) = decide(&v, &w, 11, RecoveryFormat::Full) else { panic!() };
        assert_eq!(findings[0].severity, Severity::Recover);
    }

    #[test]
    fn config_and_kit_files_parse() {
        let dir = std::env::temp_dir().join(format!("qtrc-wt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = fixture();
        let kit = serde_json::json!({
            "chain_id": CHAIN_ID,
            "account": f.watched.account.as_hex(),
            "cold_dest": f.watched.kit.cold_dest.as_hex(),
            "salt": hex::encode(SALT),
            "epoch": 0,
            "proof": f.watched.kit.proof,
        });
        let kit_path = dir.join("a.kit.json");
        std::fs::write(&kit_path, serde_json::to_vec(&kit).unwrap()).unwrap();
        let cfg_path = dir.join("wt.json");
        std::fs::write(
            &cfg_path,
            serde_json::to_vec(&serde_json::json!({
                "rpc": "http://127.0.0.1:8545",
                "payer_key": "/nonexistent",
                "accounts": [{ "kit": kit_path, "recover_at": "12.5", "trusted": [f.exchange.as_hex()] }]
            }))
            .unwrap(),
        )
        .unwrap();
        let cfg = load_config(&cfg_path).unwrap();
        assert_eq!(cfg.poll_secs, 5);
        let w = load_watched(&cfg.accounts[0]).unwrap();
        assert_eq!(w.policy.recover_at, 12_500_000);
        assert_eq!(w.account, f.watched.account);
        assert_eq!(decide(&f.vault, &w, 10, RecoveryFormat::Full), Action::Idle, "loaded kit opens the commitment");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_situation_alerts_once() {
        let f = fixture();
        let mut v = f.vault.clone();
        v.transfer(10, f.thief.clone(), 50 * MICRO_QTR).unwrap();
        let Action::Notify(a) = decide(&v, &f.watched, 11, RecoveryFormat::Full) else { panic!() };
        let Action::Notify(b) = decide(&v, &f.watched, 12, RecoveryFormat::Full) else { panic!() };
        assert_eq!(alert_key("notify", &a), alert_key("notify", &b));
        v.transfer(13, f.thief.clone(), 30 * MICRO_QTR).unwrap();
        let Action::Notify(c) = decide(&v, &f.watched, 14, RecoveryFormat::Full) else { panic!() };
        assert_ne!(alert_key("notify", &a), alert_key("notify", &c), "new activity alerts again");
    }
}
