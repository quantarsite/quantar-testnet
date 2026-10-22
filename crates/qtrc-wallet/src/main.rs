//! # qtrc-wallet
//!
//! Command-line wallet for the Quantar testnet (`quantar-testnet-2`).
//!
//! Every key is a HYDRA-X keypair (ML-DSA-87, FIPS 204, AND SLH-DSA-SHA2-256s,
//! FIPS 205) and every transaction carries both signatures. Nothing is ever
//! signed with ECDSA.
//!
//! ```text
//! qtrc-wallet new                     create a wallet
//! qtrc-wallet address                 show your address
//! qtrc-wallet faucet                  ask the testnet faucet for QTR
//! qtrc-wallet balance [ADDRESS]       show a balance
//! qtrc-wallet send <TO> <AMOUNT>      send QTR (amount in QTR, e.g. 12.5;
//!                                     a 0.01 QTR network fee is burned)
//! qtrc-wallet status                  show the network status
//! qtrc-wallet proof [ADDRESS]         check a balance against a signed state root
//!
//! Sentinel (recovery + delayed large transfers):
//! qtrc-wallet guardian setup --cold <ADDR>   protect this account
//! qtrc-wallet guardian rotate --cold <ADDR>  replace the recovery key (delayed)
//! qtrc-wallet vault [ADDRESS]                show a vault and its queue
//! qtrc-wallet finalize <ACCOUNT> <ID>        settle a matured queued operation
//! qtrc-wallet recover <ACCOUNT> --kit <FILE> send a guarded account to its cold address
//! ```
//!
//! Testnet only: the key file is stored unencrypted (owner-only permissions on
//! Linux and macOS). Do not reuse it for anything of value.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use qtrc_common::genesis::MICRO_QTR;
use qtrc_common::sentinel::SentinelOp;
use qtrc_common::tx::{Transaction, CHAIN_ID};
use qtrc_crypto::{Address, HydraXKeypair};
use reqwest::blocking::Client;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroizing;

const DEFAULT_RPC: &str = "https://testnet.quantarnetwork.com/rpc";
const DEFAULT_FAUCET: &str = "https://faucet.quantarnetwork.com";
/// Validator of quantar-testnet-2. `proof` only trusts headers it signed.
const DEFAULT_VALIDATOR: &str = "809ae6fb45d3d7c9a2c2f3968c58cc55ad6bb2ca2cfe84f65619c013bbcbbbff";

#[derive(Parser, Debug)]
#[command(
    name = "qtrc-wallet",
    version,
    about = "Quantar testnet wallet. Every transfer is signed with ML-DSA-87 + SLH-DSA (HYDRA-X); no ECDSA signatures."
)]
struct Cli {
    /// Key file (default: ~/.quantar/wallet.key)
    #[arg(long, global = true, env = "QTR_WALLET")]
    key: Option<PathBuf>,

    /// Node RPC URL
    #[arg(long, global = true, env = "QTR_RPC", default_value = DEFAULT_RPC)]
    rpc: String,

    /// Faucet URL
    #[arg(long, global = true, env = "QTR_FAUCET", default_value = DEFAULT_FAUCET)]
    faucet: String,

    /// Validator whose signature `proof` requires on block headers
    #[arg(long, global = true, env = "QTR_VALIDATOR", default_value = DEFAULT_VALIDATOR)]
    validator: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a new wallet (refuses to overwrite an existing one)
    New,
    /// Print your address
    Address,
    /// Ask the testnet faucet to send QTR to your address
    Faucet,
    /// Show the balance of your wallet, or of any address
    Balance { address: Option<String> },
    /// Send QTR. AMOUNT is in QTR (up to 6 decimals, e.g. 12.5). The network
    /// fee (0.01 QTR, burned) is charged on top
    Send { to: String, amount: String },
    /// Show the network status
    Status,
    /// Check an account's balance yourself: verifies the validator's
    /// HYDRA-X signature on the latest block header and the Merkle proof
    /// of the account against the state root in that header
    Proof { address: Option<String> },
    /// Sentinel guardian: recovery key and delayed large transfers
    #[command(subcommand)]
    Guardian(GuardianCmd),
    /// Show the Sentinel vault of your account, or of any address
    Vault { address: Option<String> },
    /// Settle a queued operation whose delay has passed (anyone can; you pay the fee)
    Finalize { account: String, id: u64 },
    /// Recover a guarded account to its committed cold address (you pay the fee)
    Recover {
        /// The guarded account
        account: String,
        /// Recovery kit written by `guardian setup` / `guardian rotate`
        #[arg(long)]
        kit: PathBuf,
        /// Recovery key file: sign now instead of using the kit's pre-made
        /// signature (needed after a rotation the kit predates)
        #[arg(long)]
        recovery_key: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum GuardianCmd {
    /// Protect this account: create a recovery key, commit to it and to a
    /// cold address, and turn on delayed large transfers
    Setup {
        /// Where a recovery sends everything. Use a fresh, never-used address
        #[arg(long)]
        cold: String,
        /// Blocks a large transfer waits (5 s per block; 720 = 1 hour)
        #[arg(long, default_value_t = 720)]
        delay: u64,
        /// QTR that may leave without delay per window of `delay` blocks
        #[arg(long, default_value = "100")]
        allowance: String,
        /// Where to write the new recovery key. Pick a removable drive or
        /// somewhere you will move it from: it must not stay next to the wallet
        #[arg(long)]
        out: PathBuf,
    },
    /// Replace the recovery key and cold address. Takes effect after the delay
    Rotate {
        #[arg(long)]
        cold: String,
        /// Where to write the new recovery key (see `guardian setup --out`)
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let key_path = cli.key.clone().map_or_else(default_key_path, Ok)?;
    let http = Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("qtrc-wallet/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let rpc = cli.rpc.trim_end_matches('/');

    match cli.command {
        Command::New => cmd_new(&key_path),
        Command::Address => {
            println!("{}", load_wallet(&key_path)?.address().as_hex());
            Ok(())
        }
        Command::Faucet => cmd_faucet(&http, cli.faucet.trim_end_matches('/'), &key_path),
        Command::Balance { address } => {
            let addr = match address {
                Some(a) => parse_address(&a)?,
                None => load_wallet(&key_path)?.address(),
            };
            let acct = get_json(&http, &format!("{rpc}/account/{}", addr.as_hex()))?;
            let balance = acct["balance"].as_u64().unwrap_or(0);
            println!("{} QTR", format_qtr(balance));
            Ok(())
        }
        Command::Send { to, amount } => cmd_send(&http, rpc, &key_path, &to, &amount),
        Command::Guardian(GuardianCmd::Setup { cold, delay, allowance, out }) => {
            cmd_guardian(&http, rpc, &key_path, &cold, Some((delay, &allowance)), out)
        }
        Command::Guardian(GuardianCmd::Rotate { cold, out }) => cmd_guardian(&http, rpc, &key_path, &cold, None, out),
        Command::Proof { address } => {
            let addr = match address {
                Some(a) => parse_address(&a)?,
                None => load_wallet(&key_path)?.address(),
            };
            cmd_proof(&http, rpc, &addr, &parse_address(&cli.validator)?)
        }
        Command::Vault { address } => {
            let addr = match address {
                Some(a) => parse_address(&a)?,
                None => load_wallet(&key_path)?.address(),
            };
            cmd_vault(&http, rpc, &addr)
        }
        Command::Finalize { account, id } => {
            let target = parse_address(&account)?;
            let op = SentinelOp::Finalize { id };
            let body = submit(&http, rpc, &load_wallet(&key_path)?, &target, 0, op.encode())?;
            println!("Finalize of operation {id} on {} submitted.", target.as_hex());
            println!("tx: {}", body["tx_hash"].as_str().unwrap_or("?"));
            Ok(())
        }
        Command::Recover { account, kit, recovery_key } => {
            cmd_recover(&http, rpc, &key_path, &account, &kit, recovery_key.as_ref())
        }
        Command::Status => {
            let s = get_json(&http, &format!("{rpc}/status"))?;
            println!("network : {}", s["chain_id"].as_str().unwrap_or("?"));
            println!("height  : {}", s["height"]);
            println!("tip     : {}", s["block_hash"].as_str().unwrap_or("?"));
            println!("version : {}", s["version"].as_str().unwrap_or("?"));
            if let Some(fee) = s["fee"].as_u64() {
                println!("fee     : {} QTR per transaction (burned)", format_qtr(fee));
            }
            if let Some(burned) = s["burned"].as_u64() {
                println!("burned  : {} QTR so far", format_qtr(burned));
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_new(path: &PathBuf) -> Result<()> {
    if path.exists() {
        bail!(
            "a wallet already exists at {}. Use --key to create another one elsewhere.",
            path.display()
        );
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let keypair = HydraXKeypair::generate();
    write_secret_file(path, &keypair.to_bytes())?;

    println!("New post-quantum wallet created (ML-DSA-87 + SLH-DSA, HYDRA-X).");
    println!();
    println!("Address : {}", keypair.address().as_hex());
    println!("Key file: {}", path.display());
    println!();
    println!("Back up the key file. Whoever has it controls this address.");
    println!("Next: `qtrc-wallet faucet` to get testnet QTR.");
    Ok(())
}

fn cmd_faucet(http: &Client, faucet: &str, key_path: &PathBuf) -> Result<()> {
    let address = load_wallet(key_path)?.address().as_hex();
    let resp: Value = http
        .post(format!("{faucet}/api/claim"))
        .json(&serde_json::json!({ "address": address }))
        .send()
        .context("faucet unreachable")?
        .json()
        .context("unexpected faucet response")?;

    if resp["success"].as_bool() == Some(true) {
        println!("{}", resp["message"].as_str().unwrap_or("Tokens sent."));
        if let Some(tx) = resp["tx_hash"].as_str() {
            println!("tx: {tx}");
        }
        println!("It shows up in your balance with the next block (a few seconds).");
        Ok(())
    } else {
        bail!("{}", resp["message"].as_str().unwrap_or("faucet refused the request"))
    }
}

fn cmd_send(http: &Client, rpc: &str, key_path: &PathBuf, to: &str, amount: &str) -> Result<()> {
    let wallet = load_wallet(key_path)?;
    let from = wallet.address();
    let to = parse_address(to)?;
    let micro = parse_qtr(amount)?;
    if micro == 0 {
        bail!("amount must be greater than zero");
    }
    if to == from {
        bail!("sending to your own address does nothing");
    }

    let status = get_json(http, &format!("{rpc}/status"))?;
    let network = status["chain_id"].as_str().unwrap_or_default();
    if network != CHAIN_ID {
        bail!("node is on {network}, this wallet signs for {CHAIN_ID}. Update the wallet.");
    }

    // Nodes before v2.0.2 report no fee and charge none.
    let fee = status["fee"].as_u64().unwrap_or(0);
    let acct = get_json(http, &format!("{rpc}/account/{}", from.as_hex()))?;
    let balance = acct["balance"].as_u64().unwrap_or(0);
    let total = micro.checked_add(fee).ok_or_else(|| anyhow!("amount too large"))?;
    if balance < total {
        if fee > 0 && balance >= micro {
            bail!(
                "not enough QTR for the fee: you have {}, sending {} plus the {} QTR fee needs {}. The most you can send is {}.",
                format_qtr(balance),
                format_qtr(micro),
                format_qtr(fee),
                format_qtr(total),
                format_qtr(balance.saturating_sub(fee))
            );
        }
        bail!(
            "not enough QTR: you have {}, tried to send {}",
            format_qtr(balance),
            format_qtr(micro)
        );
    }
    let vault = get_json(http, &format!("{rpc}/vault/{}", from.as_hex())).ok();
    if let Some(v) = &vault {
        let available = v["available"].as_u64().unwrap_or(0);
        if available < total {
            bail!(
                "not enough unlocked QTR: {} available ({} locked by queued transfers)",
                format_qtr(available),
                format_qtr(v["vault"]["reserved"].as_u64().unwrap_or(0))
            );
        }
    }

    let body = submit(http, rpc, &wallet, &to, micro, Vec::new())?;

    if let Some(v) = &vault {
        let delay = v["vault"]["policy"]["delay_blocks"].as_u64().unwrap_or(0);
        println!("Submitted {} QTR to {}", format_qtr(micro), to.as_hex());
        println!(
            "This account is guarded: within the allowance it leaves with the next block; above it, it waits {delay} blocks and then anyone can finalize it. Check with `qtrc-wallet vault`."
        );
    } else {
        println!("Sent {} QTR to {}", format_qtr(micro), to.as_hex());
    }
    if fee > 0 {
        println!("fee: {} QTR (burned)", format_qtr(fee));
    }
    println!("tx: {}", body["tx_hash"].as_str().unwrap_or("?"));
    println!("Signed with ML-DSA-87 AND SLH-DSA-SHA2-256s.");
    Ok(())
}

/// Sign and submit a transaction with the next nonce. Checks the network first.
fn submit(http: &Client, rpc: &str, wallet: &HydraXKeypair, to: &Address, amount: u64, data: Vec<u8>) -> Result<Value> {
    let status = get_json(http, &format!("{rpc}/status"))?;
    let network = status["chain_id"].as_str().unwrap_or_default();
    if network != CHAIN_ID {
        bail!("node is on {network}, this wallet signs for {CHAIN_ID}. Update the wallet.");
    }
    if !data.is_empty() && status["sentinel_from_height"].is_null() {
        bail!("this node does not support Sentinel yet");
    }
    let from = wallet.address();
    let acct = get_json(http, &format!("{rpc}/account/{}", from.as_hex()))?;
    let nonce = acct["next_nonce"]
        .as_u64()
        .or_else(|| acct["nonce"].as_u64())
        .ok_or_else(|| anyhow!("node did not return a nonce"))?;

    let payload = Transaction::signing_payload_with_data(&from, to, amount, nonce, &data);
    let tx = Transaction {
        from,
        to: to.clone(),
        amount,
        nonce,
        timestamp: chrono::Utc::now().timestamp(),
        signature: wallet.sign(&payload),
        data,
    };
    // Never send something the node would reject for our own mistake.
    tx.verify().map_err(|e| anyhow!("local signature check failed: {e}"))?;

    let resp = http.post(format!("{rpc}/tx")).json(&tx).send().context("node unreachable")?;
    let ok = resp.status().is_success();
    let body: Value = resp.json().unwrap_or_default();
    if !ok {
        bail!("node rejected the transaction: {}", body["error"].as_str().unwrap_or("unknown error"));
    }
    Ok(body)
}

/// Everything needed to recover an account, written next to the wallet.
/// It contains a ready-made recovery signature: whoever holds this file can
/// force a recovery (funds still only go to `cold_dest`). Keep it private.
#[derive(serde::Serialize, serde::Deserialize)]
struct RecoveryKitFile {
    chain_id:  String,
    account:   String,
    cold_dest: String,
    salt:      String,
    /// Guardian epoch the signature is valid for
    epoch:     u64,
    /// Pre-made recovery signature (for you or a watchtower)
    proof:     qtrc_crypto::HydraXSignature,
}

fn cmd_guardian(
    http: &Client,
    rpc: &str,
    key_path: &PathBuf,
    cold: &str,
    setup: Option<(u64, &str)>,
    rec_path: PathBuf,
) -> Result<()> {
    let wallet = load_wallet(key_path)?;
    let account = wallet.address();
    let cold = parse_address(cold)?;
    if cold == account {
        bail!("the cold address must be a different account");
    }
    let vault = get_json(http, &format!("{rpc}/vault/{}", account.as_hex())).ok();
    match (&setup, &vault) {
        (Some(_), Some(_)) => bail!("this account already has a guardian; use `guardian rotate`"),
        (None, None) => bail!("this account has no guardian yet; use `guardian setup`"),
        _ => {}
    }
    if get_json(http, &format!("{rpc}/vault/{}", cold.as_hex())).is_ok() {
        bail!("the cold address has its own vault; use a plain, never-used address");
    }

    if rec_path.parent() == key_path.parent() && key_path.parent().is_some() {
        eprintln!("warning: the recovery key is going next to your wallet key; move it elsewhere afterwards");
    }
    let kit_path = rec_path.with_extension("kit.json");

    let recovery = HydraXKeypair::generate();
    let mut salt = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    let commitment = qtrc_sentinel::recovery_commitment(
        CHAIN_ID.as_bytes(),
        &account,
        &recovery.address(),
        &cold,
        &salt,
    );
    // Epoch the new commitment will be under: 0 for a first setup, one more
    // than now for a rotation (it only applies once finalized).
    let epoch = match &vault {
        Some(v) => v["vault"]["epoch"].as_u64().unwrap_or(0) + 1,
        None => 0,
    };
    let proof = recovery.sign(&qtrc_sentinel::recovery_message(CHAIN_ID.as_bytes(), &account, &commitment, epoch));

    // Write the secrets before anything goes on chain.
    write_secret_file(&rec_path, &recovery.to_bytes())?;
    let kit = RecoveryKitFile {
        chain_id: CHAIN_ID.into(),
        account: account.as_hex(),
        cold_dest: cold.as_hex(),
        salt: hex::encode(salt),
        epoch,
        proof,
    };
    write_secret_file(&kit_path, &serde_json::to_vec_pretty(&kit)?)?;

    let op = match setup {
        Some((delay, allowance)) => SentinelOp::SetGuardian {
            commitment,
            delay_blocks: delay,
            allowance_per_window: parse_qtr(allowance)?,
        },
        None => SentinelOp::RotateGuardian { commitment },
    };
    // The key and kit are written first so they can never be lost after
    // the commitment is on chain. If the node refuses the transaction, the
    // commitment never existed: remove them so a retry starts clean.
    let body = match submit(http, rpc, &wallet, &account, 0, op.encode()) {
        Ok(b) => b,
        Err(e) => {
            let _ = std::fs::remove_file(&rec_path);
            let _ = std::fs::remove_file(&kit_path);
            return Err(e.context("nothing was set up (the recovery key and kit files were removed)"));
        }
    };

    match setup {
        Some((delay, allowance)) => {
            println!("Guardian set up for {}.", account.as_hex());
            println!("Up to {allowance} QTR per {delay} blocks leaves at once; anything above waits {delay} blocks.");
        }
        None => println!("Rotation queued. It takes effect after the delay; until then the old kit still works."),
    }
    println!();
    println!("Recovery key : {}", rec_path.display());
    println!("Recovery kit : {}", kit_path.display());
    println!("Cold address : {}", cold.as_hex());
    println!();
    println!("Move the recovery key OFF this computer (USB drive, paper backup).");
    println!("The kit can force a recovery to the cold address: keep it private.");
    println!("tx: {}", body["tx_hash"].as_str().unwrap_or("?"));
    Ok(())
}

/// What a verified proof shows.
#[derive(Debug)]
struct Proven {
    height: u64,
    timestamp: i64,
    root: [u8; 32],
    leaf: qtrc_common::state_root::Leaf,
}

/// Check a node's answer without trusting the node: the header must be
/// signed (ML-DSA-87 AND SLH-DSA) by the expected validator, and the proof
/// must lead from the account to the state root in that header.
fn verify_proof_answer(
    header: &qtrc_common::block::BlockHeader,
    sigs: &[qtrc_common::block::ValidatorSig],
    proof: Option<&qtrc_common::state_root::Proof>,
    addr: &Address,
    validator: &Address,
) -> Result<Proven> {
    if &header.proposer != validator {
        bail!(
            "header was proposed by {}, not by the expected validator {}",
            header.proposer.as_hex(),
            validator.as_hex()
        );
    }
    let sig = sigs
        .iter()
        .find(|s| &s.validator == validator)
        .ok_or_else(|| anyhow!("header has no signature from the validator"))?;
    if &sig.signature.signer_address() != validator {
        bail!("header signature was made by a different key than the validator's");
    }
    sig.signature
        .verify(&header.signing_bytes())
        .map_err(|e| anyhow!("validator signature on the header is invalid: {e}"))?;
    let root = header.state_root.ok_or_else(|| anyhow!("this block has no state root"))?;
    let proof = proof.ok_or_else(|| {
        anyhow!("NOT VERIFIED: the node sent no proof (it says the account is empty, which cannot be proven yet)")
    })?;
    if &proof.leaf.address != addr {
        bail!("node returned a proof for a different account");
    }
    if !proof.verify(&root) {
        bail!("PROOF INVALID: the node's answer does not match the signed state root");
    }
    Ok(Proven { height: header.height, timestamp: header.timestamp, root, leaf: proof.leaf.clone() })
}

fn cmd_proof(http: &Client, rpc: &str, addr: &Address, validator: &Address) -> Result<()> {
    use qtrc_common::block::{BlockHeader, ValidatorSig};
    use qtrc_common::state_root::Proof;

    let r = get_json(http, &format!("{rpc}/proof/{}", addr.as_hex()))?;
    let header: BlockHeader = serde_json::from_value(r["header"].clone()).context("bad header from node")?;
    let sigs: Vec<ValidatorSig> = serde_json::from_value(r["validator_sigs"].clone()).context("bad signatures from node")?;
    let proof: Option<Proof> = serde_json::from_value(r["proof"].clone()).context("bad proof from node")?;

    let p = verify_proof_answer(&header, &sigs, proof.as_ref(), addr, validator)?;
    let age = chrono::Utc::now().timestamp().saturating_sub(p.timestamp);

    println!("Verified with ML-DSA-87 AND SLH-DSA-SHA2-256s, signed by validator {}.", short_addr(validator));
    println!("account : {}", addr.as_hex());
    println!("balance : {} QTR", format_qtr(p.leaf.balance));
    println!("nonce   : {}", p.leaf.nonce);
    println!("guarded : {}", if p.leaf.vault_hash.is_some() { "yes (Sentinel vault)" } else { "no" });
    println!("block   : {} ({} ago)", p.height, human_age(age));
    println!("root    : {}", hex::encode(p.root));
    println!();
    println!("This proves the balance as of block {}. A node can still answer with an older", p.height);
    println!("block; if that block looks too old for recent activity, ask another node.");
    Ok(())
}

fn short_addr(a: &Address) -> String {
    let h = a.as_hex();
    format!("{}…{}", &h[..8], &h[56..])
}

fn human_age(secs: i64) -> String {
    match secs {
        s if s < 120 => format!("{s} s"),
        s if s < 7_200 => format!("{} min", s / 60),
        s if s < 172_800 => format!("{} h", s / 3_600),
        s => format!("{} days", s / 86_400),
    }
}

fn cmd_vault(http: &Client, rpc: &str, addr: &Address) -> Result<()> {
    let r = get_json(http, &format!("{rpc}/vault/{}", addr.as_hex()))?;
    let v = &r["vault"];
    let height = get_json(http, &format!("{rpc}/status"))?["height"].as_u64().unwrap_or(0);
    println!("account   : {}", addr.as_hex());
    if let Some(to) = v["recovered_to"].as_str() {
        println!("status    : RECOVERED, everything forwards to {to}");
        return Ok(());
    }
    println!("balance   : {} QTR", format_qtr(v["balance"].as_u64().unwrap_or(0)));
    println!("available : {} QTR", format_qtr(r["available"].as_u64().unwrap_or(0)));
    println!("locked    : {} QTR", format_qtr(v["reserved"].as_u64().unwrap_or(0)));
    println!(
        "policy    : {} QTR per {} blocks without delay",
        format_qtr(v["policy"]["allowance_per_window"].as_u64().unwrap_or(0)),
        v["policy"]["delay_blocks"]
    );
    println!("epoch     : {}", v["epoch"]);
    let pending = v["pending"].as_array().cloned().unwrap_or_default();
    if pending.is_empty() {
        println!("queue     : empty");
    }
    for p in pending {
        let unlock = p["unlock_height"].as_u64().unwrap_or(0);
        let when = if height >= unlock { "ready to finalize".to_string() } else { format!("{} blocks left", unlock - height) };
        let what = if let Some(t) = p["kind"].get("Transfer") {
            format!("send {} QTR to {}", format_qtr(t["amount"].as_u64().unwrap_or(0)), t["to"].as_str().unwrap_or("?"))
        } else {
            "replace recovery key".to_string()
        };
        println!("  #{} {what} ({when})", p["id"]);
    }
    Ok(())
}

fn cmd_recover(
    http: &Client,
    rpc: &str,
    key_path: &PathBuf,
    account: &str,
    kit_path: &PathBuf,
    recovery_key: Option<&PathBuf>,
) -> Result<()> {
    let target = parse_address(account)?;
    let kit: RecoveryKitFile = serde_json::from_slice(
        &std::fs::read(kit_path).with_context(|| format!("cannot read {}", kit_path.display()))?,
    )
    .context("invalid kit file")?;
    if kit.account != target.as_hex() {
        bail!("this kit belongs to account {}, not {}", kit.account, target.as_hex());
    }
    let cold = parse_address(&kit.cold_dest)?;
    let salt: [u8; 32] = hex::decode(&kit.salt)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("invalid salt in kit"))?;

    let r = get_json(http, &format!("{rpc}/vault/{}", target.as_hex()))?;
    let epoch = r["vault"]["epoch"].as_u64().unwrap_or(0);
    let commitment: [u8; 32] = serde_json::from_value(r["vault"]["commitment"].clone())
        .ok()
        .flatten()
        .ok_or_else(|| anyhow!("the account has no active guardian"))?;

    let proof = match recovery_key {
        Some(path) => {
            let rec = load_wallet(path)?;
            rec.sign(&qtrc_sentinel::recovery_message(CHAIN_ID.as_bytes(), &target, &commitment, epoch))
        }
        None => {
            if kit.epoch != epoch {
                bail!("this kit is for epoch {}, the vault is at {epoch}; pass --recovery-key to sign now", kit.epoch);
            }
            kit.proof
        }
    };
    let op = SentinelOp::Recover { cold_dest: cold.clone(), salt, proof: Box::new(proof) };
    let payer = load_wallet(key_path)?;
    if payer.address() == target {
        println!("Submitting from the guarded account itself: the fee comes out of the recovered amount.");
        println!("If a thief has this key, submitting from another wallet (--key) avoids racing its nonces.");
    }
    let body = submit(http, rpc, &payer, &target, 0, op.encode())?;
    println!("Recovery submitted: everything in {} goes to {}.", target.as_hex(), cold.as_hex());
    println!("tx: {}", body["tx_hash"].as_str().unwrap_or("?"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_key_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| anyhow!("cannot find your home folder; pass --key <file>"))?;
    Ok(PathBuf::from(home).join(".quantar").join("wallet.key"))
}

fn load_wallet(path: &PathBuf) -> Result<HydraXKeypair> {
    let bytes = Zeroizing::new(std::fs::read(path).with_context(|| {
        format!("no wallet at {}. Create one with `qtrc-wallet new`.", path.display())
    })?);
    HydraXKeypair::from_bytes(&bytes).map_err(|e| anyhow!("invalid key file {}: {e}", path.display()))
}

fn write_secret_file(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn get_json(http: &Client, url: &str) -> Result<Value> {
    let resp = http.get(url).send().with_context(|| format!("cannot reach {url}"))?;
    let ok = resp.status().is_success();
    let body: Value = resp.json().context("unexpected response from node")?;
    if !ok {
        bail!("{}", body["error"].as_str().unwrap_or("request failed"));
    }
    Ok(body)
}

fn parse_address(input: &str) -> Result<Address> {
    let a = input.trim();
    if a.starts_with("qtr1") {
        bail!("qtr1... is the short display form and only half of an address. Use the full 64-character address.");
    }
    if a.starts_with("0x") || a.starts_with("bc1") {
        bail!("Quantar does not use ECDSA; Ethereum and Bitcoin addresses cannot receive QTR.");
    }
    if a.len() != 64 || !a.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid address: expected 64 hex characters");
    }
    Address::from_hex(&a.to_lowercase()).map_err(|e| anyhow!("invalid address: {e}"))
}

/// "12.5" QTR -> 12_500_000 micro-QTR. Exact, no floating point.
fn parse_qtr(input: &str) -> Result<u64> {
    let s = input.trim();
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if whole.is_empty() && frac.is_empty() {
        bail!("invalid amount");
    }
    if !whole.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) {
        bail!("invalid amount '{input}': use a number like 10 or 2.5");
    }
    if frac.len() > 6 {
        bail!("QTR has 6 decimal places at most");
    }
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().context("amount too large")? };
    let frac_micro: u64 = if frac.is_empty() { 0 } else { format!("{frac:0<6}").parse()? };
    whole
        .checked_mul(MICRO_QTR)
        .and_then(|w| w.checked_add(frac_micro))
        .ok_or_else(|| anyhow!("amount too large"))
}

fn format_qtr(micro: u64) -> String {
    let whole = micro / MICRO_QTR;
    let frac = micro % MICRO_QTR;
    if frac == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{}", format!("{frac:06}").trim_end_matches('0'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qtr_amounts_parse_exactly() {
        assert_eq!(parse_qtr("50").unwrap(), 50 * MICRO_QTR);
        assert_eq!(parse_qtr("12.5").unwrap(), 12_500_000);
        assert_eq!(parse_qtr("0.000001").unwrap(), 1);
        assert_eq!(parse_qtr(".5").unwrap(), 500_000);
        assert!(parse_qtr("1.0000001").is_err());
        assert!(parse_qtr("-1").is_err());
        assert!(parse_qtr("1e3").is_err());
        assert!(parse_qtr("").is_err());
        assert!(parse_qtr("99999999999999999999").is_err());
    }

    #[test]
    fn qtr_amounts_format_back() {
        assert_eq!(format_qtr(50 * MICRO_QTR), "50");
        assert_eq!(format_qtr(12_500_000), "12.5");
        assert_eq!(format_qtr(1), "0.000001");
    }

    /// Regression W1: a node cannot pass off a header signed by its own key.
    #[test]
    fn proof_requires_the_expected_validator() {
        use qtrc_common::block::{BlockHash, BlockHeader, ValidatorSig};
        use qtrc_common::state::AccountState;
        use qtrc_common::tx::TxHash;

        let victim = HydraXKeypair::generate().address();
        let mut fake = qtrc_common::genesis::Genesis::testnet_with_faucet(None).initial_state();
        fake.accounts.insert(victim.as_hex(), AccountState { balance: 1_000_000 * MICRO_QTR, nonce: 0 });
        let header_by = |kp: &HydraXKeypair| {
            let header = BlockHeader {
                height: 999_999,
                prev_hash: BlockHash([0; 32]),
                merkle_root: TxHash([0; 32]),
                timestamp: 0,
                proposer: kp.address(),
                state_root: Some(fake.state_root()),
                witness_root: None,
            };
            let sigs = vec![ValidatorSig { validator: kp.address(), signature: kp.sign(&header.signing_bytes()) }];
            (header, sigs)
        };
        let proof = fake.state_proof(&victim).unwrap();

        let real = HydraXKeypair::generate();
        let evil = HydraXKeypair::generate();
        let (h, s) = header_by(&evil);
        assert!(verify_proof_answer(&h, &s, Some(&proof), &victim, &real.address()).is_err(), "evil key refused");

        let (h, s) = header_by(&real);
        let ok = verify_proof_answer(&h, &s, Some(&proof), &victim, &real.address()).unwrap();
        assert_eq!(ok.leaf.balance, 1_000_000 * MICRO_QTR);

        // Signature by the validator over a different header is refused.
        let (mut h2, s2) = header_by(&real);
        h2.height += 1;
        assert!(verify_proof_answer(&h2, &s2, Some(&proof), &victim, &real.address()).is_err());

        // No proof is "not verified", never a statement of fact.
        let err = verify_proof_answer(&h, &s, None, &victim, &real.address()).unwrap_err().to_string();
        assert!(err.contains("NOT VERIFIED"), "{err}");
    }

    #[test]
    fn addresses_reject_ecdsa_and_short_forms() {
        assert!(parse_address("0x742d35Cc6634C0532925a3b844Bc454e4438f44e").is_err());
        assert!(parse_address("qtr19b7eb38c5f5b8fa2248fa761a4ec4730").is_err());
        assert!(parse_address(&"a".repeat(64)).is_ok());
        assert!(parse_address(&"A".repeat(64)).is_ok());
    }
}
