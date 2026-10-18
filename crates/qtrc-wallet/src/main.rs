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
//! qtrc-wallet send <TO> <AMOUNT>      send QTR (amount in QTR, e.g. 12.5)
//! qtrc-wallet status                  show the network status
//! ```
//!
//! Testnet only: the key file is stored unencrypted (owner-only permissions on
//! Linux and macOS). Do not reuse it for anything of value.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use qtrc_common::genesis::MICRO_QTR;
use qtrc_common::tx::{Transaction, CHAIN_ID};
use qtrc_crypto::{Address, HydraXKeypair};
use reqwest::blocking::Client;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroizing;

const DEFAULT_RPC: &str = "https://testnet.quantarnetwork.com/rpc";
const DEFAULT_FAUCET: &str = "https://faucet.quantarnetwork.com";

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
    /// Send QTR. AMOUNT is in QTR and accepts up to 6 decimals (e.g. 12.5)
    Send { to: String, amount: String },
    /// Show the network status
    Status,
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
        Command::Status => {
            let s = get_json(&http, &format!("{rpc}/status"))?;
            println!("network : {}", s["chain_id"].as_str().unwrap_or("?"));
            println!("height  : {}", s["height"]);
            println!("tip     : {}", s["block_hash"].as_str().unwrap_or("?"));
            println!("version : {}", s["version"].as_str().unwrap_or("?"));
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

    let acct = get_json(http, &format!("{rpc}/account/{}", from.as_hex()))?;
    let balance = acct["balance"].as_u64().unwrap_or(0);
    if balance < micro {
        bail!(
            "not enough QTR: you have {}, tried to send {}",
            format_qtr(balance),
            format_qtr(micro)
        );
    }
    let nonce = acct["next_nonce"]
        .as_u64()
        .or_else(|| acct["nonce"].as_u64())
        .ok_or_else(|| anyhow!("node did not return a nonce"))?;

    let payload = Transaction::signing_payload(&from, &to, micro, nonce);
    let tx = Transaction {
        from,
        to: to.clone(),
        amount: micro,
        nonce,
        timestamp: chrono::Utc::now().timestamp(),
        signature: wallet.sign(&payload),
    };
    // Never send something the node would reject for our own mistake.
    tx.verify().map_err(|e| anyhow!("local signature check failed: {e}"))?;

    let resp = http.post(format!("{rpc}/tx")).json(&tx).send().context("node unreachable")?;
    let ok = resp.status().is_success();
    let body: Value = resp.json().unwrap_or_default();
    if !ok {
        bail!("node rejected the transaction: {}", body["error"].as_str().unwrap_or("unknown error"));
    }

    println!("Sent {} QTR to {}", format_qtr(micro), to.as_hex());
    println!("tx: {}", body["tx_hash"].as_str().unwrap_or("?"));
    println!("Signed with ML-DSA-87 AND SLH-DSA-SHA2-256s.");
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

    #[test]
    fn addresses_reject_ecdsa_and_short_forms() {
        assert!(parse_address("0x742d35Cc6634C0532925a3b844Bc454e4438f44e").is_err());
        assert!(parse_address("qtr19b7eb38c5f5b8fa2248fa761a4ec4730").is_err());
        assert!(parse_address(&"a".repeat(64)).is_ok());
        assert!(parse_address(&"A".repeat(64)).is_ok());
    }
}
