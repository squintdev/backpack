//! `sats` — Bitcoin from the command line, keys in the backpack keystore.
//!
//! ```text
//! sats address --identity alice                 # next receive address
//! sats balance --identity alice
//! sats history --identity alice
//! sats send    --identity alice <ADDRESS> <SATS> [--fee normal] [--force]
//! sats export  --identity alice --yes           # account xprv (backup)
//! ```
//!
//! Runs on **signet** unless `--network mainnet` (or
//! `BACKPACK_BTC_NETWORK=mainnet`) says otherwise.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use keyring::{default_keystore_path, KeyStore, PATH_ENV};
use sats::hd::{Chain, Wallet};
use sats::wallet::{build_spend, build_sweep, history, scan, sign_spend};
use sats::{default_esplora, fmt_sats, parse_network, Network};
use zeroize::Zeroizing;

const PASS_ENV: &str = "BACKPACK_PASSPHRASE";
const NET_ENV: &str = "BACKPACK_BTC_NETWORK";
const ESPLORA_ENV: &str = "BACKPACK_ESPLORA";

#[derive(Parser)]
#[command(
    name = "sats",
    version,
    about = "Thin Bitcoin client: HD addresses, balance, history, send",
    after_help = "EXAMPLES:\n  \
        sats address --identity alice\n  \
        sats balance --identity alice\n  \
        sats send --identity alice tb1q... 50000 --fee normal\n\n\
        Defaults to SIGNET (worthless test coins). Real Bitcoin requires\n\
        --network mainnet or BACKPACK_BTC_NETWORK=mainnet, deliberately.\n\
        The Esplora server you query learns your addresses and IP; use\n\
        --esplora to point at your own instance."
)]
struct Cli {
    /// bitcoin network: signet (default), testnet, or mainnet.
    #[arg(long, global = true)]
    network: Option<String>,

    /// Esplora API base URL (defaults per network).
    #[arg(long, global = true)]
    esplora: Option<String>,

    /// Path to the keystore file.
    #[arg(long, global = true)]
    keyring: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show the next unused receive address.
    Address {
        #[arg(long)]
        identity: String,
    },
    /// Confirmed and pending balance.
    Balance {
        #[arg(long)]
        identity: String,
    },
    /// Transaction history (net effect per transaction).
    History {
        #[arg(long)]
        identity: String,
    },
    /// Build, confirm, sign, and broadcast a payment.
    Send {
        #[arg(long)]
        identity: String,
        /// Destination address.
        address: String,
        /// Amount in sats, or "max" to sweep the whole balance minus fee.
        sats: String,
        /// Fee target: fast (~1 block), normal (~6), slow (~144), or a
        /// number in sat/vB.
        #[arg(long, default_value = "normal")]
        fee: String,
        /// Skip the sanity refusals (high fee ratio, >50% of balance).
        #[arg(long)]
        force: bool,
        /// Print the signed transaction instead of broadcasting it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Print the account xprv (FULL SPEND AUTHORITY — for backup/recovery).
    Export {
        #[arg(long)]
        identity: String,
        /// Confirm you understand this prints the private key material.
        #[arg(long)]
        yes: bool,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("sats: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let network = resolve_network(&cli)?;
    let esplora_url = cli
        .esplora
        .clone()
        .or_else(|| std::env::var(ESPLORA_ENV).ok())
        .unwrap_or_else(|| default_esplora(network).to_string());
    let client = sats::esplora::Client::new(&esplora_url);

    if network == Network::Bitcoin {
        eprintln!("network: MAINNET — real money");
    } else {
        eprintln!("network: {network:?} (test coins; --network mainnet for real Bitcoin)");
    }

    match &cli.cmd {
        Cmd::Address { identity } => {
            let wallet = load_wallet(&cli, identity, network)?;
            let s = scan(&wallet, &client)?;
            let key = wallet.key(Chain::External, s.next_receive)?;
            println!("{}", key.address);
            eprintln!("(fresh address — give each payer their own)");
            Ok(())
        }
        Cmd::Balance { identity } => {
            let wallet = load_wallet(&cli, identity, network)?;
            let s = scan(&wallet, &client)?;
            println!("confirmed: {}", fmt_sats(s.confirmed_sats));
            if s.pending_sats != 0 {
                println!("pending:   {}", fmt_sats(s.pending_sats));
            }
            Ok(())
        }
        Cmd::History { identity } => {
            let wallet = load_wallet(&cli, identity, network)?;
            let s = scan(&wallet, &client)?;
            let entries = history(&s, &client)?;
            if entries.is_empty() {
                println!("(no transactions)");
                return Ok(());
            }
            for e in entries {
                let when = match (e.confirmed, e.block_time) {
                    (true, Some(t)) => fmt_ts(t),
                    _ => "unconfirmed        ".into(),
                };
                println!("{when}  {:>26}  {}", fmt_sats(e.net_sats), e.txid);
            }
            Ok(())
        }
        Cmd::Send {
            identity,
            address,
            sats: amount,
            fee,
            force,
            dry_run,
        } => cmd_send(
            &cli, &client, network, identity, address, amount, fee, *force, *dry_run,
        ),
        Cmd::Export { identity, yes } => {
            if !yes {
                bail!("this prints your PRIVATE key. Re-run with --yes if you mean it");
            }
            let wallet = load_wallet(&cli, identity, network)?;
            println!("{}", wallet.xprv());
            eprintln!("account xprv (BIP84 {network:?}) — anyone with this string can spend");
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_send(
    cli: &Cli,
    client: &sats::esplora::Client,
    network: Network,
    identity: &str,
    address: &str,
    amount: &str,
    fee: &str,
    force: bool,
    dry_run: bool,
) -> Result<()> {
    let wallet = load_wallet(cli, identity, network)?;
    let s = scan(&wallet, client)?;
    let fee_rate = resolve_fee_rate(client, fee)?;
    let sweep = amount.eq_ignore_ascii_case("max") || amount.eq_ignore_ascii_case("all");
    let mut spend = if sweep {
        build_sweep(&wallet, &s, address, fee_rate)?
    } else {
        let amount: u64 = amount
            .replace([',', '_'], "")
            .parse()
            .map_err(|_| anyhow!("amount must be a whole number of sats, or \"max\""))?;
        build_spend(&wallet, &s, address, amount, fee_rate)?
    };

    // Foot-gun refusals — overridable, never silent. A sweep empties the
    // wallet by definition, so the half-balance guard does not apply.
    if !force {
        if spend.fee * 20 > spend.amount {
            bail!(
                "fee ({}) exceeds 5% of the amount — use --force if intentional",
                fmt_sats(spend.fee as i64)
            );
        }
        if !sweep && spend.amount * 2 > spend.spendable_before {
            bail!(
                "sending more than half your spendable balance ({}) — use --force if intentional",
                fmt_sats(spend.spendable_before as i64)
            );
        }
    }

    // The confirmation screen: everything, then typed consent.
    let d = &spend.destination;
    eprintln!("─────────────────────────────────────────────");
    if sweep {
        eprintln!(
            "send      {} (MAX — empties the wallet)",
            fmt_sats(spend.amount as i64)
        );
    } else {
        eprintln!("send      {}", fmt_sats(spend.amount as i64));
    }
    eprintln!("to        {d}");
    if d.len() > 16 {
        eprintln!("          check ends: {} … {}", &d[..8], &d[d.len() - 8..]);
    }
    eprintln!(
        "fee       {} ({:.1} sat/vB)",
        fmt_sats(spend.fee as i64),
        spend.fee_rate
    );
    if let Some(c) = &spend.change_address {
        eprintln!("change    {} -> {c}", fmt_sats(spend.change as i64));
    }
    eprintln!(
        "balance   {} -> {}",
        fmt_sats(spend.spendable_before as i64),
        fmt_sats(spend.spendable_before as i64 - spend.amount as i64 - spend.fee as i64)
    );
    eprintln!("network   {network:?}");
    if sweep {
        eprintln!();
        eprintln!("⚠ PRIVACY: a sweep spends ALL your coins in one transaction,");
        eprintln!("  publicly linking every address that ever received to this");
        eprintln!("  wallet. Anyone watching the destination sees your full");
        eprintln!("  payment history as one cluster.");
    }
    eprintln!("─────────────────────────────────────────────");

    if !dry_run {
        eprint!("type 'yes' to sign and broadcast: ");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).context("stdin")?;
        if line.trim() != "yes" {
            bail!("aborted (nothing signed, nothing sent)");
        }
    }

    let tx_hex = sign_spend(&wallet, &s, &mut spend)?;
    if dry_run {
        println!("{tx_hex}");
        eprintln!("dry run — not broadcast");
        return Ok(());
    }
    let txid = client.broadcast(&tx_hex)?;
    println!("broadcast: {txid}");
    eprintln!("RBF is enabled — the fee can be bumped if it gets stuck");
    Ok(())
}

/// fast/normal/slow via the live estimator, or a literal sat/vB number.
fn resolve_fee_rate(client: &sats::esplora::Client, fee: &str) -> Result<f64> {
    if let Ok(n) = fee.parse::<f64>() {
        if !(0.9..=2000.0).contains(&n) {
            bail!("fee rate {n} sat/vB is out of sane range");
        }
        return Ok(n);
    }
    let target = match fee {
        "fast" => "2",
        "normal" => "6",
        "slow" => "144",
        other => bail!("unknown fee target {other:?} (fast/normal/slow or sat/vB)"),
    };
    let est = client.fee_estimates().map_err(|e| anyhow!(e))?;
    Ok(est.get(target).copied().unwrap_or(1.0).max(1.0))
}

fn resolve_network(cli: &Cli) -> Result<Network> {
    let name = cli
        .network
        .clone()
        .or_else(|| std::env::var(NET_ENV).ok())
        .unwrap_or_else(|| "signet".to_string());
    Ok(parse_network(&name)?)
}

fn load_wallet(cli: &Cli, identity: &str, network: Network) -> Result<Wallet> {
    let path = match &cli.keyring {
        Some(p) => p.clone(),
        None => default_keystore_path()
            .ok_or_else(|| anyhow!("cannot determine config directory; set {PATH_ENV}"))?,
    };
    if !path.exists() {
        bail!(
            "no keystore at {} — create an identity with `keyring gen` first",
            path.display()
        );
    }
    let pass = passphrase()?;
    let store = KeyStore::open(&path, pass.as_bytes())?;
    let kp = store
        .get(identity)
        .ok_or_else(|| anyhow!("no identity named {identity:?}"))?;
    let seed = kp.btc_seed().ok_or_else(|| {
        anyhow!("{identity} has no Bitcoin seed yet — run `keyring btc-init {identity}`")
    })?;
    Ok(Wallet::from_seed(&seed, network)?)
}

fn passphrase() -> Result<Zeroizing<String>> {
    if let Ok(p) = std::env::var(PASS_ENV) {
        if p.is_empty() {
            bail!("{PASS_ENV} must not be empty");
        }
        return Ok(Zeroizing::new(p));
    }
    let p = rpassword::prompt_password("Keystore passphrase: ").context("reading passphrase")?;
    Ok(Zeroizing::new(p))
}

fn fmt_ts(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let rem = unix % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe as i64 + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        rem / 3_600,
        (rem % 3_600) / 60
    )
}
