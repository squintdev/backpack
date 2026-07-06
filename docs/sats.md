# sats — thin Bitcoin client

Send and receive Bitcoin with keys that live in your backpack keystore. Not
a wallet app — no seed phrases to write down separately, no accounts, no
hardware integrations. Each keyring identity carries a Bitcoin master seed;
`sats` derives addresses from it, reads the chain through an Esplora server,
and builds/signs transactions locally. Broadcast is the only thing the
network ever sees.

## Design

- **HD (BIP84)**: standard `m/84'/coin'/0'` derivation, native segwit
  (`bc1q…`/`tb1q…`) addresses, fresh address per receive, separate internal
  chain for change. Recoverable in any BIP84-capable wallet from the
  exported xprv — funds are never trapped in backpack.
- **Separate key material**: the Bitcoin seed is distinct from the Nostr
  key. Your npub is public; sharing a key would link your identity to your
  money on-chain.
- **Signet by default**: `sats` talks to Bitcoin's signet test network
  (worthless coins, real infrastructure) unless you pass
  `--network mainnet` or set `BACKPACK_BTC_NETWORK=mainnet`. You cannot
  accidentally touch real money.
- **RBF always on**: a stuck transaction can be fee-bumped, never lost.
- **Audited crypto**: transaction construction and signing use rust-bitcoin
  / libsecp256k1 — the same code securing Bitcoin Core — not hand-rolled
  primitives. Money is the one place backpack does not build its own.

## Usage

```sh
keyring btc-init alice        # once, for identities created before sats

sats address --identity alice           # next unused receive address
sats balance --identity alice
sats history --identity alice
sats send --identity alice tb1q… 50000 --fee normal
sats send --identity alice tb1q… max               # sweep: whole balance minus fee
sats send --identity alice tb1q… 50000 --dry-run   # print the signed tx, send nothing
sats export --identity alice --yes      # account xprv — full spend authority
```

`--fee` accepts `fast` (~1 block), `normal` (~6), `slow` (~144), or a
literal sat/vB number.

### The send confirmation

Nothing is signed until you've seen the whole picture and typed `yes`
(not just pressed Enter):

```text
─────────────────────────────────────────────
send      50,000 sats
to        tb1qexampleexampleexampleexampleexamplex9df00
          check ends: tb1qexam … amplex9df00
fee       210 sats (1.5 sat/vB)
change    12,340 sats -> tb1q…
balance   62,550 sats -> 12,340 sats
network   Signet
─────────────────────────────────────────────
type 'yes' to sign and broadcast:
```

The "check ends" line exists because clipboard-swapping malware is the most
common way people lose coins — compare the first and last characters against
the address you were given, out of band.

`max` (or `all`) as the amount sweeps the wallet: every confirmed coin in,
one output, no change — the confirmation panel says "MAX — empties the
wallet" so there is no ambiguity about what is signed.

Refused unless you pass `--force`:

- fee above 5% of the amount
- sending more than half your spendable balance (not applied to `max` —
  emptying the wallet is the stated intent)
- amounts below dust; addresses for the wrong network (never overridable)

## Trying it safely

1. `sats address --identity alice` (signet is the default network)
2. Paste the `tb1q…` address into any signet faucet (search "bitcoin signet
   faucet") — free worthless coins arrive in minutes
3. `sats balance`, `sats history`, then `sats send` some back to the faucet
4. Only after that round-trips clean, consider `--network mainnet` with
   money you can afford to lose

## Privacy and trust

- The Esplora server you query (default: blockstream.info for mainnet,
  mempool.space for signet) learns **your addresses and your IP**. Point
  `--esplora` / `BACKPACK_ESPLORA` at your own instance to remove that.
- Fresh receive addresses per payer keep observers from linking your
  payments together; `sats address` always hands you an unused one.
- Verification of balances trusts the Esplora server's view of the chain.
  For large sums, check against a second source or your own node.

## Backup

The seed lives in the encrypted keystore — backing up
`~/.config/backpack/keyring.veil` (plus remembering its passphrase) backs up
your coins. `sats export --yes` prints the account xprv for recovery into
other wallets; treat that string like the money itself.

## In the TUI

The `backpack` launcher has a SATS screen (menu item 9): ADDRESS / BALANCE /
HISTORY / SEND / NETWORK, with the same full confirmation panel (`y`
broadcasts, `n` aborts) and the same refusal warnings. NETWORK switches
between signet and mainnet in-app, and the panel title always names the
active network. Identities created before Bitcoin support are offered a
seed in-app on first use — equivalent to `keyring btc-init`.

## Building note

`sats` pulls rust-bitcoin's `secp256k1-sys`, which compiles C. Native builds
need nothing extra; cross-compiling for the Pi additionally needs an ARM C
cross-compiler — see [deploy.md](deploy.md).
