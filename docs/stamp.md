# stamp — timestamp proofs

Prove a file existed at a point in time without revealing its contents — or
even its hash. `stamp` is an OpenTimestamps client: proofs it writes are
standard `.ots` files any OTS tool can verify, and it verifies proofs made by
other clients (including the reference client's own example proofs — that's
in the live test suite).

## How it works

1. **Stamp.** SHA-256 the file, append a random 16-byte nonce, hash again.
   Calendars only ever see this *blinded commitment* — never the file, never
   its digest.
2. **Aggregate.** Public calendar servers merkle-aggregate everyone's
   commitments and commit the root to a Bitcoin transaction (every few
   hours, at their expense — free for you, no account).
3. **Upgrade.** Once the transaction confirms, fetch the merkle path from the
   calendar. The proof now says: this commitment is under the merkle root of
   Bitcoin block *N* — a timestamp no one can forge or backdate without
   rewriting Bitcoin.
4. **Verify.** Replay the proof's operations from the file hash and compare
   the result against block *N*'s merkle root (via Esplora by default; any
   Bitcoin node works).

## Usage

```sh
stamp report.pdf                 # -> report.pdf.ots  (pending)
stamp info report.pdf.ots        # show attestations
stamp upgrade report.pdf.ots     # hours later: fetch the Bitcoin attestation
stamp verify report.pdf          # OK: existed by 2026-07-04T… (Bitcoin block N)
```

Options: `-c/--calendar` overrides the calendar pool (repeatable);
`--esplora` points verification at your own Esplora instance;
`--offline` skips network checks and just reports what the proof claims.

Exit codes on `verify`: `0` Bitcoin-verified, `1` mismatch/error, `2` proof
exists but has no Bitcoin attestation yet.

## Trust model

- **Stamping** trusts nothing: the calendar can't learn or forge anything —
  worst case it drops your commitment and the upgrade never arrives (stamp
  submits to three calendars by default, any one suffices).
- **Verifying** an upgraded proof needs an honest view of Bitcoin block
  headers. The default (Esplora over HTTPS) trusts blockstream.info to
  report the right merkle root; point `--esplora` at your own node's
  Esplora, or check the printed merkle root against any source, to remove
  that trust.
- The proof file itself is public information — it commits to your file's
  hash but reveals nothing about the contents.

## Pairs with canary

Stamp each canary you publish and you can later prove the canary existed
(and when) even if your site vanishes:

```sh
canary new --key ops --days 30 --statement "…" -o canary.txt
stamp canary.txt
```

## In the TUI

The `backpack` launcher has a STAMP screen (menu item 8): STAMP / UPGRADE /
VERIFY / INFO as native forms. Network calls show a WORKING overlay.

## Library

```rust
let digest = stamp::digest_reader(&mut file)?;
let (proof, outcomes) = stamp::stamp(digest, stamp::calendar::DEFAULT_CALENDARS);
let mut proof = proof?;
// … hours later …
let (upgraded, remaining) = stamp::upgrade(&mut proof)?;
let checks = stamp::verify(&proof, digest, Some(stamp::calendar::DEFAULT_ESPLORA))?;
```

The `ots` module is a standalone implementation of the OpenTimestamps proof
format (ops tree, attestations, canonical serialization); `ser` holds the
wire primitives. Format compatibility is pinned by live tests against the
reference client's published example proof.
