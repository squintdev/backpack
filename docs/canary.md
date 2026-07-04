# canary — warrant canaries

A warrant canary inverts the gag order: instead of announcing that something
happened (which you may be legally barred from doing), you routinely announce
that it *hasn't*. The day you stop, your silence speaks. `canary` makes those
statements cryptographically checkable: signed with a `keyring` identity,
carrying an explicit expiry and a monotonic sequence number.

Readers treat any of these as the signal:

- the canary **expired** without renewal
- the canary **disappeared**
- the **sequence went backwards** (someone republished an old one)
- the **signing key changed**

## Document format

One copy-pasteable text document — safe to paste into a web page, a Nostr
note, or a pinned file. Surrounding text is tolerated by the parser.

```text
BPCANARY1
key: BPKEY1 ops <ed25519 hex> <x25519 hex>
issued: 1783143647 2026-07-04T05:40:47Z
expires: 1785735647 2026-08-03T05:40:47Z
sequence: 1
-----BEGIN STATEMENT-----
As of the date above, we have received no warrants, NSLs, or gag orders.
-----END STATEMENT-----
BPSIG1 <ed25519 signature hex>
```

The Ed25519 signature covers the identity line, the unix timestamps, the
sequence number, and the exact statement text. The human-readable dates are
derived decoration — altering them doesn't help an attacker; altering the
signed timestamps breaks the signature.

## Usage

```sh
# Sign the first canary (sequence 1, valid 30 days)
canary new --key ops --days 30 \
  --statement "No warrants received." -o canary.txt

# Statement from a file or stdin also works
canary new --key ops --file statement.txt -o canary.txt

# On your renewal schedule: same statement, sequence+1, fresh window
canary renew canary.txt --key ops --days 30 -o canary.txt

# Anyone verifies — no passphrase, no keystore needed
canary check canary.txt
canary check canary.txt --pub ops.pub            # pin the signer
canary check canary.txt --previous last-seen.txt # detect rollback
```

`check` output:

```text
signer:   ops [a6c9-0bec-5381-236a]
sequence: 2
issued:   2026-07-04T05:40:51Z
expires:  2026-08-03T05:40:51Z
status:   ALIVE (29d 23h remaining)
```

Exit codes: `0` alive, `1` bad signature / rollback / wrong key, `2` expired —
so a cron job can page you when your own canary is about to trip, and readers
can script their checks.

## Operating one

- **Publish the public identity separately** (`keyring export ops`), through a
  different channel than the canary itself, so readers can pin the key.
- **Renew early.** Pick a window comfortably longer than your renewal cadence
  (e.g. renew weekly with `--days 30`) so an outage doesn't false-trip it.
- **Keep the last canary you saw** if you're a reader: `--previous` is what
  catches an adversary replaying an old, still-unexpired canary.
- **Say only what's true.** The scheme proves the statement was signed by the
  key and hasn't expired — the legal theory of canaries rests on you never
  signing a false statement, only declining to renew.

Verification is stateless and offline; only `new` and `renew` touch the
keystore (`$BACKPACK_PASSPHRASE` skips the prompt, `--keyring` /
`$BACKPACK_KEYRING` override the path).

## In the TUI

The `backpack` launcher has a CANARY screen (menu item 7): NEW / RENEW /
CHECK as native forms over the same library. See
[launcher.md](launcher.md).

## Library

`canary` is a lib + thin CLI like the rest of the suite:

```rust
let c = canary::Canary::issue(&keypair, "No warrants.", now, 30 * 86_400, 1)?;
let doc = c.render();                 // the signed text document
let parsed = canary::Canary::parse(&doc)?;
parsed.verify()?;                     // signature
parsed.status(now);                   // Valid { remaining } | Expired { overdue }
parsed.check_succession(&previous)?;  // rollback / key-swap detection
```

## Not included (yet)

The original spec also sketched **tripwire tokens** — unique URLs/files that
alert when accessed. Those need a listening server and are out of scope for
an offline deck tool.
