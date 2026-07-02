# nostr

Publish and read [Nostr](https://nostr.com) notes with a backpack keyring
identity. Nostr is a decentralized publishing protocol: notes are signed by
your key and mirrored across independent relays, so no company can silence the
key. `nostr` is a minimal, synchronous NIP-01 client — no daemon, no async
runtime.

## Usage

```text
nostr whoami --identity NAME              # your npub + hex pubkey
nostr post   --identity NAME "text"       # sign + publish a text note
nostr fetch  --author <npub|hex> [--limit N]
```

```sh
nostr whoami --identity alice
nostr post --identity alice "hello, uncensorable world"
nostr fetch --author npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6 --limit 5
```

## Relays

Priority: `-r/--relay` (repeatable) → `$BACKPACK_NOSTR_RELAYS` (comma-separated)
→ built-in defaults (`relay.damus.io`, `nos.lol`, `relay.nostr.band`).

- `post` sends to **every** configured relay in parallel and reports
  accept/reject per relay; it fails only if none accept.
- `fetch` reads from the **first** relay that answers.
- Everything is bounded: 5 s TCP connect timeout, 10 s socket reads. A dead or
  blackholed relay costs seconds, not minutes, and can never hang the client.

## Identity

Nostr uses secp256k1 (BIP340 Schnorr) — a different curve from the keyring's
Ed25519/X25519 — so each keyring identity carries a **third, distinct key** for
Nostr. New identities get one automatically; identities created before Nostr
support need a one-time upgrade:

```sh
keyring nostr-init alice
```

The key never leaves the encrypted keystore; `post`/`whoami` unlock it with
`$BACKPACK_PASSPHRASE` or a prompt.

## How it works

- **Events (NIP-01):** id = SHA-256 of the canonical JSON array
  `[0, pubkey, created_at, kind, tags, content]`; signature = BIP340 Schnorr
  over the id (pure-Rust `k256`, fresh auxiliary randomness per signature).
- **Verification:** every event `fetch` receives is re-hashed and its signature
  checked before display — relay data is never trusted. Bad events are dropped
  and counted.
- **npub (NIP-19):** bech32 encoding of the x-only pubkey; `fetch --author`
  accepts npub or raw hex.
- **Transport:** synchronous WebSocket (`tungstenite`) over rustls with
  compiled-in webpki roots — works on a minimal deck image with no system CA
  store.

## Security notes

- Notes are **public and permanent** — relays and mirrors keep them. There is
  no delete, only a request (NIP-09, unimplemented) that relays may ignore.
- Posting reveals your pubkey and a timestamp. Timing correlation is a real
  metadata leak; content is signed but **not encrypted** (DMs are a different
  NIP, unimplemented).
- v0.1: text notes only — no follows, DMs, or reactions yet.

## See also

[keyring](keyring.md) · [workflows](workflows.md)
