# nostr

Publish and read [Nostr](https://nostr.com) notes with a backpack keyring
identity. Nostr is a decentralized publishing protocol: notes are signed by
your key and mirrored across independent relays, so no company can silence the
key. `nostr` is a minimal, synchronous NIP-01 client — no daemon, no async
runtime.

## Usage

```text
nostr whoami   --identity NAME              # your npub + hex pubkey
nostr post     --identity NAME "text"       # sign + publish a text note
nostr fetch    --author <npub|hex> [--limit N]
nostr follow   --identity NAME <npub|hex> [--name petname]
nostr unfollow --identity NAME <npub|hex>
nostr follows  --identity NAME              # who you follow
nostr timeline --identity NAME [--limit N]  # notes from everyone you follow
nostr profile  --identity NAME | --author <npub|hex>
nostr set-profile --identity NAME [--name N] [--about A] [--picture URL] [--nip05 ID]
nostr dm      --identity NAME <npub|hex> "text"   # send an encrypted DM
nostr dms     --identity NAME [--limit N]         # read your DMs
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

## Follows and the timeline (NIP-02)

Your follow list is a **kind-3 contact list stored on the relays**, not on
disk — portable across devices, replaceable by design. Because publishing a
kind-3 replaces the whole list, `follow`/`unfollow` always fetch the newest
list from **all** relays first (freshest `created_at` wins), merge the change,
then publish the update — never a blind write.

`timeline` resolves your follows, then queries all relays in parallel for
their recent notes, merged, deduplicated by event id, newest first, every
signature verified. Petnames (from `--name`) label authors in the output.

## Profiles (kind-0)

A profile is a replaceable kind-0 event whose content is a JSON object
(`name`, `about`, `picture`, `nip05`, …). Pictures are **URLs to ordinary web
hosting** — only the metadata lives on relays. `nip05` is DNS-based
verification: clients check `https://<domain>/.well-known/nostr.json`.

`set-profile` edits are **merge-safe**: the newest kind-0 is fetched from all
relays and only the flags you pass change — fields written by other clients
(banner, lud16, website, …) are preserved verbatim; passing an empty string
clears a field. The timeline labels authors by your petname first, then their
profile `name`, then a pubkey prefix.

## Direct messages (NIP-04)

`dm` sends an encrypted kind-4 message; `dms` fetches and decrypts your inbox
(both directions), labeling partners by profile name. Encryption is ECDH over
secp256k1 → AES-256-CBC, so only you and the other party can read the text.

**NIP-04 leaks metadata by design and is deprecated upstream.** The *content*
is private, but the fact that you and a given pubkey exchanged a message, when,
and roughly how long it was, are public relay data visible to anyone. It is
implemented here because verification services and most clients still use it;
NIP-17 gift-wrapped DMs (which hide metadata) can be added alongside later. Do
not treat NIP-04 as private communication against a network observer.

## Security notes

- Notes are **public and permanent** — relays and mirrors keep them. There is
  no delete, only a request (NIP-09, unimplemented) that relays may ignore.
- Posting reveals your pubkey and a timestamp. Timing correlation is a real
  metadata leak; content is signed but **not encrypted** (DMs are a different
  NIP, unimplemented).
- v0.1: text notes, follows, profiles, and NIP-04 direct messages — no reactions or NIP-17 private DMs yet.

## See also

[keyring](keyring.md) · [workflows](workflows.md)
