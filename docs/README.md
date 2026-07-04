# backpack documentation

A suite of privacy, crypto, and sovereignty tools in Rust, sharing one audited
crypto core (`bp-core`).

## Components

| Tool | Kind | One-liner |
|------|------|-----------|
| [`bp-core`](bp-core.md) | library | Shared crypto primitives (KDF, AEAD stream, public-key sealing) |
| [`veil`](veil.md) | CLI | Encrypt/decrypt files with a passphrase **or** a public key |
| [`scrub`](scrub.md) | CLI | Strip identifying metadata (EXIF/GPS, XMP, PDF Info) before sharing |
| [`split`](split.md) | CLI | Shamir secret sharing: split a secret into `k`-of-`n` shares |
| [`keyring`](keyring.md) | CLI + TUI + lib | Manage Ed25519/X25519 identities in an encrypted store |
| [`canary`](canary.md) | CLI + lib | Warrant canaries: signed, expiring dead-man statements |
| [`stamp`](stamp.md) | CLI + lib | Timestamp proofs: Bitcoin-anchored via OpenTimestamps |
| [`sats`](sats.md) | CLI + lib | Thin Bitcoin client: HD addresses, balance, history, send |
| [`nostr`](nostr.md) | CLI | Publish/read Nostr notes with a keyring identity |
| [`backpack`](launcher.md) | TUI | The whole suite as one native TUI client (cyberdeck entry point) |

## How they fit together

`bp-core` is the foundation every other tool builds on. `keyring` holds the
identities; `veil` uses them to encrypt to a person instead of a passphrase, and
`nostr` publishes with them.
`scrub` and `split` are standalone but compose naturally in a share-a-secret or
publish-a-leak pipeline.

```
                 ┌───────────┐
                 │ bp-core  │  KDF · AEAD stream · X25519 seal
                 └─────┬─────┘
        ┌──────────────┼───────────────┬───────────────┐
        │              │               │               │
   ┌────▼───┐     ┌────▼───┐      ┌─────▼────┐    ┌──────▼─────┐
   │  veil  │◄────│keyring │      │  split   │    │   scrub    │
   │  enc/  │ x25519 pubkeys      │ deal/    │    │  strip     │
   │  dec   │     │identities│    │ combine  │    │  metadata  │
   └────────┘     └────────┘      └──────────┘    └────────────┘
```

See [workflows.md](workflows.md) for concrete end-to-end recipes that combine
the tools, and [deploy.md](deploy.md) for putting the suite on a Raspberry Pi
cyberdeck.

## Build

```sh
cargo build --release      # binaries in target/release/
cargo test                 # run the suite
```

## Status

v0.1, unaudited. Formats and APIs may change. Do not use for high-stakes
secrets yet.
