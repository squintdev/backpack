# cipherpunk documentation

A suite of privacy, crypto, and sovereignty tools in Rust, sharing one audited
crypto core (`cph-core`).

## Components

| Tool | Kind | One-liner |
|------|------|-----------|
| [`cph-core`](cph-core.md) | library | Shared crypto primitives (KDF, AEAD stream, public-key sealing) |
| [`veil`](veil.md) | CLI | Encrypt/decrypt files with a passphrase **or** a public key |
| [`scrub`](scrub.md) | CLI | Strip identifying metadata (EXIF/GPS, XMP, PDF Info) before sharing |
| [`split`](split.md) | CLI | Shamir secret sharing: split a secret into `k`-of-`n` shares |
| [`keyring`](keyring.md) | CLI + lib | Manage Ed25519/X25519 identities in an encrypted store |

## How they fit together

`cph-core` is the foundation every other tool builds on. `keyring` holds the
identities; `veil` uses them to encrypt to a person instead of a passphrase.
`scrub` and `split` are standalone but compose naturally in a share-a-secret or
publish-a-leak pipeline.

```
                 ┌───────────┐
                 │ cph-core  │  KDF · AEAD stream · X25519 seal
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
the tools.

## Build

```sh
cargo build --release      # binaries in target/release/
cargo test                 # run the suite
```

## Status

v0.1, unaudited. Formats and APIs may change. Do not use for high-stakes
secrets yet.
