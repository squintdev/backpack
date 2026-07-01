# cipherpunk

A suite of privacy, crypto, and sovereignty tools built in Rust.

Every tool shares one audited crypto core (`cph-core`) so a fix or audit applies
everywhere at once. The core is native-first and WASM-ready, so CLI, TUI, and
future web apps run identical crypto.

See [`initial-tool-list.md`](initial-tool-list.md) for the full planned suite and
per-tool user stories.

> **Status:** v0.1, unaudited. Do not use for high-stakes secrets yet.

## Workspace layout

```
cipherpunk/
├── Cargo.toml            cargo workspace
└── crates/
    ├── cph-core/         shared crypto primitives (lib)
    │   ├── kdf.rs        Argon2id passphrase → 32-byte key
    │   ├── stream.rs     chunked ChaCha20-Poly1305 (STREAM)
    │   └── error.rs      typed errors
    └── veil/             file encryptor CLI
```

## Build

```sh
cargo build --release      # binaries in target/release/
cargo test                 # run the test suite
```

## Tools

### `veil` — file encryptor

Encrypt and decrypt files with a passphrase.

```sh
veil enc secret.pdf              # -> secret.pdf.veil
veil dec secret.pdf.veil         # -> secret.pdf
veil enc notes.txt -o n.bin      # explicit output name
tar c dir | veil enc > d.veil    # encrypt a stream
veil dec d.veil | tar x          # decrypt a stream
```

- Passphrase is prompted on the terminal (twice, to confirm, when encrypting).
- Set `VEIL_PASSPHRASE` to supply it non-interactively for scripts/CI.
- File output is written to a temp sibling and atomically renamed on success,
  so a wrong passphrase or error never leaves a truncated file.

Run `veil --help` for all options.

## Cryptography

`cph-core` provides the shared primitives:

| Concern            | Choice                                                    |
|--------------------|-----------------------------------------------------------|
| Key derivation     | Argon2id, 64 MiB memory, 3 passes, 16-byte random salt    |
| Encryption         | ChaCha20-Poly1305 AEAD, 64 KiB chunks                     |
| Chunk nonce        | 7-byte random prefix ‖ 4-byte counter ‖ 1-byte last-flag  |
| Key handling       | zeroized on drop                                          |

**Stream format** (`veil` files):

```
MAGIC "VEIL1\n" (6) ‖ salt (16) ‖ prefix (7) ‖ chunk_0 ‖ chunk_1 ‖ … ‖ chunk_n
```

Each chunk is `ciphertext ‖ Poly1305 tag (16)`. The per-chunk counter binds
ordering and the final-chunk flag binds end-of-stream, so **reordering or
truncating chunks fails authentication**. A fresh random salt and nonce prefix
per file means encrypting the same input twice yields different ciphertext.

### Threat model

- **Protects:** confidentiality and integrity of file contents at rest against
  an attacker who holds the ciphertext but not the passphrase.
- **Does not protect:** file size (leaked), file metadata (use `scrub`, planned),
  or against a weak passphrase. No forward secrecy; passphrase compromise
  decrypts all files it protected.

## License

MIT OR Apache-2.0
