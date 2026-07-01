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
    ├── veil/             file encryptor CLI
    ├── scrub/            metadata stripper CLI (lib + bin)
    └── split/            Shamir secret sharing CLI (lib + bin)
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

### `scrub` — metadata stripper

Remove identifying metadata (EXIF/GPS, XMP, IPTC, PDF Info) before sharing files.

```sh
scrub photo.jpg              # -> photo.clean.jpg (original kept)
scrub -n leak.pdf            # dry run: list what would be removed
scrub -i a.jpg b.png         # overwrite in place
scrub doc.pdf -o clean.pdf   # explicit output name
```

- Supported: **JPEG, PNG, PDF** (detected by content, not extension). Others are
  reported and skipped.
- Removes container metadata while keeping rendering data (ICC color profiles,
  gamma). Does **not** touch watermarks or data embedded in the pixels/text.
- Default writes `<name>.clean.<ext>` and keeps the original; `-i` overwrites in
  place via atomic rename.

Run `scrub --help` for all options.

### `split` — Shamir secret sharing

Split a secret into `n` shares where any `k` reconstruct it and any `k - 1`
reveal nothing. For backups, inheritance, and multi-party recovery keys.

```sh
printf 'master password' | split deal -k 3 -n 5      # 5 shares to stdout
split deal -k 2 -n 3 --input seed.txt --out-dir shares/
split combine share-01.txt share-03.txt share-05.txt # -> secret to stdout
cat shares/*.txt | split combine
```

Each share is one copy-pasteable line:

```text
SPLIT1-<k>-<index>-<hex share bytes>-<hex checksum>
```

- **Integrity, not just math:** a digest of the secret is split *with* it, so
  wrong or insufficient shares are reported as an error instead of silently
  returning garbage (plain Shamir cannot tell). A per-share checksum catches
  typos before reconstruction.
- Threshold `k = 1` is rejected (no protection). Any `k` shares reveal the
  secret in full — store them separately.

Run `split --help` for all options.

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
