# backpack

A suite of privacy, crypto, and sovereignty tools built in Rust.

Every tool shares one audited crypto core (`bp-core`) so a fix or audit applies
everywhere at once. The core is native-first and WASM-ready, so CLI, TUI, and
future web apps run identical crypto.

See [`initial-tool-list.md`](initial-tool-list.md) for the full planned suite and
per-tool user stories, and [`docs/`](docs/README.md) for per-tool documentation
and cross-tool [workflows](docs/workflows.md).

> **Status:** v0.1, unaudited. Do not use for high-stakes secrets yet.

## Workspace layout

```
backpack/
├── Cargo.toml            cargo workspace
└── crates/
    ├── bp-core/         shared crypto primitives (lib)
    │   ├── kdf.rs        Argon2id passphrase → 32-byte key
    │   ├── stream.rs     chunked ChaCha20-Poly1305 (STREAM)
    │   └── error.rs      typed errors
    ├── veil/             file encryptor CLI
    ├── scrub/            metadata stripper CLI (lib + bin)
    ├── split/            Shamir secret sharing CLI (lib + bin)
    ├── keyring/          Ed25519/X25519/secp256k1 identity manager (lib + bin + TUI)
    ├── bp-nostr/         `nostr` minimal Nostr client (NIP-01)
    └── launcher/         `backpack` boot menu TUI (cyberdeck entry point)
```

## Build

```sh
cargo build --release      # binaries in target/release/
cargo test                 # run the test suite
```

Cross-compiling static ARM binaries for a Raspberry Pi cyberdeck is covered in
[docs/deploy.md](docs/deploy.md).

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

**Public-key mode** — encrypt to a `keyring` identity, no shared passphrase:

```sh
keyring export alice > alice.pub
veil enc -r alice.pub secret.pdf          # anyone can encrypt to alice
veil dec --identity alice secret.pdf.veil # only alice's key decrypts
```

Uses X25519 key agreement with a fresh ephemeral key per file (anonymous
sender), then the same ChaCha20-Poly1305 stream. `--identity` unlocks the
keystore (`$BACKPACK_PASSPHRASE` / prompt); `--keyring` / `$BACKPACK_KEYRING`
override its path.

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

### `keyring` — identity manager

Generate and manage signing/encryption identities. Each identity holds an
Ed25519 signing keypair and an X25519 key-agreement keypair. Private keys live
in a keystore that is **encrypted at rest** with `veil`'s crypto (`bp-core`):
the on-disk file is a `VEIL1` ciphertext sealed under a passphrase.

```sh
keyring gen --name alice
keyring list
keyring export alice > alice.pub          # share this public line
keyring sign --key alice msg.txt > msg.sig
keyring verify alice.pub msg.txt msg.sig  # no passphrase needed
```

Public identities and signatures are single-line, copy-pasteable text:

```text
BPKEY1 <name> <ed25519 pubkey hex> <x25519 pubkey hex>
BPSIG1 <ed25519 signature hex>
```

- Keystore defaults to `~/.config/backpack/keyring.veil`; override with
  `--keyring` or `$BACKPACK_KEYRING`. Set `$BACKPACK_PASSPHRASE` to skip
  prompts (scripts/CI).
- `verify` is stateless — it only needs the public line, message, and signature.
- The X25519 key is published in `export` to enable public-key file encryption
  (`veil` recipient mode) without regenerating identities.

An interactive terminal UI over the same store is available as `keyring-tui`
(browse, generate, export, delete). Run `keyring --help` for all CLI options.

### `nostr` — Nostr client

Publish and read notes on Nostr — decentralized, censorship-resistant
publishing — signed with a keyring identity's secp256k1 key (a third key each
identity carries; older identities upgrade with `keyring nostr-init NAME`).

```sh
nostr whoami --identity alice            # your npub
nostr post --identity alice "hello"      # publish to relays
nostr follow --identity alice npub1... --name fj
nostr timeline --identity alice          # notes from everyone you follow
nostr dms --identity alice               # read your encrypted DMs
```

Every fetched event is signature-verified before display. Relays come from
`-r`, `$BACKPACK_NOSTR_RELAYS`, or built-in defaults. See
[docs/nostr.md](docs/nostr.md).

### `backpack` — the TUI client

The suite as one full-screen client: the keystore unlocks via an in-TUI masked
prompt, and every tool — identities, nostr, veil, scrub, split, sign/verify —
is a native screen with forms and results panes. No shelling out. `!` drops to
a real shell when you need one. Designed as the auto-start entry point for a
terminal-only cyberdeck — amber phosphor monochrome, renders on the bare Linux
console. See [docs/launcher.md](docs/launcher.md) for keys and the
boot-at-login recipe.

## Cryptography

`bp-core` provides the shared primitives:

| Concern            | Choice                                                    |
|--------------------|-----------------------------------------------------------|
| Passphrase KDF     | Argon2id, 64 MiB memory, 3 passes, 16-byte random salt    |
| Public-key agreement | X25519 ECDH, ephemeral sender, HKDF-SHA256 to the key   |
| Encryption         | ChaCha20-Poly1305 AEAD, 64 KiB chunks                     |
| Chunk nonce        | 7-byte random prefix ‖ 4-byte counter ‖ 1-byte last-flag  |
| Key handling       | zeroized on drop                                          |

**Stream formats:**

```
passphrase:  MAGIC "VEIL1\n" (6)  ‖ salt (16)          ‖ prefix (7) ‖ chunks…
public key:  MAGIC "VEILX1\n" (7) ‖ ephemeral_pub (32) ‖ prefix (7) ‖ chunks…
```

Each chunk is `ciphertext ‖ Poly1305 tag (16)`. The per-chunk counter binds
ordering and the final-chunk flag binds end-of-stream, so **reordering or
truncating chunks fails authentication**. Fresh randomness per file (salt in
passphrase mode, ephemeral key in public-key mode) means encrypting the same
input twice yields different ciphertext. Public-key mode rejects low-order
recipient points (all-zero shared secret).

### Threat model

- **Protects:** confidentiality and integrity of file contents at rest against
  an attacker who holds the ciphertext but not the key. Public-key mode hides
  the sender's identity (anonymous ephemeral sender).
- **Does not protect:** file size (leaked), file metadata (use `scrub`), or
  against a weak passphrase. No forward secrecy in passphrase mode; no sender
  authentication in public-key mode (anyone can encrypt to a public key).

## License

MIT OR Apache-2.0
