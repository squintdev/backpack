# keyring

Manage signing/encryption identities. Each identity holds an **Ed25519** signing
keypair and an **X25519** key-agreement keypair. Private keys live in a keystore
that is encrypted at rest under a passphrase.

`keyring` is a library (used by [`veil`](veil.md)), a CLI, and a terminal UI
(`keyring-tui`).

## Usage

```text
keyring [--keyring PATH] <command>

  gen --name NAME            Generate a new identity
  list                       List identities and fingerprints
  export NAME                Print an identity's public line (share this)
  rm NAME                    Delete an identity
  sign --key NAME [INPUT]    Sign a file (or stdin); prints a BPSIG1 line
  verify PUBFILE MSG SIGFILE Verify a signature (no passphrase needed)
```

```sh
keyring gen --name alice
keyring list
keyring export alice > alice.pub
keyring sign --key alice msg.txt > msg.sig
keyring verify alice.pub msg.txt msg.sig
```

## Keystore

- Default path `~/.config/backpack/keyring.veil`; override with `--keyring` or
  `$BACKPACK_KEYRING`.
- Encrypted at rest by sealing the whole store with [`bp-core`](bp-core.md)
  (`seal`/`open`, i.e. the same Argon2id + ChaCha20-Poly1305 as `veil`). The
  on-disk file is a `VEIL1` ciphertext — no plaintext key material or even
  identity names.
- Unlock passphrase comes from `$BACKPACK_PASSPHRASE` or the prompt (entered
  twice when the store is first created).

Operations that touch private keys (`gen`, `list`, `export`, `rm`, `sign`)
unlock the store. **`verify` is stateless** — it needs only the public line,
message, and signature, so it requires no passphrase.

## Terminal UI

`keyring-tui` is an interactive front-end over the same keystore:

```sh
keyring-tui        # unlock, then browse identities
```

It unlocks the store in the normal terminal (passphrase prompt or
`$BACKPACK_PASSPHRASE`), then shows a two-pane view: the identity list on the
left, details (fingerprint + public line) on the right.

| Key | Action |
|-----|--------|
| `j` / `k`, ↑ / ↓ | Move selection |
| `g` | Generate a new identity (type a name, Enter) |
| `e` | Export the selected identity to `<name>.pub` |
| `d` | Delete the selected identity (confirm `y`/`n`) |
| `q` / Esc | Quit |

Mutations are saved to the encrypted store immediately. Signing and verification
stay in the CLI.

## Wire formats

Public identities and signatures are single-line, copy-pasteable text:

```text
BPKEY1 <name> <ed25519 pubkey hex> <x25519 pubkey hex>
BPSIG1 <ed25519 signature hex>
```

A **fingerprint** (shown by `list` / `verify`) is the first 8 bytes of
SHA-256(ed25519 pubkey), grouped as `xxxx-xxxx-xxxx-xxxx`.

## How it works

- **Generation** draws 32 random bytes each for the Ed25519 seed and the X25519
  secret from the OS CSPRNG.
- **Signing** uses Ed25519 over the raw message bytes.
- **Verification** checks the Ed25519 signature against the public line's key.
- The **X25519 public key** is published in `export` so [`veil`](veil.md) can
  encrypt to the identity without regenerating keys. The X25519 **secret** is
  surfaced to `veil` (`--identity`) for public-key decryption.
- Secret key material is wrapped in `Zeroizing` and wiped on drop.

## Security notes

- The keystore is only as strong as its passphrase (Argon2id slows brute force,
  but a weak passphrase is still weak).
- Anyone with a public line can encrypt to you and verify your signatures — that
  is the point; publish it freely.
- Web-of-trust / contact management are planned; this pass is the lib, CLI, and
  a browse/generate/delete/export TUI.
- v0.1.

## See also

[bp-core](bp-core.md) · [veil](veil.md) · [workflows](workflows.md)
