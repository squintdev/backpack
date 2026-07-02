# veil

Encrypt and decrypt files with a **passphrase** or a recipient's **public key**.

## Usage

```text
veil enc [INPUT] [-o OUTPUT] [-r RECIPIENT_PUB]
veil dec [INPUT] [-o OUTPUT] [--identity NAME] [--keyring PATH]
```

`INPUT` omitted or `-` reads stdin; output omitted derives a name or writes
stdout.

### Passphrase mode

```sh
veil enc secret.pdf              # -> secret.pdf.veil  (prompts twice)
veil dec secret.pdf.veil         # -> secret.pdf
tar c dir | veil enc > d.veil    # encrypt a stream
veil dec d.veil | tar x          # decrypt a stream
```

Set `VEIL_PASSPHRASE` to supply the passphrase non-interactively (scripts/CI).

### Public-key mode

Encrypt to a [`keyring`](keyring.md) identity — no shared secret needed:

```sh
keyring export alice > alice.pub
veil enc -r alice.pub secret.pdf          # anyone can encrypt to alice
veil dec --identity alice secret.pdf.veil # only alice's key decrypts
```

`--identity` opens the keystore to fetch the private key; supply its passphrase
via `BACKPACK_PASSPHRASE` or the prompt. `--keyring` / `$BACKPACK_KEYRING`
override the keystore path.

## Output naming

- `enc`: `-o` if given, else `<input>.veil`, else stdout.
- `dec`: `-o` if given, else strip a `.veil` suffix, else (for a named input
  without `.veil`) error asking for `-o`; stdin goes to stdout.

Every file write goes to a temporary sibling and is atomically renamed on
success, so a wrong key or an interrupted run never leaves a truncated
destination file.

## How it works

`veil` is a thin CLI over [`bp-core`](bp-core.md):

| Command | Under the hood |
|---------|----------------|
| `enc` (passphrase) | `bp_core::seal` — Argon2id + ChaCha20-Poly1305, `VEIL1` format |
| `dec` (passphrase) | `bp_core::open` |
| `enc -r` | parse the `BPKEY1` line, `bp_core::seal_to_recipient` (X25519), `VEILX1` |
| `dec --identity` | open keystore, `bp_core::open_as_recipient` with the identity's X25519 key |

The mode is chosen by the flags: `-r` selects public-key encryption, `--identity`
selects public-key decryption; otherwise it is passphrase mode. The two formats
are distinguished on disk by their magic header (`VEIL1` vs `VEILX1`).

## Environment

| Variable | Used for |
|----------|----------|
| `VEIL_PASSPHRASE` | Passphrase mode, non-interactive |
| `BACKPACK_PASSPHRASE` | Keystore passphrase for `--identity` |
| `BACKPACK_KEYRING` | Keystore path for `--identity` |

## Security notes

- Passphrase strength determines passphrase-mode security. No forward secrecy:
  compromising the passphrase decrypts every file it protected.
- Public-key mode hides the sender (anonymous ephemeral sender) but provides **no
  sender authentication** — anyone can encrypt to a public key. Combine with a
  [`keyring`](keyring.md) signature if you need to prove authorship.
- File size is not hidden.
- v0.1, unaudited.

## See also

[bp-core](bp-core.md) · [keyring](keyring.md) · [workflows](workflows.md)
