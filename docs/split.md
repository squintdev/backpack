# split

Shamir secret sharing. Split a secret into `n` shares where any `k` reconstruct
it and any `k − 1` reveal nothing. For backups, inheritance, and multi-party
recovery keys.

## Usage

```text
split deal    -k K -n N [--input FILE] [--out-dir DIR]
split combine [SHARE_FILES...] [-o OUTPUT]
```

```sh
printf 'master password' | split deal -k 3 -n 5      # 5 shares to stdout
split deal -k 2 -n 3 --input seed.txt --out-dir shares/
split combine share-01.txt share-03.txt share-05.txt # -> secret to stdout
cat shares/*.txt | split combine
```

- `deal` reads the secret from `--input` or stdin; writes shares to stdout, or
  as `share-NN.txt` files under `--out-dir`.
- `combine` reads shares from the given files or from stdin; writes the secret
  to stdout or `--output`. It keeps only lines beginning with `SPLIT1` (so blank
  lines and comments are ignored) and deduplicates by share index.
- Requires `2 ≤ k ≤ n ≤ 255`. A threshold of `k = 1` is rejected (no
  protection).

## Share format

Each share is one copy-pasteable line:

```text
SPLIT1-<k>-<index>-<hex share bytes>-<hex checksum>
```

## How it works

`split` is a library (`deal` / `combine`) plus a thin CLI, built on the `sharks`
crate for the GF(256) Shamir math. On top of the raw math it adds two integrity
layers, because **plain Shamir silently returns garbage** for wrong or
insufficient shares:

1. **Recovery verification.** A 4-byte digest of the secret is appended to the
   secret and the combined payload (`secret ‖ digest`) is what gets split. The
   digest is therefore only recoverable with `k` valid shares — it is never
   exposed in an individual share. On `combine`, a digest mismatch means the
   shares are wrong or insufficient, and the tool errors instead of returning
   garbage.

2. **Per-share checksum.** Each share string carries a 2-byte checksum over its
   contents, so a mistyped or corrupted share is caught on parse, before
   reconstruction is attempted.

## Security notes

- Any `k` shares reveal the secret **in full** — store them separately and with
  different custodians.
- Fewer than `k` shares reveal nothing about the secret.
- The 4-byte digest is a low-probability integrity check, not a MAC; it is there
  to catch honest mistakes (wrong/insufficient shares), not to resist a
  motivated forger crafting shares.
- v0.1.

## See also

[workflows](workflows.md) — e.g. split a `keyring` passphrase across trustees.
