# Workflows

How the cipherpunk tools combine. Each recipe chains standalone commands; the
tools share formats and (for `veil` + `keyring`) an identity model.

## 1. Send a file to a person (no shared secret)

The identity layer paying off: `keyring` holds the keys, `veil` uses them.

```sh
# Recipient, once:
keyring gen --name alice
keyring export alice > alice.pub      # share alice.pub publicly

# Sender (only needs alice.pub):
veil enc -r alice.pub report.pdf      # -> report.pdf.veil

# Recipient:
veil dec --identity alice report.pdf.veil   # -> report.pdf
```

No passphrase is exchanged. Anyone with `alice.pub` can encrypt to alice; only
alice's stored key decrypts. See [veil](veil.md), [keyring](keyring.md).

## 2. Publish a leak safely (strip metadata, then encrypt)

```sh
scrub -n photo.jpg                    # preview: does it carry GPS?
scrub photo.jpg                       # -> photo.clean.jpg (no EXIF/GPS)
veil enc -r journalist.pub photo.clean.jpg
```

`scrub` removes the location and device fingerprints; `veil` protects the
contents in transit. Order matters — scrub **before** encrypting, since you
can't scrub ciphertext.

## 3. Prove authorship of an encrypted file

Public-key `veil` hides the sender but does **not** authenticate them. Add a
signature when the recipient must know it was really you:

```sh
keyring sign --key me report.pdf > report.sig     # detached signature
veil enc -r alice.pub report.pdf                  # confidential to alice
# send report.pdf.veil + report.sig + your me.pub

# Alice:
veil dec --identity alice report.pdf.veil -o report.pdf
keyring verify me.pub report.pdf report.sig       # confirms you signed it
```

## 4. Back up a secret across several people

Split a high-value secret so no single person (or single lost drive) can expose
or destroy it.

```sh
# Split a wallet seed 3-of-5:
split deal -k 3 -n 5 --input seed.txt --out-dir shares/
#   hand share-01.txt … share-05.txt to five custodians

# Any three can recover it later:
split combine shares/share-01.txt shares/share-03.txt shares/share-05.txt > seed.txt
```

Wrong or insufficient shares are detected and rejected, not silently mis-recovered.
See [split](split.md).

## 5. Protect the keyring passphrase itself

The keystore is encrypted under one passphrase — a single point of failure for
your whole identity. Split that passphrase so recovery needs a quorum:

```sh
printf 'my keystore passphrase' | split deal -k 2 -n 3 --out-dir keyring-shares/
# store the three shares in three separate places

# To reconstruct when needed:
cat keyring-shares/*.txt | split combine
#   feed the result to CIPHERPUNK_PASSPHRASE / the keyring prompt
```

## 6. Encrypt-at-rest backup with a passphrase

No identities involved — just a strong passphrase:

```sh
tar c ~/documents | veil enc > documents.veil     # prompts (twice)
veil dec documents.veil | tar x                    # restore
```

For scripts, set `VEIL_PASSPHRASE`.

---

## How the pieces relate

- **`cph-core`** is the crypto every tool shares (KDF, AEAD stream, X25519
  seal). `veil` and `keyring` both call it directly.
- **`keyring` → `veil`.** `keyring export` produces the public line `veil enc -r`
  consumes; `veil dec --identity` reads the private key back out of the keystore.
- **`keyring` uses `veil`'s crypto for itself.** The keystore file is a `veil`
  (`cph-core`) ciphertext.
- **`scrub` and `split`** are self-contained but slot into pipelines: scrub
  before you encrypt/publish; split around any secret, including a `veil` or
  `keyring` passphrase.

See each tool's page for details: [cph-core](cph-core.md) · [veil](veil.md) ·
[scrub](scrub.md) · [split](split.md) · [keyring](keyring.md).
