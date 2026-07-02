# bp-core

Shared crypto primitives for the backpack suite. Every tool depends on this
crate so that one audited layer of key derivation, authenticated encryption, and
stream framing is reused everywhere instead of duplicated.

`bp-core` is a library, not a binary. It is native-first and WASM-ready.

## Modules

| Module | Purpose |
|--------|---------|
| `kdf` | Argon2id passphrase → 32-byte key |
| `stream` | Chunked ChaCha20-Poly1305 authenticated streaming |
| `pubkey` | X25519 public-key file sealing (anonymous sender) |
| `error` | Typed error enum shared across the crate |

## Public API

```rust
// Passphrase mode
bp_core::seal(&mut reader, &mut writer, passphrase)?;   // -> VEIL1 stream
bp_core::open(&mut reader, &mut writer, passphrase)?;

// Raw-key mode (caller supplies a 32-byte key, provides its own header)
bp_core::seal_with_key(&mut reader, &mut writer, &key32)?;
bp_core::open_with_key(&mut reader, &mut writer, &key32)?;

// Public-key mode (X25519)
bp_core::seal_to_recipient(&mut reader, &mut writer, &recipient_x_pub)?;  // -> VEILX1
bp_core::open_as_recipient(&mut reader, &mut writer, &recipient_x_sk)?;
```

All functions stream: they take `Read`/`Write` and never buffer the whole input
in memory.

## How it works

### Key derivation (`kdf`)

`derive_key(passphrase, salt)` runs **Argon2id** (64 MiB memory, 3 passes,
16-byte salt) to produce a 32-byte key. The result is wrapped in `Zeroizing` so
it is wiped from memory on drop.

### Authenticated stream (`stream`)

The plaintext is split into 64 KiB chunks. Each chunk is sealed with
ChaCha20-Poly1305 under a per-chunk nonce:

```
nonce (12 bytes) = prefix (7) ‖ counter_be_u32 (4) ‖ last_flag (1)
```

- The **counter** binds chunk order — reordering chunks breaks authentication.
- The **last-flag** binds end-of-stream — truncating the file breaks
  authentication.

Two framings share this machinery:

```
passphrase:  MAGIC "VEIL1\n" (6)  ‖ salt (16)          ‖ prefix (7) ‖ chunk_0 … chunk_n
public key:  MAGIC "VEILX1\n" (7) ‖ ephemeral_pub (32) ‖ prefix (7) ‖ chunk_0 … chunk_n
```

Each `chunk_i` is `ciphertext ‖ Poly1305 tag (16)`. A read-ahead of one chunk
lets the encoder flag the final chunk correctly even when the plaintext length
is an exact multiple of the chunk size.

### Public-key sealing (`pubkey`)

`seal_to_recipient` implements anonymous-sender public-key encryption
(sealed-box style):

1. Generate a fresh **ephemeral** X25519 keypair.
2. `shared = X25519(ephemeral_sk, recipient_pub)`. Reject low-order recipient
   points (all-zero shared secret).
3. `key = HKDF-SHA256(ikm = shared, info = ephemeral_pub ‖ recipient_pub)`.
4. Write `VEILX1 ‖ ephemeral_pub`, then `seal_with_key` the body.

`open_as_recipient` recomputes the same `shared` from
`X25519(recipient_sk, ephemeral_pub)` and decrypts.

Because the sender key is ephemeral and never stored, the sender is anonymous
and each file encrypts to different ciphertext.

## Security properties

- Confidentiality + integrity of the payload against anyone without the key.
- Tamper / truncation / reorder detection via the AEAD + nonce construction.
- Fresh randomness per file (salt or ephemeral key) → no deterministic
  ciphertext.
- Keys zeroized on drop.

**Not provided:** file-size hiding, forward secrecy (passphrase mode), or sender
authentication (public-key mode — anyone can encrypt to a public key).

## Used by

[`veil`](veil.md) (all modes) and [`keyring`](keyring.md) (encrypts its keystore
at rest with `seal`/`open`).
