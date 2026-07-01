# Cipherpunk Tools — Initial Tool List

A suite of privacy, crypto, and sovereignty tools built in Rust. Shared crypto
core (`cph-core`) compiled to native + WASM so CLI, TUI, and web apps all reuse
one audited primitive layer.

**Stack:** Rust. Core library + CLI/TUI binaries + WASM-backed web apps in a
single cargo workspace.

**Goal:** Real daily-use tools, not toys. Real threat models, robust defaults.

---

## Tier 1 — Foundation (high use, bounded scope)

### 1. `veil` — File Encryptor (CLI + lib)
Encrypt/decrypt files with a passphrase or recipient public key. age-style UX,
streaming for large files, authenticated encryption (ChaCha20-Poly1305 +
Argon2id KDF).

- **Crates:** `age` or `chacha20poly1305` + `argon2`
- **User story:** *As a journalist, I want to encrypt a folder of source
  documents with a single passphrase before backing it up to cloud storage, so
  that even if the provider is breached the contents stay unreadable.*

### 2. `scrub` — Metadata Stripper (CLI)
Remove EXIF, PDF, and Office document metadata before sharing files. Batch mode,
dry-run preview of what would be removed.

- **Crates:** `img-parts`, `kamadak-exif`, `lopdf`
- **User story:** *As a whistleblower, I want to strip GPS coordinates and device
  serial numbers from a photo before I post it, so that the image cannot be
  traced back to my location or camera.*

### 3. `split` — Shamir Secret Sharing (CLI + lib)
Split a secret (seed phrase, master password) into N shares where any K recover
it. Print/export shares, reconstruct from a subset.

- **Crates:** `sharks` or `vsss-rs`
- **User story:** *As someone managing a crypto wallet, I want to split my seed
  phrase into 5 shares and give them to 5 trusted people, so that any 3 can
  recover my wallet if I die but no single person can steal it.*

---

## Tier 2 — Identity Layer

### 4. `keyring` — Keypair Manager (TUI)
Generate, store, sign, and verify with Ed25519 (signing) and X25519 (key
exchange) keys. Encrypted at rest. Web-of-trust view showing who signed whom.

- **Crates:** `ed25519-dalek`, `x25519-dalek`, `ratatui`
- **User story:** *As a developer, I want to manage my signing keys and see which
  of my contacts' keys are vouched for by people I already trust, so that I can
  decide whether to trust a new key without a central authority.*

### 5. `nostr-cli` — Nostr Client (CLI + TUI)
Post, read, and follow over the Nostr protocol — decentralized identity and
social with no central server. Reuses `keyring` keys as identity.

- **Crates:** `nostr-sdk`
- **User story:** *As a user who was deplatformed from a centralized social
  network, I want to publish notes signed by my own key across independent
  relays, so that no single company can silence or ban me.*

---

## Tier 3 — Verification / Anti-Surveillance

### 6. `canary` — Warrant Canary + Canary Tokens (CLI + web)
Publish signed, dated dead-man statements ("we have not received a warrant").
Generate tripwire tokens (unique URLs/files) that alert when accessed.

- **Reuses:** `keyring` signing
- **User story:** *As a service operator under a gag order I cannot legally
  confirm, I want to publish a signed statement that I stop updating if
  compromised, so that my users can infer trouble from its absence.*

### 7. `stamp` — Timestamp Proofs (CLI + lib)
Hash a file and commit the hash to a public timestamping authority / blockchain.
Later prove the file existed at time T without revealing its contents.

- **Crates:** `opentimestamps`
- **User story:** *As an inventor, I want to timestamp a design document without
  publishing it, so that I can later prove I created it on a specific date in a
  dispute over prior art.*

### 8. `vault-paste` — End-to-End Encrypted Pastebin (web app)
Paste text, encrypt in the browser (WASM built from `cph-core`), upload only
ciphertext, share a link with the key in the URL fragment. Burn-after-read.

- **Stack:** Rust WASM (`cph-core`) + TypeScript frontend + Axum backend
- **User story:** *As someone sending a password to a coworker, I want to share a
  self-destructing link where the server never sees the plaintext, so that the
  secret is exposed only once and to only the intended reader.*

---

## Shared Core

### `cph-core` — Crypto Primitives (lib, native + WASM)
Single audited home for AEAD, KDF, key types, encoding, and Shamir logic. Every
tool depends on it. Compiles to WASM for the web apps so browser and CLI run
identical crypto.

- **User story:** *As the maintainer of this suite, I want one crypto library
  that every tool shares, so that a fix or audit applies everywhere at once
  instead of being duplicated per tool.*

---

## Suggested Build Order
1. `cph-core` + `veil` together — proves lib → CLI → WASM pattern end to end.
2. `scrub`, `split` — bounded, immediately useful.
3. `keyring` — unlocks the identity layer.
4. Everything else builds on the above.
