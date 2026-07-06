# Deploying to a cyberdeck (Raspberry Pi)

The suite is Rust throughout (the one exception: `nostr`'s TLS pulls in
`ring`, which contains assembly — it cross-compiles to ARM musl fine with the
same C toolchain the linker already needs). Everything builds to a handful of
static binaries you copy onto any minimal ARM Linux. No package
manager, no shared libraries, no display server — the TUIs run on the bare
framebuffer console.

## 1. Build for the Pi

Pick the target for your board and OS:

| Board / OS | Target |
|---|---|
| Pi 3/4/5, 64-bit OS | `aarch64-unknown-linux-musl` |
| Pi 2 / Zero 2, 32-bit OS | `armv7-unknown-linux-musleabihf` |

**Option A — `cross` (easiest, needs Docker/Podman):**

```sh
cargo install cross
cross build --release --target aarch64-unknown-linux-musl
```

**Option B — host toolchain:**

```sh
rustup target add aarch64-unknown-linux-musl
# linker: Arch `pacman -S aarch64-linux-gnu-gcc`,
#         Debian/Ubuntu `apt install gcc-aarch64-linux-gnu`
cargo build --release --target aarch64-unknown-linux-musl
```

`.cargo/config.toml` already selects the cross-linker and `+crt-static`, and the
release profile is tuned for the deck (thin LTO, stripped, `panic=abort`).
Expected output: ten binaries (backpack, veil, scrub, split, keyring,
keyring-tui, nostr, canary, stamp, sats), under 25 MB total.

Note: `sats` compiles libsecp256k1 (C), so cross-builds need an ARM C
cross-compiler in addition to the Rust target — e.g. the
`aarch64-linux-musl-cross` toolchain (or `zig cc`). Set
`CC_aarch64_unknown_linux_musl=aarch64-linux-musl-gcc` if cargo does not
find it on its own.

> Musl static builds have not been run on real Pi hardware yet — the dependency
> tree is pure Rust so they are expected to work, but verify on your board.

## 2. Install on the deck

```sh
# from the build machine
scp target/aarch64-unknown-linux-musl/release/{backpack,veil,scrub,split,keyring,keyring-tui,nostr,canary,stamp,sats} \
    deck@pi:/opt/backpack/
```

Keep all six in **one directory** — the launcher resolves the tools as siblings
of its own binary, so no PATH setup is needed. Add `/opt/backpack` to PATH
anyway if you want the tools from a shell.

## 3. Boot straight into the suite

Autologin on tty1, then `exec` the launcher from the shell profile (see
[launcher.md](launcher.md) for details):

```ini
# /etc/systemd/system/getty@tty1.service.d/autologin.conf
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin deck --noclear %I $TERM
```

```sh
# ~deck/.profile
if [ "$(tty)" = "/dev/tty1" ]; then
    exec /opt/backpack/backpack
fi
```

Quitting the launcher ends the session; getty logs back in and restarts it. The
`!` key inside the launcher still gives you a real shell when you need one.

## 4. Console niceties

- **Font:** install `terminus-font` and set e.g. `ter-v16n` in
  `/etc/vconsole.conf` — the TUIs use box-drawing and block glyphs.
- **Colors:** the TUIs use truecolor amber (#FFB000 family). The bare Linux VT
  approximates RGB onto its 16-color palette; for authentic amber, retune the
  console palette (kernel param `vt.default_red/grn/blu` or an escape sequence
  in the profile) or run a truecolor terminal (kmscon/fbterm/foot).
- **Keystore:** lives at `~/.config/backpack/keyring.veil` for the autologin
  user; override with `BACKPACK_KEYRING` if you keep it on removable media.

## Performance notes (Argon2)

Keystore/passphrase unlocks run Argon2id at 64 MiB / 3 passes:

| Board | Unlock feel |
|---|---|
| Pi 5 / Pi 4 | well under a second |
| Pi 3 | ~1s |
| Pi Zero 2 (512 MB) | a few seconds; fine, but leave headroom — the KDF wants 64 MiB free |

These parameters are compile-time constants in `bp-core::kdf`; lower `M_COST_KIB`
if you target very small boards (that weakens brute-force resistance — see the
threat model in the [README](../README.md)).

## Prebuilt binaries & the deck scripts

CI builds static musl binaries (aarch64, armv7, x86_64) on every `v*` tag —
see GitHub Releases. `deck/build-sd.sh` assembles a boot-into-backpack Arch
Linux ARM SD card and `deck/install-backpack.sh` installs the latest release
(or builds from source) — see [../deck/README.md](../deck/README.md).
