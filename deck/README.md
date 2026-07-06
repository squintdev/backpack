# deck/ — Raspberry Pi cyberdeck image

Scripts that turn a Raspberry Pi + SD card into a terminal-only Arch Linux
ARM machine that boots straight into backpack.

## Build the SD card (on any Linux host)

```sh
sudo ./build-sd.sh /dev/sdX rpi-aarch64   # Pi 3/4/5
```

Partitions the card, extracts the official Arch Linux ARM rootfs, sets up
tty1 autologin that `exec`s into backpack, and drops `install-backpack.sh`
into the home directory.

## First boot on the Pi

1. Boot lands in a shell (backpack isn't installed yet).
2. Get networking up, then:
   ```sh
   sudo ./install-backpack.sh          # prebuilt static binaries (fast)
   sudo ./install-backpack.sh --source # or build from source (~30+ min)
   ```
3. Reboot — the deck now boots into the backpack TUI. Quitting it logs out
   and getty restarts it. `!` inside backpack opens a real shell.

Prebuilt binaries come from this repo's GitHub Releases (built by CI as
static musl binaries for aarch64, armv7, x86_64 on every `v*` tag).

## Carrying your identity on a USB drive

On your main machine:

- TUI: IDENTITIES → `u` → destination `/media/usb/keyring.veil` + a
  passphrase for the USB store (created if missing, verified after write)
- CLI: `keyring transfer NAME --to /media/usb/keyring.veil`

The USB file is a complete, self-contained backpack keystore — encrypted
with Argon2id + ChaCha20-Poly1305 under its own passphrase. The filesystem
(FAT32 is fine) doesn't matter; the encryption travels with the file.

On the deck:

```sh
mount /dev/sda1 /mnt
backpack --keyring /mnt/keyring.veil
```

The identity is used **in place** — nothing is copied to the Pi. Unplug the
USB and no key material remains on the deck. The unlock screen always shows
which keystore file it is opening.

Threat note: whoever finds the USB gets unlimited offline guesses against
the passphrase. Argon2id makes each guess slow (64 MiB, 3 passes), but only
a strong passphrase makes that matter.
