# backpack (launcher)

The suite as **one TUI client** — the binary a cyberdeck boots into. Every tool
is a native screen inside the launcher: nothing shells out, nothing drops you
back to a bash prompt, and the keystore passphrase is entered in a masked
in-TUI prompt.

```sh
backpack
```

## Flow

1. **Unlock gate.** First screen is a masked passphrase prompt. On a first run
   it asks twice and creates the encrypted keystore; afterwards it unlocks the
   existing one. The store stays unlocked for the whole session, so no screen
   ever prompts again.
2. **Home.** The tool menu. `↑↓`/`jk` or `1`–`6` select, `Enter` opens,
   `!` drops to a real shell (exit to return), `q` quits.
3. **Tool screens.** Each tool is native — forms with `Tab`/`Enter` field
   navigation, `Esc` backs out one level. Slow operations (relay calls,
   Argon2) show a `WORKING…` overlay and return their results in-screen.

## Screens

| Screen | What it does |
|--------|--------------|
| IDENTITIES | List/generate/export/delete identities; shows fingerprint, public line, and npub. `c` copies the npub to the clipboard; `n` adds a Nostr key to a pre-Nostr identity. |
| NOSTR | TIMELINE (scrollable notes from everyone you follow, petname labels), POST (explicit *public + permanent* y/n confirm), FETCH (one author), FOLLOW/FOLLOWS (manage your relay-stored contact list; `d` unfollows with confirm, `c` copies an npub), WHOAMI (npub). Results scroll with `j/k`/PgUp/PgDn. |
| VEIL | Encrypt/decrypt with a passphrase or to/with an identity. Output names auto-derive; writes are atomic. |
| SCRUB | Scan a file, show exactly what metadata would be removed, then write a `.clean.` copy on confirm. |
| SPLIT | DEAL a secret file into k-of-n share files; COMBINE shares back (display or write to file). |
| SIGN/VERIFY | Sign a file with an identity (`<file>.sig`); verify anyone's signature from their `.pub` line. |

The standalone CLIs (`veil`, `scrub`, `split`, `keyring`, `nostr`) remain for
scripting and pipes — the launcher and the CLIs share the same libraries, so
behavior is identical.

## Console-friendly by design

Monochrome amber phosphor (truecolor `#FFB000` family) on the Linux framebuffer
console (no X/Wayland) or any terminal emulator — the bare VT approximates the
amber onto its 16-color palette (see [deploy.md](deploy.md) for retuning it).
Screens narrower than 80 columns collapse the banner to a one-line badge. Use a
console font with box-drawing glyphs (e.g. Terminus).

## Boot into it (cyberdeck)

Autologin on tty1, then `exec` the launcher from the shell profile:

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

`exec` replaces the shell, so quitting the launcher logs out and getty restarts
it — the deck always boots into the client. The `!` shell escape still works
inside.

## Security notes

- The keystore passphrase is held in memory (zeroized on drop) for the session
  so mutations can re-seal the store without re-prompting. Lock the deck when
  you walk away — quitting the launcher drops the key material.
- Masked fields never echo; the pty carries only `●` glyphs.

## Clipboard

Mouse-selecting text in a TUI drags in border glyphs and padding, so copyable
values have a key instead: `c` copies the npub (IDENTITIES) or the result
value — npub, event id — (NOSTR results) via **OSC 52**, which works in modern
terminal emulators and over SSH. The bare Linux VT has no clipboard; in tmux
enable `set -g set-clipboard on`.

## See also

[keyring](keyring.md) · [veil](veil.md) · [scrub](scrub.md) · [split](split.md) ·
[nostr](nostr.md) · [workflows](workflows.md) · [deploy](deploy.md)
