# backpack (launcher)

The boot menu for the suite — the binary a cyberdeck starts at login. A
full-screen amber-phosphor menu that launches the suite's tools and takes the
terminal back when they exit.

```sh
backpack
```

## Keys

| Key | Action |
|-----|--------|
| `↑↓` / `jk` | Move selection |
| `1`–`5` | Jump straight to a tool |
| `Enter` | Launch the selected tool |
| `!` | Drop to a shell (`$SHELL`, exit to return) |
| `q` / Esc | Quit |

## How launching works

Two kinds of tools:

- **Interactive (KEYRING)** — the tty is handed over to `keyring-tui` directly;
  when it exits, the menu resumes.
- **CLI (VEIL / SCRUB / SPLIT / SIGN-VERIFY)** — `Enter` opens an argument
  prompt in the detail pane (with examples above it). The command runs in the
  normal terminal in cooked mode, so the tool's own prompts (passphrases) work.
  Any key returns to the menu; the last command and its exit status stay visible
  in the detail pane.

Commands run through `sh -c`, so quoting and globs behave like a shell.

Suite binaries are resolved as **siblings of the launcher executable** first
(the deploy layout: all binaries in one directory), falling back to `$PATH`.

## Console-friendly by design

The UI is monochrome amber phosphor (truecolor #FFB000 family) and runs on the
Linux framebuffer console (no X/Wayland) as well as desktop emulators — the
bare VT approximates the amber onto its 16-color palette (see
[deploy.md](deploy.md) for retuning it). On screens
narrower than 80 columns the ASCII banner collapses to a one-line badge. Use a
console font with box-drawing glyphs (e.g. Terminus) for best results.

## Boot into it (cyberdeck)

Autologin on tty1 + start from the shell profile. With systemd:

```ini
# /etc/systemd/system/getty@tty1.service.d/autologin.conf
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin deck --noclear %I $TERM
```

```sh
# ~deck/.profile (or .bash_profile)
if [ "$(tty)" = "/dev/tty1" ]; then
    exec backpack
fi
```

`exec` replaces the shell, so quitting the launcher logs out and getty restarts
it — the deck always boots into the menu. (The `!` shell escape still works
inside the launcher.)

## See also

[keyring](keyring.md) · [veil](veil.md) · [scrub](scrub.md) · [split](split.md) ·
[workflows](workflows.md)
