# MyUbuntu

Idempotent, resumable setup for a Linux pentest workstation — one Python file, no
dependencies beyond a stock Ubuntu install.

```bash
git clone https://github.com/j0yb0y-m/myubuntu.git ~/tools/myubuntu
python3 ~/tools/myubuntu/myubuntu.py --dry-run
python3 ~/tools/myubuntu/myubuntu.py
```

Re-running is always safe: finished steps are recorded and skipped, and downloads
resume instead of starting over.

## Requirements

- Ubuntu (or a close Debian derivative) on x86-64
- Python 3.10+ (the archive's `python3` is fine)
- `sudo` access — run as your normal user, **not** as root
- Disk: ~5 GB for a base install, ~20 GB with wordlists and every toolchain

Start with `--dry-run` if you want to see the plan before anything is touched.

## Usage

```bash
python3 myubuntu.py                  # everything
python3 myubuntu.py --dry-run        # show the plan, change nothing
python3 myubuntu.py --list           # list profiles and steps
python3 myubuntu.py --update         # update the system and installed tools
python3 myubuntu.py --only recon ad  # just these profiles
python3 myubuntu.py --skip wordlists metasploit
python3 myubuntu.py --step searchsploit john
python3 myubuntu.py --log-level DEBUG
python3 myubuntu.py --quiet
```

Ctrl+C is safe: the running command's process group is stopped, state is saved, and
a re-run picks up where you left off. A second Ctrl+C force-quits.

## Profiles

| Profile | What it installs |
| --- | --- |
| `base` | Core packages, GPU support, containers, virtualization, system tweaks, verification |
| `languages` | Go and Rust toolchains |
| `sec-tools` | Wireshark, nmap, hashcat, aircrack-ng, mitmproxy, binwalk, radare2, … |
| `net-tools` | bettercap, hostapd, nftables, ethtool, dnsutils, sslscan |
| `recon` | nuclei, subfinder, httpx, ffuf, gobuster, amass, katana, feroxbuster, theHarvester |
| `ad` | ldap-utils, smbclient, samba-common-bin, krb5-user |
| `exploits` | Exploit-DB + searchsploit, LinPEAS, WinPEAS |
| `re` | yara, radare2 helpers, gdb-multiarch, ltrace, upx, John the Ripper |
| `firmware` | flashrom, OpenOCD, QEMU for ARM/MISC, OVMF, squashfs-tools |
| `metasploit` | Metasploit Framework |
| `traffic` | Caido and OWASP ZAP |
| `c2` | cloudflared plus the Python tooling shared with `recon` and `ad` |
| `wordlists` | SecLists, rockyou, and friends (multi-GB) |
| `desktop` | VS Code, OpenCode |
| `browsers` | Brave, Firefox, and a locked-down Firefox policy |

`python3 myubuntu.py --list` prints every step with the profiles it belongs to.

## How it behaves

- **Resumable** — progress is written to `~/tools/.myubuntu-state.json`, so an
  interrupted or failed run continues instead of restarting.
- **Self-healing** — one broken step never takes down the rest; you get a summary
  of what failed and can re-run to retry just those.
- **Slow-link friendly** — apt and pip/uv/cargo/git/go retry and timeout settings are
  tuned for high-latency and flaky connections, and downloads resume.
- **Live progress** — on a TTY it renders a progress bar with a recent-output pane
  (via `rich`); piped to a file it drops to one line a minute. Every rich call is
  guarded, so a missing or broken display can never fail the run.
- **Logs** — full output goes to `~/tools/myubuntu.log` (rotated, everything at
  `DEBUG` level), and a summary lands on stdout at the end.
- **sudo** — you get one password prompt up front, and the script installs a
  temporary scoped `NOPASSWD` rule for the duration of the run so a multi-hour
  install never stalls on a re-prompt. It is removed on success, failure, and
  Ctrl+C. If the process is killed outright, remove it with:

  ```bash
  sudo rm /etc/sudoers.d/090-pentest-setup-temp
  ```

Shell changes (`PATH`, network tuning) are written as managed blocks in
`~/.bashrc`, `~/.zshrc`, and `~/.config/fish/config.fish`, so re-running replaces
them in place rather than piling up duplicates. Existing files are backed up once
as `<file>.myubuntubak`.

## Legal note

These are offensive-security tools. Only use them on systems you own or have
explicit written permission to test. Depending on where you live, running them
without authorisation is a criminal offence.

## License

[MIT](LICENSE) © Mahdi ([@j0yb0y-m](https://github.com/j0yb0y-m))
