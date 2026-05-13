# Lazarus Config-Injection Scanner

Cross-platform Python scanner + safeguarder for the **Contagious Interview**
/ **BeaverTail** supply-chain attack that hides obfuscated payloads in
JavaScript config files (`next.config.js`, `postcss.config.js`, etc.).

Three modes of operation, all in one tool:

1. **Detect** — find the malware in files, processes, and persistence locations.
2. **Remediate** — quarantine + clean infected files, kill malicious processes.
3. **Harden** — apply proactive defenses so reinfection is harder.

Reference: [GitHub Community discussion #188732](https://github.com/orgs/community/discussions/188732#discussioncomment-16368443)

---

## What it detects

**Files** — every `*.config.{js,mjs,cjs,ts}` in the tree (matches `next`, `postcss`, `tailwind`, `vite`, `webpack`, `rollup`, `svelte`, `astro`, `nuxt`, `remix`, `babel`, `vue`, `jest`, `playwright`, `cypress`, `prettier`, `commitlint`, `lint-staged`, `metro`, …) plus `gatsby-config.*`, `gatsby-node.*`, `.babelrc.{js,cjs,mjs}`, `babel.config.json`:
- IOC strings: `global['!']`, `_$_1e42`, `A4-1928`, `TronWeb`, `bsc-dataseed`, `api.trongrid.io`, ethers JsonRpcProvider, Solana keypair access, macOS keychain refs, Chrome creds paths
- Whitespace-padding tricks (>200 spaces/tabs on one line)
- `eval()` calls in config files
- Long encoded blobs (>=500 chars)
- Suspicious large configs (>8 KB combined with `eval`)

**Processes** (any `node` / `bun` / `electron` process):
- TRON / BSC RPC endpoints in cmdline
- Obfuscation markers in cmdline
- Running from `/tmp`, `/var/tmp`, `/dev/shm`, `%TEMP%`, `\Windows\Temp\`, `/private/tmp`
- Detached (ppid=1) node processes
- `eval(`/`atob(` in cmdline
- Hex blobs in cmdline (>=200 hex chars)
- Cmdlines longer than 1500 chars (likely encoded payload)

A process is flagged if its **suspicion score >= 2**. Each indicator is worth 1–2 points; multiple weak signals combine.

**Persistence** (cross-platform):
- `curl|wget … | node|sh|bash|powershell` in `.bashrc`, `.bash_profile`, `.profile`, `.zshrc`, `.zprofile`, fish config
- User crontab entries calling node/curl/wget (Linux/macOS)
- LaunchAgents referencing node/curl (macOS `~/Library/LaunchAgents/*.plist`)
- Scheduled Tasks referencing node/curl (Windows)
- Registry Run keys with node/curl/encoded PowerShell (Windows `HKCU\…\Run`)

## Requirements

- Python 3.8+ — standard library only, no `pip install` required.
  - Linux/macOS: usually preinstalled.
  - Windows: `winget install Python.Python.3.12` or grab from python.org.

## Quick start

### Linux / macOS

```bash
# Detection only — scan the current directory
python3 lazarus_scanner.py

# Scan a specific folder
python3 lazarus_scanner.py ~/Documents/gigs

# Scan everything under your home dir
python3 lazarus_scanner.py --scan-home

# Detect AND clean infected files (auto-backs-up first)
python3 lazarus_scanner.py --scan-home --fix

# Detect AND kill suspicious processes (asks per-process)
python3 lazarus_scanner.py --kill

# Apply proactive defenses (npm ignore-scripts, hosts hint, etc.)
python3 lazarus_scanner.py --harden

# Do everything: scan home + clean files + kill procs + harden
python3 lazarus_scanner.py --all

# Continuous monitoring (checks every 60s, Ctrl-C to stop)
python3 lazarus_scanner.py --watch --interval 60 --log ~/lazarus.log
```

### Windows (PowerShell or cmd)

```powershell
py -3 lazarus_scanner.py
py -3 lazarus_scanner.py --scan-home --fix
py -3 lazarus_scanner.py --kill
py -3 lazarus_scanner.py --harden
py -3 lazarus_scanner.py --all
```

## Flags

| Flag | Purpose |
|---|---|
| `paths…` | Directories to scan (default: current dir) |
| `--scan-home` | Also scan `$HOME` / `%USERPROFILE%` |
| `--fix` | Quarantine each hit (`<file>.malware-backup-<ts>`) and truncate the trailing payload |
| `--kill` | Kill suspicious processes — asks for confirmation per PID |
| `--harden` | Apply proactive defenses (see below) |
| `--all` | Equivalent to `--scan-home --fix --kill --harden` |
| `--yes` / `-y` | Skip confirmation prompts (use with care) |
| `--watch` | Continuous loop — re-scan every `--interval` seconds |
| `--interval N` | Watch interval in seconds (default 60) |
| `--json` | Machine-readable output |
| `--no-process-check` | Skip running-process inspection (faster) |
| `--log FILE` | Append each run's JSON report to `FILE` (audit trail) |

Exit code is `1` if anything suspicious was found, `0` otherwise — usable in CI / pre-commit / cron.

## What each remediation actually does

### `--fix` (config files)

1. Copies the file to `<file>.malware-backup-<unix-timestamp>` (preserves mtime).
2. Searches for the **first** legitimate end marker:
   - `export default <name>;`
   - `module.exports = <name>;`
   - `export default { … };`
   - `module.exports = { … };`
3. Truncates everything after that point and writes a single trailing newline.
4. Skips files where it can't find a clean cut point — better to bail than corrupt.

### `--kill` (processes)

1. Lists every running process scored ≥ 2.
2. For each: prints `pid`, `ppid`, score, indicators, and a 80-char cmdline preview.
3. Asks `[y/N]` per process (skip with `--yes`).
4. POSIX: `kill -9 <pid>`.  Windows: `taskkill /F /PID <pid>`.

### `--harden` (proactive defenses)

1. Sets `npm config set ignore-scripts true` globally — blocks the `postinstall` vector. Revert with `npm config delete ignore-scripts`.
2. Runs `git credential-cache exit` — flushes any in-memory cached git credentials, so a backgrounded malicious process can't borrow them.
3. Checks your hosts file for entries blocking known C2 domains and **prints the lines you should add as root/admin**:
   - `api.trongrid.io`, `api.shasta.trongrid.io`, `api.nileex.io`
   - `bsc-dataseed.binance.org`, `bsc-dataseed1.defibit.io`, `bsc-dataseed1.ninicoin.io`
   - `data-seed-prebsc-1-s1.binance.org`, `data-seed-prebsc-2-s1.binance.org`

   The hosts file is **not auto-edited** because it requires elevation and is system-critical. Append manually:

   ```bash
   # Linux / macOS
   sudo sh -c 'cat >> /etc/hosts <<EOF
   127.0.0.1	api.trongrid.io
   127.0.0.1	bsc-dataseed.binance.org
   # …rest of the lines printed by --harden
   EOF'
   ```

   ```powershell
   # Windows — run PowerShell as Administrator
   Add-Content -Path "$env:WINDIR\System32\drivers\etc\hosts" -Value "127.0.0.1`tapi.trongrid.io"
   ```

> Note: blocking BSC / TRON RPC endpoints will break legitimate Web3 work. If you build crypto apps, skip the hosts step or block selectively.

## Watch mode

`--watch` runs the same checks on a loop. Pair it with `--log` to keep an audit trail:

```bash
python3 lazarus_scanner.py --watch --interval 30 --log ~/lazarus-audit.jsonl
```

Each run appends one JSON line. To run it as a background daemon:

```bash
nohup python3 lazarus_scanner.py --watch --interval 60 \
  --log ~/lazarus-audit.jsonl --no-process-check >/dev/null 2>&1 &
```

Or as a cron / systemd-timer / Task Scheduler entry — exit code `1` flags hits for alerting.

## If something is found

1. **Stop**. Don't run `npm install`, `npm run dev`, or push commits until you've cleaned up.
2. Inspect the backup the scanner saved next to each infected file — confirm the indicators are real (not a false positive on, say, a legitimate Web3 config).
3. Run `--fix` to clean automatically, or restore from the last clean git commit: `git checkout HEAD -- next.config.js`.
4. Run `--kill` to terminate any matched malicious processes.
5. Run `--harden` to set defenses and print the hosts entries.
6. Rotate every credential the host had access to:
   - `gh auth status` → revoke and re-issue.
   - `npm token list` → revoke.
   - SSH keys, `.env` secrets, browser-saved creds, **crypto wallet seed phrases**.
7. Audit your repos for unauthorized commits:
   ```bash
   for d in */; do
     (cd "$d" && git log --all --since="2025-11-01" --pretty=format:"%h %an %ae %s" 2>/dev/null) \
       | sed "s|^|$d: |"
   done
   ```
8. Reboot — the report says hidden detached processes survive until reboot but not past it.
9. Consider the host compromised. The only fully safe move is a wipe; at minimum reboot, re-scan, harden, and watch for reappearance.

## Defenses going forward

- Run interview coding tests in a **VM, container, or sandbox** — never on your host.
- Use a separate user account / machine for freelance / contract work.
- Pin and review `postinstall` scripts in `package.json` of any cloned repo.
- Keep `npm config set ignore-scripts true` set; opt in per project when needed.
- Schedule `python3 lazarus_scanner.py --scan-home` to run daily via cron / Task Scheduler with `--log` for an audit trail.
- Keep recent clean snapshots / backups so you can restore quickly.

## Files

```
lazarus-scanner/
├── lazarus_scanner.py    # the scanner (stdlib only)
└── README.md             # this file
```
