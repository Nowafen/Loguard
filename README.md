# Loguard

**Real-time, tamper-resistant Linux login alert system for Telegram**

Loguard is a lightweight, security-focused daemon that monitors every login attempt on your Linux system – SSH, console, `su`, `sudo`, and graphical displays – and instantly sends a Telegram notification. It is designed to be resilient against tampering, with self-healing, integrity checks, and a persistent queue that survives network outages and reboots.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-0.1.0-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)

---

## Features

- **Instant Login Alerts** – Get notified in real time whenever a user logs in via SSH, console, `su`, `sudo`, or a graphical session.
- **Tamper‑Resistant** – The daemon regularly verifies its own binary, the PAM hook, and the PAM configuration files. Any modification triggers an immediate alert and optional self‑healing.
- **Persistent Queue** – All events are stored locally in a JSONL queue. If Telegram is unreachable, messages are retried automatically until they are delivered.
- **Zero Runtime Dependencies** – The only external tool needed is `curl` (for HTTPS calls). No libcurl, no Python, no Node.js – just plain C++ and C.
- **Minimal Login Overhead** – The PAM hook writes a single line to a local file and exits immediately. It never blocks the login process with network I/O.
- **Watchdog System** – A systemd timer or cron job runs `loguard check` every minute, verifying daemon health, PAM integrity, and binary checksums.
- **Self‑Healing** – If the PAM hook is removed (accidentally or maliciously), the watchdog can automatically re‑apply it.
- **Simple Configuration** – Interactive wizard or environment‑variable driven setup.

---

## Installation

### One‑line install (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/Nowafen/Loguard/main/install.sh | sudo bash
```

The script will:
- Detect your distribution and package manager
- Install build dependencies (`curl`, `gcc`, `g++`, `make`)
- Download the latest source
- Compile both binaries
- Install systemd units (or OpenRC/cron fallback)
- Guide you through Telegram Bot Token and Chat ID setup
- Send a test message
- Enable monitoring

### Manual install from source

```bash
git clone https://github.com/Nowafen/Loguard.git
cd Loguard
sudo bash install.sh
```

### Build manually (without installer)

```bash
# Build main daemon
g++ -std=c++17 -O2 -o loguard \
    src/main.cpp src/util.cpp src/config.cpp \
    src/telegram.cpp src/queue.cpp src/pam.cpp \
    src/integrity.cpp

# Build PAM hook
gcc -O2 -o loguard-notify src/pam_hook.c

# Install
sudo install -m 0755 loguard loguard-notify /opt/loguard/bin/
sudo ln -sf /opt/loguard/bin/loguard /usr/local/bin/loguard
sudo mkdir -p /etc/loguard /var/lib/loguard /var/log/loguard
# Then set up systemd/OpenRC/cron and create /etc/loguard/config.toml
```

---

## Configuration

Loguard stores its configuration in `/etc/loguard/config.toml` (root‑only readable).

### Interactive wizard

```bash
sudo loguard edit
```

This will guide you through setting:
- **Bot Token** – from [@BotFather](https://t.me/BotFather)
- **Chat ID** – from [@userinfobot](https://t.me/userinfobot)
- **Hostname** (optional, shown in alerts)
- **Heartbeat interval** (minutes, 0 = disabled)
- **Self‑heal** toggle

### Non‑interactive (environment variables)

```bash
export LOGUARD_BOT_TOKEN="your:token"
export LOGUARD_CHAT_ID="123456789"
export LOGUARD_HOSTNAME="my-server"   # optional
sudo bash install.sh
```

### Manual config file

Create `/etc/loguard/config.toml`:

```toml
bot_token = "your:token"
chat_id   = "123456789"
hostname  = "my-server"
os_info   = "Ubuntu 24.04 LTS (x86_64)"
heartbeat_minutes = 15
self_heal_pam = true
```

---

## Commands

| Command | Description |
|---------|-------------|
| `loguard status` | Show full health status: daemon, PAM hook, config, integrity, queue, last alert |
| `sudo loguard enable` | Activate monitoring: install PAM hook, start daemon and watchdog timer |
| `sudo loguard disable` | Pause monitoring: remove PAM hook and stop daemon |
| `sudo loguard test` | Send a test Telegram message to verify credentials |
| `sudo loguard edit` | Interactive configuration wizard |
| `loguard logs [n]` | Show last `n` delivery log lines (default 20) |
| `loguard queue` | Display pending messages in the queue |
| `sudo loguard clear-queue` | Discard all pending alerts (asks for confirmation) |
| `loguard check` | Run one watchdog pass manually (checks integrity and sends alerts if issues found) |
| `sudo loguard update` | Check GitHub Releases for a newer version, verify checksum, and update atomically |
| `sudo loguard restart` | Disable then enable (re‑applies PAM hook) |
| `sudo loguard uninstall` | Completely remove Loguard and all its files |
| `loguard version` | Print installed version |
| `loguard help` | Show this help |

---

## How It Works

1. **PAM Hook** (`loguard-notify`) – A tiny C program that is invoked by PAM on every `open_session` event. It reads the current session details (user, service, remote host, TTY), builds a JSON line, and appends it to `/var/lib/loguard/queue.jsonl` with an exclusive lock. It never performs network I/O.

2. **Queue** – The queue file is a simple JSONL (JSON Lines) format. Each line contains the event timestamp, user, service, origin, TTY, a plain‑text message, an HTML‑formatted message, and a retry counter.

3. **Daemon** (`loguard daemon`) – The background process wakes up every few seconds, loads the queue, attempts to deliver each message via Telegram’s Bot API using `curl`, and rewrites the queue file to remove successfully sent events. It also sends periodic heartbeat messages and runs a health check every minute.

4. **Watchdog** – A systemd timer (or cron job) runs `loguard check` every minute. This verifies:
   - The daemon is running
   - The PAM hook is still present in all files recorded in the manifest
   - The installed binaries match their SHA‑256 checksums
   
   If any problem is found, it sends a Telegram alert and, if `self_heal_pam` is enabled, automatically restores the PAM hook.

5. **Integrity Manifest** – After `loguard enable`, the SHA‑256 hashes of the main binary and the PAM hook are stored in `/etc/loguard/integrity.sha256`. Future `check` runs compare the current binaries against these hashes.

6. **Tamper Log** – Any integrity or PAM‑related alerts are also written to `/var/log/loguard/tamper.log` for offline auditing.

---

## Security Considerations

- **Root privileges** – The daemon runs as root because it needs to modify PAM files and read system logs. The PAM hook also runs as root (PAM context).
- **No shell injection** – All external commands are executed via `execvp` with an argument vector – never through a shell. This prevents injection of bot tokens, usernames, or hostnames.
- **Atomic file writes** – Configuration, queue rewrites, and manifest files are written atomically (using a temporary file + rename), so a crash during write never corrupts the real file.
- **File permissions** – Sensitive files (config, queue, manifests) are created with `0600` permissions, owned by root.
- **Checksum verification** – The `update` command verifies the downloaded archive against the published SHA‑256SUMS file before installing.
- **Retry limit** – Events that fail delivery are retried up to 500 times to prevent unbounded queue growth.

---

## Troubleshooting

### Test message fails

- Verify your Bot Token and Chat ID are correct.
- Ensure the machine can reach `api.telegram.org` (no firewall/proxy blocking).
- Run `curl -v https://api.telegram.org/bot<YOUR_TOKEN>/getMe` to check the token.

### Daemon not running

```bash
sudo systemctl status loguard   # systemd
sudo rc-service loguard status  # OpenRC
```

Check the logs: `sudo journalctl -u loguard -f` (systemd) or `/var/log/loguard/alert.log`.

### PAM hook not working after manual PAM edits

Run `sudo loguard restart` to re‑apply the hook. Or run `sudo loguard check` – if `self_heal_pam` is enabled, it will restore automatically.

### Queue grows indefinitely

If Telegram is unreachable for a long time, the queue will grow. You can clear it with `sudo loguard clear-queue` (after verifying connectivity). The daemon will continue retrying until delivery succeeds or the retry limit is reached.

---

## Creator
- **X** : [@Nawid](https://x.com/RedTeamElite)

---

**Loguard** – Keep your Linux logins under watch, always!