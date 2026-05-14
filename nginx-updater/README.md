# nginx-updater

Automated, idempotent nginx upgrade tool for **[CVE-2026-42945](https://nginx.org/en/security_advisories.html)** (NGINX Rift, CVSS 9.2) — and any future nginx security campaign.

[![Shellcheck](https://github.com/tagashi666/nginx-updater/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/tagashi666/nginx-updater/actions/workflows/shellcheck.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## TL;DR

A single bash script you drop on any Linux server. It auto-detects:

- **System nginx** — Debian / Ubuntu / RHEL / Alma / Rocky / Oracle / Fedora
- **Docker nginx** — managed by `docker compose`

It checks the running version, upgrades to a non-vulnerable release, runs `nginx -t`, performs a full restart (not reload), and verifies. With backup. Idempotent.

```bash
# Dry-run first — change nothing, just report
curl -fsSL https://raw.githubusercontent.com/tagashi666/nginx-updater/main/nginx-upgrade.sh \
  | sudo bash -s -- --check
```

## About CVE-2026-42945

A heap buffer overflow in `ngx_http_rewrite_module`, present in nginx since version 0.6.27 (2008). Enables unauthenticated remote code execution under specific rewrite configurations. Disclosed by F5 and depthfirst on **May 13, 2026**.

| | |
|---|---|
| **Affected** | nginx OSS 0.6.27 – 1.30.0, NGINX Plus R32 – R36 |
| **Fixed in** | nginx 1.30.1 (stable), 1.31.0 (mainline) |
| **CVSS v4** | 9.2 (Critical) |
| **Auth** | None required |
| **PoC** | Public |

## Features

- **Idempotent** — re-runs on already-patched servers exit clean with code 0
- **Dry-run mode** (`--check`) for safe fleet-wide preview
- **Auto-detection** of OS family and Docker Compose stacks via container labels
- **Pre-flight `nginx -t`** — bad configs never kill the running service
- **Backup** of `/etc/nginx`, installed packages list, and `docker inspect` snapshots before any change
- **Structured exit codes** for orchestration:
  - `0` — success (or nothing to do)
  - `1` — fatal error
  - `2` — partial success, manual action required
- **Refuses dangerous operations** — won't recreate raw `docker run` containers blind, won't override pinned compose tags

## Quick start

### Inspect first (this is a security tool — read what you run)

```bash
git clone https://github.com/tagashi666/nginx-updater.git
cd nginx-updater
less nginx-upgrade.sh
```

### Dry-run

```bash
sudo ./nginx-upgrade.sh --check
```

### Apply

```bash
sudo ./nginx-upgrade.sh
```

### Flags

| Flag | Description |
|---|---|
| `--check`, `--dry-run` | Report state, change nothing |
| `--skip-system` | Don't touch system nginx |
| `--skip-docker` | Don't touch Docker containers |
| `--stable` | Install stable branch (default — e.g. 1.30.x) |
| `--mainline` | Install mainline branch (e.g. 1.31.x) |
| `-h`, `--help` | Show help |

## Fleet deployment

### xargs fan-out

```bash
mkdir -p logs
cat hosts.txt | xargs -P8 -I{} sh -c '
  scp -q nginx-upgrade.sh root@{}:/tmp/ &&
  ssh root@{} "bash /tmp/nginx-upgrade.sh --check" > "logs/{}.log" 2>&1 &&
  echo "{}: $?"
'
```

### Ansible

```yaml
- hosts: web_servers
  become: true
  tasks:
    - name: Run nginx upgrade
      script: nginx-upgrade.sh --check    # remove --check to apply
      register: result
      failed_when: result.rc == 1
      changed_when: result.rc == 0 and 'УЯЗВИМ' not in result.stdout
```

## What it does NOT handle

For these scenarios, see the [manual runbook](docs/RUNBOOK.md):

- **Custom-built nginx** (compiled from source) — package managers can't replace it
- **OpenResty** — separate upstream with its own release cycle
- **nginx in Kubernetes Ingress controllers** — use Helm chart upgrade
- **Raw `docker run` containers** — script detects them, saves `docker inspect` snapshot, and asks you to recreate manually with the right volumes/ports/env

## Safety guarantees

- Always backs up `/etc/nginx` to `/root/nginx-backup-<timestamp>/` before changes
- Always runs `nginx -t` before any restart
- Logs everything to `/var/log/nginx-upgrade/upgrade-<timestamp>.log`
- Exits non-zero on failure — no silent breakage
- Verifies the version is actually safe after upgrade (catches package-manager weirdness)

Still — **test on a staging host first**. This is the kind of tool you don't run blind in prod.

## Output language

The script's user-facing output is currently in Russian. PRs adding `--lang en` are welcome.

## Contributing

Issues and PRs welcome. Please run `shellcheck nginx-upgrade.sh` before submitting.

## License

[MIT](LICENSE)
