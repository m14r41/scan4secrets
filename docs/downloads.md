---
id: downloads
title: Downloads
sidebar_position: 8
description: Prebuilt scan4secrets binaries for Windows64 and Linux amd64, plus Docker image and Python wheel. Checksum verification instructions included.
keywords: [scan4secrets download, scan4secrets binary, scan4secrets windows, scan4secrets linux, scan4secrets docker, scan4secrets release]
---

# Downloads

Pick your platform. All releases are published on the [GitHub Releases](https://github.com/m14r41/scan4secrets/releases) page.

## Latest release

| Platform | Asset | Install |
|---|---|---|
| **Linux (amd64)** | `scan4secrets-linux-amd64` | [Download](https://github.com/m14r41/scan4secrets/releases/latest/download/scan4secrets-linux-amd64) |
| **Windows (x64)** | `scan4secrets-win-amd64.exe` | [Download](https://github.com/m14r41/scan4secrets/releases/latest/download/scan4secrets-win-amd64.exe) |
| **Docker** | `ghcr.io/m14r41/scan4secrets:latest` | `docker pull ghcr.io/m14r41/scan4secrets:latest` |
| **Python wheel** | `scan4secrets-X.Y.Z-py3-none-any.whl` | `pipx install scan4secrets` |

## Linux amd64

```bash
# Download
curl -L -o scan4secrets \
  https://github.com/m14r41/scan4secrets/releases/latest/download/scan4secrets-linux-amd64

# Verify checksum (download SHA256SUMS alongside the binary)
curl -L -o SHA256SUMS \
  https://github.com/m14r41/scan4secrets/releases/latest/download/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS

# Install
chmod +x scan4secrets
sudo mv scan4secrets /usr/local/bin/
scan4secrets --version
```

## Windows x64

PowerShell:

```powershell
# Download
Invoke-WebRequest `
  -Uri "https://github.com/m14r41/scan4secrets/releases/latest/download/scan4secrets-win-amd64.exe" `
  -OutFile "$env:USERPROFILE\scan4secrets.exe"

# Verify checksum (compare against SHA256SUMS on the release page)
Get-FileHash "$env:USERPROFILE\scan4secrets.exe" -Algorithm SHA256

# Optionally add to PATH (current user)
$env:Path += ";$env:USERPROFILE"
scan4secrets.exe --version
```

## Docker

```bash
# Pull
docker pull ghcr.io/m14r41/scan4secrets:latest

# SAST scan a host directory
docker run --rm -v "$(pwd):/scan" ghcr.io/m14r41/scan4secrets:latest \
  --path /scan --report sarif --output /scan/reports/scan

# DAST scan a URL (no volume mount needed)
docker run --rm ghcr.io/m14r41/scan4secrets:latest \
  --url https://example.com --report json --output - > scan.json
```

Image is multi-stage, runs as non-root, and is ~120 MB compressed.

## Python wheel (recommended for CI)

```bash
# pipx (preferred. keeps deps isolated)
pipx install scan4secrets

# OR pip
pip install scan4secrets

# OR from latest main
pipx install git+https://github.com/m14r41/scan4secrets
```

## Checksums and signatures

Every release ships a `SHA256SUMS` file. Verify before running:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

Signature verification (when published):

```bash
cosign verify-blob \
  --certificate scan4secrets-linux-amd64.cert \
  --signature scan4secrets-linux-amd64.sig \
  scan4secrets-linux-amd64
```

## Older releases

All prior versions are on the [Releases page](https://github.com/m14r41/scan4secrets/releases). Each release lists its [Changelog](./changelog) entry and includes Linux amd64, Windows x64, Docker, and wheel artifacts.

## Build from source

If you'd rather build locally:

```bash
git clone https://github.com/m14r41/scan4secrets
cd scan4secrets
pip install -e .
scan4secrets --version
```
