# oncedrop

One-shot, end-to-end encrypted file hand-off from your computer to your phone, over the internet, with no account at any provider.

[![CI](https://github.com/uetam3/oncedrop/actions/workflows/ci.yml/badge.svg)](https://github.com/uetam3/oncedrop/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/uetam3/oncedrop)](https://github.com/uetam3/oncedrop/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Why

You have a file on your computer and you want it in an app on your phone: a chat, an email, a cloud drive. Cables, shared drives and uploading to a third-party service are all more work than the file deserves.

With oncedrop you run one program, drop the file into a local panel and scan a QR code with your phone. The phone decrypts the file in the browser and opens the system share sheet, so you can send it to any app straight away. The file is never stored on a server, and the link works exactly once.

It is a single Go binary with the frontend (Preact + Vite) and `cloudflared` embedded, so there is nothing to install. Prebuilt binaries cover Linux (amd64, arm64, arm, 386), Windows (amd64, 386, arm64) and macOS (Intel, Apple Silicon).

## How it works

```
computer                               internet                         phone
┌────────────────────┐   ssh / cloudflared    ┌─────────────────────┐   https   ┌─────────────┐
│ oncedrop           │◄──────────────────────►│ tunnel              │◄─────────►│ browser     │
│  panel 127.0.0.1   │  (sees only ciphertext)│ *.lhr.life          │           │  WebCrypto  │
│  AES-256-GCM       │                        │ *.trycloudflare.com │           │  Web Share  │
└────────────────────┘                        └─────────────────────┘           └─────────────┘
```

1. oncedrop generates a random 256-bit key and a token, encrypts the file (together with its name and MIME type) with AES-256-GCM and keeps the ciphertext in memory.
2. It opens a tunnel to a local port, but only while one is needed (see below). By default it uses the embedded `cloudflared` (a quick tunnel, no account). If that is missing or fails, it falls back to `localhost.run` over SSH, implemented in pure Go.
3. The QR code holds `https://<host>/s/<token>#<key>`. The part after `#` never leaves the browser: it reaches neither the tunnel nor the server.
4. The phone downloads the ciphertext, decrypts it in the browser (WebCrypto) and shows a *Share* button (Web Share API) and a *Save to phone* button.
5. The first download of the ciphertext invalidates the token; a second attempt gets `410 Gone`. A link also expires after a time limit (15 minutes by default).

### Tunnel on demand

oncedrop can run in the background all the time. The tunnel is opened only when:

- the panel is open in a visible browser tab (the panel pings every 2 seconds),
- or a link exists that has not been downloaded and has not expired,
- or a download is in progress.

When none of that holds for `-tunnel-idle` (3 minutes by default), the tunnel is closed and nothing is exposed to the internet. It reconnects within a few seconds when you open the panel again.

A running tunnel is checked: once a minute oncedrop sends a request to itself through the public address. After three failures in a row the tunnel is rebuilt. A new tunnel means a new address, so the panel refreshes the QR codes of active links on its own. A green dot next to the address means it has been verified; orange means it is still connecting or has not answered yet.

The tunnel provider sees only a random token and encrypted bytes. Even if it captured the traffic, it could not read the file or its name.

## Install

### Prebuilt binaries

Download the binary for your system and `SHA256SUMS` from the [latest release](https://github.com/uetam3/oncedrop/releases/latest), then verify it:

```sh
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify oncedrop-linux-amd64 -R uetam3/oncedrop
```

The second command checks the build provenance attestation and needs the GitHub CLI.

### From source

Requires Go 1.26+ and Node 22. The built frontend (`web/dist`) is not committed, so build it first; `go install` alone gives a binary without the web pages.

```sh
(cd web && npm ci && npm run build)
go run ./tools/release                   # ./oncedrop for this system, with embedded cloudflared
go run ./tools/release -all              # every platform into dist/ (+ dist/SHA256SUMS)
go run ./tools/release -os windows -arch amd64
go run ./tools/release -no-cloudflared   # small binary (~7 MB) without cloudflared
```

The tool downloads the official `cloudflared` release from GitHub into `.cache/`, checks its SHA-256 against `tools/release/cloudflared.sums`, compresses it and embeds it. On first run, oncedrop unpacks it into the user cache directory (`~/.cache/oncedrop`, `%LocalAppData%\oncedrop`, `~/Library/Caches/oncedrop`) and verifies the checksum again. The resulting binary is about 25 MB, of which about 19 MB is `cloudflared`. There is no official `cloudflared` for Windows on ARM, so that build uses `localhost.run`.

The `Makefile` (`make`, `make release`, `make nocf`) also rebuilds the frontend. A plain `go build` gives a binary without `cloudflared`.

To update `cloudflared`, change `cloudflaredVersion` in `tools/release/main.go` and the sums in `tools/release/cloudflared.sums` (they are in the release notes and the GitHub API).

## Usage

```sh
./oncedrop                       # opens the panel in your browser; drop the file there
./oncedrop contract.pdf offer.pdf  # shares the files right away and prints QR codes in the terminal
```

Only one copy runs at a time (the panel has a fixed port). Running `./oncedrop` again opens the panel of the running copy, and `./oncedrop file.pdf` hands the file to it and prints the QR code.

Flags:

| flag | default | meaning |
|---|---|---|
| `-tunnel` | `auto` | `auto`, `cloudflared`, `localhost.run` or `none` (local testing only) |
| `-tunnel-idle` | `3m` | how long without a panel and without pending links before the tunnel closes |
| `-ttl` | `15m` | how long a link stays valid |
| `-max-size` | `104857600` | maximum file size in bytes (100 MB) |
| `-max-total` | `1073741824` | maximum bytes held in memory across all shares (1 GB) |
| `-max-shares` | `50` | maximum number of shares at once |
| `-admin` | `127.0.0.1:47651` | panel address, loopback only (`127.0.0.1:0` picks a random port) |
| `-public` | `127.0.0.1:0` | local address the tunnel forwards to |
| `-secret-file` | user config directory | file holding the panel key, created on first start |
| `-no-open` | | do not open the panel in a browser |
| `-no-qr` | | do not print QR codes in the terminal |
| `-insecure-hostkey` | | skip localhost.run host key pinning |
| `-version` | | print the version and the embedded cloudflared version |

The panel shows the tunnel status, the QR code, a countdown and the moment of download. After a download or an expiry you can create a new link for the same file with one click.

### Panel key

On start, oncedrop prints the panel address with a key: `http://127.0.0.1:47651/?k=...`. The first visit stores the key in a cookie (HttpOnly, SameSite=Strict) and removes it from the address bar, so afterwards the bookmark `http://127.0.0.1:47651/` is enough. The key lives in `~/.config/oncedrop/admin-key` (Windows: `%AppData%\oncedrop\admin-key`, macOS: `~/Library/Application Support/oncedrop/admin-key`) with mode `0600`. Deleting the file invalidates the old key on the next start.

### Running in the background

Linux (systemd, user service):

```ini
# ~/.config/systemd/user/oncedrop.service
[Unit]
Description=oncedrop

[Service]
ExecStart=%h/bin/oncedrop -no-open
Restart=on-failure

[Install]
WantedBy=default.target
```

```sh
systemctl --user enable --now oncedrop
```

Windows: put a shortcut to `oncedrop.exe -no-open` in `shell:startup`. macOS: a LaunchAgent with `ProgramArguments` set to the binary path and `-no-open`, and `KeepAlive` set to true.

## On the phone

Scan the QR code with the camera, open the link in Chrome (Android) or Safari (iOS) and tap *Download and share*. The system share sheet opens, listing your messaging and mail apps. If the sheet does not open by itself (the browser wants a tap), tap *Share* again. The file stays in the tab's memory until you close it, so you can send it several times, but do not reload the page: the link is already used.

## Security model

- AES-256-GCM with a random nonce and a random key per share. The file name is inside the ciphertext.
- The key is only in the URL fragment (`#`). The receiving page removes it from the address bar right after loading.
- The token is 128 bits, single-use and time-limited. Files are held in RAM only, with limits on total memory and number of shares. Uploads are streamed into memory, so the plaintext never touches the disk, not even in the system temp directory.
- The tunnel exists only while it is needed. When idle, nothing can be reached from the internet.
- The panel listens on loopback only (other addresses are rejected), requires a key, checks the `Host` header (DNS rebinding) and requires an `X-Requested-With` header (CSRF). It does not answer CORS requests.
- The browser is opened with a single-use login link that expires after two minutes, never with the panel key: command lines are visible to other users of the machine.
- A second `oncedrop` hands its files to a running one only after that instance proves, with an HMAC over a fresh nonce, that it knows the panel key. A process of another user that took the panel port first gets neither the key nor any file.
- Public page: after 30 requests for a nonexistent token within 10 minutes, a client address gets `429`. The client address is taken from the header that the active tunnel provider controls (`CF-Connecting-IP` on Cloudflare, the last `X-Forwarded-For` element on localhost.run), never from client-supplied values. The rate limiter's table is bounded. There are timeouts on headers, reads and idle connections.
- CSP, `nosniff`, `no-referrer` and `noindex` headers on both servers.
- The embedded `cloudflared` is checked against a SHA-256 sum at build time and again when unpacked. It is unpacked into a private per-user cache directory, which is refused if it is shared or owned by someone else (there is no fallback to the shared temp directory). It runs with an empty config and no auto-update. On Linux and Windows it dies together with oncedrop, even after `kill -9`.
- The localhost.run SSH host key is pinned in the code.

### What it does not protect against

- The phone itself: once the file is decrypted and handed to another app, that app and the phone are in charge.
- Someone photographing the QR code on your screen. Show the QR code only to yourself.
- The tunnel provider going down or blocking you. oncedrop depends on Cloudflare quick tunnels or localhost.run being available.

## Development

```sh
./oncedrop -tunnel none -no-open                                         # backend on 47651
cd web && ONCEDROP_KEY=$(cat ~/.config/oncedrop/admin-key) npm run dev  # Vite with /api proxy
make test                                                                # go test -race ./...
```

Code layout:

- `main.go`: CLI, listeners, terminal QR codes
- `instance.go`: panel key, handing files to a running copy
- `internal/share`: share store and encryption
- `internal/tunnel`: `cloudflared` and `localhost.run` providers (pure Go, `x/crypto/ssh`); `manager.go` handles the on-demand tunnel, idle shutdown and the self-check through the public address
- `internal/cfbin`: embedded `cloudflared` and its unpacking
- `tools/release`: fetches `cloudflared` and builds for every platform
- `internal/server`: the panel (`admin.go`) and the receiver (`public.go`)
- `web/src/admin`: Preact panel
- `web/src/receive`: receiving page with progress fetch, WebCrypto and Web Share

## Contributing

Issues and pull requests are welcome. Please make sure `make test` passes and that `gofmt` and `go vet` are clean. Report security problems as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
