# WinfoomRust

> **⚠️ Project under active development — beta version**

HTTP(S) facade proxy in Rust for working with HTTP, SOCKS, and PAC proxies, with a desktop GUI.

Current version: **0.6.0**

**This project is open source and developed with AI assistance.**

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Logs](#logs)
- [Troubleshooting](#troubleshooting)
- [Architecture](#architecture)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Overview

WinfoomRust is a reimplementation of [Winfoom](https://github.com/ecovaci/winfoom) in Rust.  
The application exposes a local proxy (default `127.0.0.1:3129`) and relays requests to an upstream proxy, handling authentication and connectivity scenarios.

## Features

- Upstream proxy types:
  - `HTTP`
  - `SOCKS4` / `SOCKS5`
  - `PAC` (built-in evaluation via JavaScript engine)
  - `DIRECT`
- Built-in PAC evaluation:
  - Embedded JavaScript engine (`boa_engine`) — **no native dependencies required**
  - Support for local PAC files (`C:\...\proxy.pac`, `file:///...`) and remote ones (`http://...`)
  - Full implementation of standard PAC functions (`FindProxyForURL`, `shExpMatch`, `dnsDomainIs`, `isInNet`, `dnsResolve`, `myIpAddress`, etc.)
  - Cache with configurable TTL and stale-while-revalidate mechanism
- HTTP Auth:
  - Manual `BASIC`: supported
  - `NTLM` / `KERBEROS` + `use_current_credentials = true` (Windows): supported
  - `NTLM` / `KERBEROS` with manual credentials: not supported
- `egui` graphical interface
- Windows notification area (tray):
  - Left click: restore window
  - Right click: `Open` / `Quit` menu
- Daily log rotation + retention
- Windows packaging:
  - Embedded EXE icon (Windows resource)
  - Tray icon embedded in the binary

## Quick Start

### Prerequisites

- Rust `1.75+`
- Windows, Linux, or macOS
- **No native dependencies** (all dependencies are managed by Cargo)

### Build

```bash
cargo build --release
```

Generated binary:

- Windows: `target/release/winfoomrust.exe`
- Linux/macOS: `target/release/winfoomrust`

On Windows, the icon is automatically embedded in the executable.

### Run

```bash
# via cargo
cargo run --release

# or run directly
./target/release/winfoomrust      # Linux/macOS
.\target\release\winfoomrust.exe # Windows
```

## Installation

### Rust

If Rust is not installed:

- Windows:

```powershell
winget install Rustlang.Rustup
```

- Linux/macOS:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### Dependencies

All dependencies are Rust crates managed automatically by Cargo during compilation.

## Usage

1. Launch the application.
2. Select a proxy type (`HTTP`, `SOCKS4`, `SOCKS5`, `PAC`, `DIRECT`).
3. Enter the upstream proxy details (host/port).
4. Configure authentication if needed.
5. Start the local proxy.
6. Configure client applications to use `127.0.0.1:3129`.

### PAC Mode

In `PAC` mode, the application directly evaluates the configured PAC file:
- **Remote URL:** `http://proxy.company.com/proxy.pac` or `https://...`
- **Local file:** `C:\Users\...\proxy.pac` or `file:///C:/Users/.../proxy.pac`

Evaluation uses a built-in JavaScript engine (`boa_engine`) that implements all standard PAC functions. The PAC file configured in the application is used directly, independently of system proxy settings.

### Windows Tray

- Closing with `X` minimizes the app to the tray.
- Left click on the tray icon: restores the window.
- Right click: `Open` / `Quit` menu.

## Configuration

The configuration file is saved automatically:

- Windows: `%APPDATA%\winfoom-rust\config.toml`
- Linux/macOS: `~/.config/winfoom-rust/config.toml`

Example:

```toml
proxy_type = "HTTP"
proxy_host = "proxy.company.com"
proxy_port = 8080
local_port = 3129

use_current_credentials = true
proxy_username = ""
proxy_password = ""
http_auth_protocol = "NTLM"

proxy_pac_file_location = ""
pac_cache_ttl_seconds = 300
pac_stale_ttl_seconds = 900

socket_timeout = 60
connect_timeout = 20
blacklist_timeout = 30

autostart = false
start_minimized = false
autodetect = false

api_port = 3128
log_level = "info"
```

## Logs

- Quick access: **Help** menu → **Open logs folder**
- Rotation: daily
- Default retention: 14 files
- Levels: `trace`, `debug`, `info`, `warn`, `error`

Debug mode:

```bash
RUST_LOG=debug cargo run --release
```

## Troubleshooting

### The local proxy won't start

- Check that the local port is not already in use
- Check the logs

### PAC mode is not working

- Verify that the PAC file URL or path is correct
- Verify that the PAC file is accessible (network or disk)
- Check the logs for JavaScript evaluation errors
- Verify the PAC file syntax (`FindProxyForURL` function expected)

### Authentication errors

- Check the protocol (`BASIC`, `NTLM`, `KERBEROS`)
- Check the credentials mode (`use_current_credentials`)
- Reminder: manual NTLM/Kerberos is not supported

### Compilation errors

- Make sure you have the latest version of Rust: `rustup update`
- Clean and rebuild: `cargo clean` then `cargo build --release`

## Architecture

```text
src/
├── main.rs      # App entry point + window options
├── gui.rs       # Graphical interface (egui/eframe)
├── tray.rs      # Native Windows tray
├── proxy.rs     # Local proxy server + upstream routing
├── auth.rs      # HTTP Auth / SSPI
├── pac.rs       # Built-in PAC evaluator (boa_engine) + cache
└── config.rs    # Config loading/saving
```

### Core Technologies

| Component | Crate | Role |
|-----------|-------|------|
| GUI | `egui` / `eframe` 0.28 | Desktop graphical interface |
| Proxy server | `hyper` 1.4 + `tokio` 1.38 | Asynchronous HTTP server |
| HTTP client | `reqwest` 0.12 | HTTP client (upstream + PAC download) |
| PAC evaluation | `boa_engine` 0.20 | Pure Rust JavaScript engine |
| Windows Auth | `windows` 0.58 | SSPI (NTLM/Kerberos) |

## Roadmap

- Harden compatibility across multi-proxy environments
- Extend test coverage
- Improve binary distribution (packaging)
- Fully implement temporal PAC functions (`weekdayRange`, `dateRange`, `timeRange`)

## Contributing

Contributions are welcome via issues and pull requests on GitHub.

This project is in beta testing. Experience feedback and bug reports are especially appreciated.

## License

Apache-2.0 (see [LICENSE](LICENSE)).

## Acknowledgments

- This project is inspired by [Winfoom](https://github.com/ecovaci/winfoom).
- **This project was developed with AI assistance.**

---

Inspired by [Winfoom](https://github.com/ecovaci/winfoom).
