# WinfoomRust - Build and Usage Guide

> **⚠️ Project under active development — beta version**

Current version: **0.6.0**

**This project is open source and developed with AI assistance.**

## Installing Rust (if needed)

### Windows

1. **Download rustup-init.exe** from https://rustup.rs/
2. **Run the installer** and follow the instructions
3. **Restart the terminal** for the changes to take effect

Or via winget:
```powershell
winget install Rustlang.Rustup
```

### Linux/macOS

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## Verify the installation

```bash
rustc --version
cargo --version
```

## Building

All dependencies are Rust crates managed automatically by Cargo.

```bash
# Navigate to the folder
cd winfoom-rust

# Build in debug mode (faster to compile, slower to run)
cargo build

# Build in release mode (optimized for performance)
cargo build --release
```

Executables will be in:
- Debug mode: `target/debug/winfoomrust` (or `.exe` on Windows)
- Release mode: `target/release/winfoomrust` (or `.exe` on Windows)

On Windows, the icon is automatically embedded in the executable.

## Running

```bash
# Directly with cargo (recompiles if needed)
cargo run --release

# Or run the compiled binary
./target/release/winfoomrust      # Linux/macOS
.\target\release\winfoomrust.exe  # Windows
```

## Configuration

The application will automatically create a configuration file at:
- **Windows:** `%APPDATA%\winfoom-rust\config.toml`
- **Linux:** `~/.config/winfoom-rust/config.toml`
- **macOS:** `~/Library/Application Support/winfoom-rust/config.toml`

## Usage

1. **Launch the application** - A graphical window will open
2. **Configure the upstream proxy:**
   - Select the proxy type (HTTP, SOCKS4, SOCKS5, PAC, or DIRECT)
   - Enter the proxy host and port
   - Configure authentication if needed
3. **Configure the local port** (default: 3129)
4. **Start the proxy** by clicking "▶ Start proxy"
5. **Configure your applications** to use `127.0.0.1:3129` as proxy
6. **Access logs** via the **Help** menu → **Open logs folder**

### PAC Mode

In `PAC` mode, the application directly evaluates the configured PAC file using a built-in JavaScript engine (`boa_engine`):
- **Remote URL:** `http://proxy.company.com/proxy.pac` or `https://...`
- **Local file:** `C:\Users\...\proxy.pac` or `file:///C:/Users/.../proxy.pac`

The PAC file configured in the application is used directly, independently of system proxy settings. All standard PAC functions are implemented (`FindProxyForURL`, `shExpMatch`, `dnsDomainIs`, `isInNet`, `dnsResolve`, `myIpAddress`, etc.).

### Notification Area (Windows)

- Closing with `X` minimizes the application to the notification area.
- Left click on the tray icon: restores the window.
- Right click: `Open` / `Quit` menu.

## Configuration Examples

### HTTP Proxy with NTLM (Windows)

```toml
proxy_type = "HTTP"
proxy_host = "proxy.company.com"
proxy_port = 8080
local_port = 3129
use_current_credentials = true
```

> NTLM/Kerberos mode via current Windows credentials (`use_current_credentials = true`) is supported on Windows.

### HTTP Proxy with manual authentication

```toml
proxy_type = "HTTP"
proxy_host = "proxy.company.com"
proxy_port = 8080
local_port = 3129
use_current_credentials = false
proxy_username = "DOMAIN\\username"
proxy_password = "password"
http_auth_protocol = "NTLM"
```

### SOCKS5 Proxy

```toml
proxy_type = "SOCKS5"
proxy_host = "socks.proxy.com"
proxy_port = 1080
local_port = 3129
```

### PAC Proxy

```toml
proxy_type = "PAC"
proxy_pac_file_location = "http://proxy.company.com/proxy.pac"
local_port = 3129
pac_cache_ttl_seconds = 300
pac_stale_ttl_seconds = 900
```

### PAC Proxy (local file)

```toml
proxy_type = "PAC"
proxy_pac_file_location = "C:\\Users\\username\\proxy.pac"
local_port = 3129
pac_cache_ttl_seconds = 300
pac_stale_ttl_seconds = 900
```

## Common Issues

### "cargo: command not found"
- Rust is not installed or the PATH is not configured
- Restart the terminal after installation
- On Windows, check that `%USERPROFILE%\.cargo\bin` is in the PATH

### Compilation errors
- Make sure you have the latest version of Rust: `rustup update`
- Clean and rebuild: `cargo clean` then `cargo build --release`

### The proxy won't start
- Check that the port is not already in use
- Check permissions (ports < 1024 require admin privileges)
- Check the logs in the console

### PAC mode is not working
- Verify that the PAC file URL or path is correct
- Verify that the PAC file is accessible (network or disk)
- Check the logs for JavaScript evaluation errors
- Verify the PAC file syntax (`FindProxyForURL` function expected)

### Authentication errors
- Check the credentials
- On Windows, try with `use_current_credentials = true`
- Check that the configured protocol matches the expected mode
- In HTTP:
   - `BASIC` + manual credentials: supported
   - `NTLM` / `KERBEROS` + `use_current_credentials = true`: supported (Windows)
   - `NTLM` / `KERBEROS` + manual credentials: not supported

## Support and Contributing

For any questions or issues:
- Refer to the main README.md
- Check the application logs
- Open an issue on GitHub

This project is in beta testing. Experience feedback and bug reports are especially appreciated.

## Development Note

**This application was developed with AI assistance.**

## Performance

Release mode is **much faster** than debug mode. Always use `--release` for normal usage:
```bash
cargo build --release
cargo run --release
```

## Updating

To update dependencies:
```bash
cargo update
cargo build --release
```

To update Rust:
```bash
rustup update
```
