# WinfoomRust

Proxy facade HTTP(S) en Rust pour travailler avec des proxies HTTP, SOCKS et PAC, avec interface graphique desktop.

Version actuelle: **0.5.0**

---

## Sommaire

- [Aperçu](#aperçu)
- [Fonctionnalités](#fonctionnalités)
- [Quick Start](#quick-start)
- [Installation (dépendances natives)](#installation-dépendances-natives)
- [Utilisation](#utilisation)
- [Configuration](#configuration)
- [Logs](#logs)
- [Dépannage](#dépannage)
- [Architecture](#architecture)
- [Roadmap](#roadmap)
- [Contribution](#contribution)
- [Licence](#licence)

## Aperçu

WinfoomRust est une réimplémentation moderne de [Winfoom](https://github.com/ecovaci/winfoom).  
L’application expose un proxy local (par défaut `127.0.0.1:3129`) et relaie les requêtes vers un proxy upstream en gérant les scénarios d’authentification et de connectivité.

## Fonctionnalités

- Types de proxy upstream:
  - `HTTP`
  - `SOCKS4` / `SOCKS5`
  - `PAC`
  - `DIRECT`
- Auth HTTP:
  - `BASIC` manuel: supporté
  - `NTLM` / `KERBEROS` + `use_current_credentials = true` (Windows): supporté
  - `NTLM` / `KERBEROS` avec credentials manuels: non supporté
- Interface graphique `egui`
- Zone de notification Windows (tray):
  - clic gauche: restaurer la fenêtre
  - clic droit: menu `Ouvrir` / `Quitter`
- Rotation quotidienne des logs + rétention
- Packaging Windows:
  - copie de `libproxy.dll` à côté de l’exécutable
  - copie de `icon.ico` à côté de l’exécutable
  - icône EXE embarquée (ressource Windows)

## Quick Start

### Prérequis

- Rust `1.75+`
- Windows, Linux ou macOS

### Build

```bash
cargo build --release
```

Binaire généré:

- Windows: `target/release/winfoomrust.exe`
- Linux/macOS: `target/release/winfoomrust`

Sous Windows, le build release copie également:

- `target/release/libproxy.dll`
- `target/release/icon.ico`

### Run

```bash
# via cargo
cargo run --release

# ou exécution directe
./target/release/winfoomrust      # Linux/macOS
.\target\release\winfoomrust.exe # Windows
```

## Installation (dépendances natives)

### Rust

Si Rust n’est pas installé:

- Windows:

```powershell
winget install Rustlang.Rustup
```

- Linux/macOS:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### libproxy (important)

Le projet dépend de `libproxy` pour la résolution PAC.

#### Windows

Le build recherche ces artefacts:

- `proxy.lib` (ou `libproxy.lib`)
- `libproxy.dll` (ou `proxy.dll`)

Installation recommandée avec `vcpkg`:

```powershell
git clone https://github.com/microsoft/vcpkg "$env:USERPROFILE\vcpkg"
& "$env:USERPROFILE\vcpkg\bootstrap-vcpkg.bat"
& "$env:USERPROFILE\vcpkg\vcpkg.exe" install libproxy:x64-windows
```

Variables optionnelles si l’auto-détection échoue:

```powershell
$env:VCPKG_ROOT = "$env:USERPROFILE\vcpkg"
$env:LIBPROXY_LIB_DIR = "C:\path\to\lib"
$env:LIBPROXY_DLL_DIR = "C:\path\to\bin"
```

#### Linux/macOS

Installer la bibliothèque système `libproxy` (et headers dev) avant compilation.

## Utilisation

1. Lancer l’application.
2. Choisir un type de proxy (`HTTP`, `SOCKS4`, `SOCKS5`, `PAC`, `DIRECT`).
3. Renseigner le proxy upstream (hôte/port).
4. Configurer l’auth si nécessaire.
5. Démarrer le proxy local.
6. Configurer les applications clientes sur `127.0.0.1:3129`.

### Tray Windows

- Fermer avec `X` masque l’app dans le tray.
- Clic gauche tray: restaure la fenêtre.
- Clic droit tray: menu `Ouvrir` / `Quitter`.

## Configuration

Le fichier est sauvegardé automatiquement:

- Windows: `%APPDATA%\winfoom-rust\config.toml`
- Linux/macOS: `~/.config/winfoom-rust/config.toml`

Exemple:

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

- Accès rapide: menu `Aide` → `Ouvrir le dossier des logs`
- Rotation: quotidienne
- Rétention par défaut: 14 fichiers
- Niveaux: `trace`, `debug`, `info`, `warn`, `error`

Mode debug:

```bash
RUST_LOG=debug cargo run --release
```

## Dépannage

### `proxy.lib introuvable` (Windows)

- Vérifier `libproxy:x64-windows` dans `vcpkg`
- Vérifier `VCPKG_ROOT`
- Sinon définir `LIBPROXY_LIB_DIR` et `LIBPROXY_DLL_DIR`

### Le proxy local ne démarre pas

- Vérifier que le port local n’est pas déjà utilisé
- Vérifier les logs

### Erreurs d’authentification

- Vérifier le protocole (`BASIC`, `NTLM`, `KERBEROS`)
- Vérifier le mode credentials (`use_current_credentials`)
- Rappel: NTLM/Kerberos manuel n’est pas supporté

## Architecture

```text
src/
├── main.rs      # Entrée app + options fenêtre
├── gui.rs       # Interface graphique
├── tray.rs      # Tray Windows natif
├── proxy.rs     # Serveur proxy local + routage upstream
├── auth.rs      # Auth HTTP / SSPI
├── pac.rs       # Résolution PAC + cache
└── config.rs    # Chargement/sauvegarde config
```

## Roadmap

- Durcir la compatibilité multi-environnements proxy
- Étendre la couverture de tests
- Améliorer la distribution binaire (packaging)

## Contribution

Les contributions sont bienvenues via issues et pull requests.

## Licence

Apache-2.0 (voir [LICENSE](LICENSE)).

## Remerciements

- Ce projet est inspiré de [Winfoom](https://github.com/ecovaci/winfoom).
- Ce projet a été développé avec utilisation de l’IA.

---

Projet inspiré de [Winfoom](https://github.com/ecovaci/winfoom).