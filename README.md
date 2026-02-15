# WinfoomRust

> **⚠️ Projet en cours de développement — version de test (beta)**

Proxy facade HTTP(S) en Rust pour travailler avec des proxies HTTP, SOCKS et PAC, avec interface graphique desktop.

Version actuelle: **0.6.0**

**Ce projet est open source et développé avec assistance de l'IA.**

---

## Sommaire

- [Aperçu](#aperçu)
- [Fonctionnalités](#fonctionnalités)
- [Quick Start](#quick-start)
- [Installation](#installation)
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
L'application expose un proxy local (par défaut `127.0.0.1:3129`) et relaie les requêtes vers un proxy upstream en gérant les scénarios d'authentification et de connectivité.

## Fonctionnalités

- Types de proxy upstream:
  - `HTTP`
  - `SOCKS4` / `SOCKS5`
  - `PAC` (évaluation intégrée via moteur JavaScript)
  - `DIRECT`
- Évaluation PAC intégrée:
  - Moteur JavaScript embarqué (`boa_engine`) — **aucune dépendance native requise**
  - Support des fichiers PAC locaux (`C:\...\proxy.pac`, `file:///...`) et distants (`http://...`)
  - Implémentation complète des fonctions PAC standard (`FindProxyForURL`, `shExpMatch`, `dnsDomainIs`, `isInNet`, `dnsResolve`, `myIpAddress`, etc.)
  - Cache avec TTL configurable et mécanisme stale-while-revalidate
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
  - icône EXE embarquée (ressource Windows)
  - icône tray embarquée dans le binaire

## Quick Start

### Prérequis

- Rust `1.75+`
- Windows, Linux ou macOS
- **Aucune dépendance native** (toutes les dépendances sont gérées par Cargo)

### Build

```bash
cargo build --release
```

Binaire généré:

- Windows: `target/release/winfoomrust.exe`
- Linux/macOS: `target/release/winfoomrust`

Sous Windows, l'icône est automatiquement embarquée dans l'exécutable.

### Run

```bash
# via cargo
cargo run --release

# ou exécution directe
./target/release/winfoomrust      # Linux/macOS
.\target\release\winfoomrust.exe # Windows
```

## Installation

### Rust

Si Rust n'est pas installé:

- Windows:

```powershell
winget install Rustlang.Rustup
```

- Linux/macOS:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### Dépendances

Toutes les dépendances sont des crates Rust gérées automatiquement par Cargo lors de la compilation. **Aucune bibliothèque native externe n'est requise.**

> **Note:** L'ancienne dépendance `libproxy` a été remplacée dans la version 0.6 par un évaluateur PAC intégré basé sur `boa_engine` (moteur JavaScript pur Rust). Il n'est plus nécessaire d'installer `vcpkg`, `libproxy.dll` ou `proxy.lib`.

## Utilisation

1. Lancer l'application.
2. Choisir un type de proxy (`HTTP`, `SOCKS4`, `SOCKS5`, `PAC`, `DIRECT`).
3. Renseigner le proxy upstream (hôte/port).
4. Configurer l'auth si nécessaire.
5. Démarrer le proxy local.
6. Configurer les applications clientes sur `127.0.0.1:3129`.

### Mode PAC

En mode `PAC`, l'application évalue directement le fichier PAC configuré:
- **URL distante:** `http://proxy.company.com/proxy.pac` ou `https://...`
- **Fichier local:** `C:\Users\...\proxy.pac` ou `file:///C:/Users/.../proxy.pac`

L'évaluation utilise un moteur JavaScript intégré (`boa_engine`) qui implémente toutes les fonctions PAC standard. Le fichier PAC configuré dans l'application est directement utilisé, indépendamment des paramètres proxy du système.

### Tray Windows

- Fermer avec `X` masque l'app dans le tray.
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

### Le proxy local ne démarre pas

- Vérifier que le port local n'est pas déjà utilisé
- Vérifier les logs

### Le mode PAC ne fonctionne pas

- Vérifier que l'URL ou le chemin du fichier PAC est correct
- Vérifier que le fichier PAC est accessible (réseau ou disque)
- Consulter les logs pour les erreurs d'évaluation JavaScript
- Vérifier la syntaxe du fichier PAC (fonction `FindProxyForURL` attendue)

### Erreurs d'authentification

- Vérifier le protocole (`BASIC`, `NTLM`, `KERBEROS`)
- Vérifier le mode credentials (`use_current_credentials`)
- Rappel: NTLM/Kerberos manuel n'est pas supporté

### Erreurs de compilation

- Vérifier que vous avez la dernière version de Rust: `rustup update`
- Nettoyer et recompiler: `cargo clean` puis `cargo build --release`

## Architecture

```text
src/
├── main.rs      # Entrée app + options fenêtre
├── gui.rs       # Interface graphique (egui/eframe)
├── tray.rs      # Tray Windows natif
├── proxy.rs     # Serveur proxy local + routage upstream
├── auth.rs      # Auth HTTP / SSPI
├── pac.rs       # Évaluateur PAC intégré (boa_engine) + cache
└── config.rs    # Chargement/sauvegarde config
```

### Technologies principales

| Composant | Crate | Rôle |
|-----------|-------|------|
| GUI | `egui` / `eframe` 0.28 | Interface graphique desktop |
| Serveur proxy | `hyper` 1.4 + `tokio` 1.38 | Serveur HTTP asynchrone |
| Client HTTP | `reqwest` 0.12 | Client HTTP (upstream + téléchargement PAC) |
| Évaluation PAC | `boa_engine` 0.20 | Moteur JavaScript pur Rust |
| Auth Windows | `windows` 0.58 | SSPI (NTLM/Kerberos) |

## Roadmap

- Durcir la compatibilité multi-environnements proxy
- Étendre la couverture de tests
- Améliorer la distribution binaire (packaging)
- Implémenter complètement les fonctions PAC temporelles (`weekdayRange`, `dateRange`, `timeRange`)

## Contribution

Les contributions sont bienvenues via issues et pull requests sur GitHub.

Ce projet est en phase de test (beta). Les retours d'expérience et rapports de bugs sont particulièrement appréciés.

## Licence

Apache-2.0 (voir [LICENSE](LICENSE)).

## Remerciements

- Ce projet est inspiré de [Winfoom](https://github.com/ecovaci/winfoom).
- **Ce projet a été développé avec assistance de l'IA.**

---

Projet inspiré de [Winfoom](https://github.com/ecovaci/winfoom).
