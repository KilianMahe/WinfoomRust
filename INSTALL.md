# WinfoomRust - Guide de Compilation et d'Utilisation

Version actuelle: **0.5**

## Installation de Rust (si nécessaire)

### Windows

1. **Télécharger rustup-init.exe** depuis https://rustup.rs/
2. **Exécuter l'installeur** et suivre les instructions
3. **Redémarrer le terminal** pour que les changements prennent effet

Ou via winget:
```powershell
winget install Rustlang.Rustup
```

### Linux/macOS

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## Vérifier l'installation

```bash
rustc --version
cargo --version
```

## Compilation

```bash
# Naviguer vers le dossier
cd winfoom-rust

# Compiler en mode debug (plus rapide à compiler, plus lent à exécuter)
cargo build

# Compiler en mode release (optimisé pour la performance)
cargo build --release
```

Les exécutables seront dans:
- Mode debug: `target/debug/winfoom` (ou `.exe` sur Windows)
- Mode release: `target/release/winfoom` (ou `.exe` sur Windows)

## Exécution

```bash
# Directement avec cargo (recompile si nécessaire)
cargo run --release

# Ou exécuter le binaire compilé
./target/release/winfoom      # Linux/macOS
.\target\release\winfoom.exe  # Windows
```

## Configuration

L'application créera automatiquement un fichier de configuration à:
- **Windows:** `%APPDATA%\winfoom-rust\config.toml`
- **Linux:** `~/.config/winfoom-rust/config.toml`
- **macOS:** `~/Library/Application Support/winfoom-rust/config.toml`

## Utilisation

1. **Lancer l'application** - Une fenêtre graphique s'ouvrira
2. **Configurer le proxy upstream:**
   - Sélectionner le type de proxy (HTTP, SOCKS4, SOCKS5, PAC, ou DIRECT)
   - Entrer l'hôte et le port du proxy
   - Configurer l'authentification si nécessaire
3. **Configurer le port local** (par défaut: 3129)
4. **Démarrer le proxy** en cliquant sur "▶ Démarrer le proxy"
5. **Configurer vos applications** pour utiliser `127.0.0.1:3129` comme proxy
6. **Accéder aux logs** via le menu **Aide** → **Ouvrir le dossier des logs**

## Exemples de configuration

### Proxy HTTP avec NTLM (Windows)

```toml
proxy_type = "HTTP"
proxy_host = "proxy.company.com"
proxy_port = 8080
local_port = 3129
use_current_credentials = true
```

> Ce mode est explicite dans l'application. Tant que le handshake NTLM/SSPI complet n'est pas implémenté, il est signalé comme non supporté.

### Proxy HTTP avec authentification manuelle

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

### Proxy SOCKS5

```toml
proxy_type = "SOCKS5"
proxy_host = "socks.proxy.com"
proxy_port = 1080
local_port = 3129
```

### Proxy PAC

```toml
proxy_type = "PAC"
proxy_pac_file_location = "http://proxy.company.com/proxy.pac"
local_port = 3129
```

## Dépendances

L'application téléchargera automatiquement toutes les dépendances Rust lors de la première compilation. Cela peut prendre quelques minutes.

Une bibliothèque dédiée est également utilisée pour la gestion proxy/PAC pendant l'installation des dépendances: `libproxy`.

Si vous rencontrez des problèmes de compilation, essayez:
```bash
cargo clean
cargo build --release
```

## Problèmes courants

### "cargo: command not found"
- Rust n'est pas installé ou le PATH n'est pas configuré
- Redémarrer le terminal après l'installation
- Sur Windows, vérifier que `%USERPROFILE%\.cargo\bin` est dans le PATH

### Erreurs de compilation
- Vérifier que vous avez la dernière version de Rust: `rustup update`
- Nettoyer et recompiler: `cargo clean && cargo build --release`

### Le proxy ne démarre pas
- Vérifier que le port n'est pas déjà utilisé
- Vérifier les permissions (les ports < 1024 nécessitent des privilèges admin)
- Consulter les logs dans la console

### Erreurs d'authentification
- Vérifier les credentials
- Sur Windows, essayer avec `use_current_credentials = true`
- Vérifier que le protocole configuré correspond au mode attendu
- Si NTLM/Kerberos est configuré, l'application affiche explicitement que ce mode n'est pas encore supporté (handshake complet requis)

## Support et contribution

Pour toute question ou problème:
- Consulter le README.md principal
- Vérifier les logs de l'application
- Ouvrir une issue sur GitHub

## Note de développement

Cette application a été développée avec assistance IA.

## Performances

Le mode release est **beaucoup plus rapide** que le mode debug. Toujours utiliser `--release` pour une utilisation normale:
```bash
cargo build --release
cargo run --release
```

## Mise à jour

Pour mettre à jour les dépendances:
```bash
cargo update
cargo build --release
```

Pour mettre à jour Rust:
```bash
rustup update
```
