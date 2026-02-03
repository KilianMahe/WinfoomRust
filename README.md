# WinfoomRust

**Proxy Facade pour NTLM, SOCKS et Proxy Auto Config (PAC) - Implémentation en Rust**

WinfoomRust est une réimplémentation moderne en Rust de [Winfoom](https://github.com/ecovaci/winfoom), un serveur proxy HTTP(s) facade qui permet aux applications de s'authentifier à travers différents types de proxies sans avoir à gérer le handshake d'authentification.

## ✨ Fonctionnalités

- 🔐 **Support de multiples types de proxy:**
  - HTTP avec authentification NTLM/Basic
  - SOCKS4 et SOCKS5 (avec ou sans authentification)
  - Proxy Auto Config (PAC)
  - Mode DIRECT (sans proxy)

- 🖥️ **Interface graphique moderne** avec egui
- ⚡ **Performance optimale** grâce à Rust et Tokio
- 🪟 **Support Windows natif** avec authentification système
- 🔧 **Configuration facile** via fichier TOML
- 📊 **Logging détaillé** pour le débogage
- 🚀 **Démarrage automatique** optionnel

## 📋 Prérequis

- **Rust 1.75+** (ou utilisez les binaires précompilés)
- Windows, Linux ou macOS

### Installation de Rust

Si Rust n'est pas installé sur votre système:

**Windows:**
```powershell
# Télécharger et exécuter rustup-init.exe depuis https://rustup.rs/
# Ou via winget:
winget install Rustlang.Rustup
```

**Linux/macOS:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## 🚀 Compilation

```bash
# Cloner ou naviguer vers le dossier
cd winfoom-rust

# Compiler en mode release (optimisé)
cargo build --release

# L'exécutable sera dans target/release/winfoom.exe (Windows) ou target/release/winfoom (Linux/macOS)
```

## 📖 Utilisation

### Lancer l'application

```bash
# Depuis le dossier du projet
cargo run --release

# Ou directement l'exécutable compilé
./target/release/winfoom     # Linux/macOS
.\target\release\winfoom.exe # Windows
```

### Configuration via l'interface graphique

1. **Sélectionner le type de proxy:**
   - HTTP (pour NTLM, Basic, ou autres proxies HTTP)
   - SOCKS4 ou SOCKS5
   - PAC (Proxy Auto-Config)
   - DIRECT (pas de proxy)

2. **Configurer le proxy upstream:**
   - Hôte et port du proxy
   - Credentials (si nécessaire)
   - Sur Windows: option pour utiliser les credentials système

3. **Configurer le port local:**
   - Par défaut: 3129
   - Modifier selon vos besoins

4. **Démarrer le proxy:**
   - Cliquer sur "▶ Démarrer le proxy"
   - Configurer vos applications pour utiliser `127.0.0.1:3129`

5. **Sauvegarder la configuration:**
   - Menu "Fichier" → "💾 Sauvegarder configuration"

### Fichier de configuration

Le fichier de configuration est automatiquement créé à:
- **Windows:** `%APPDATA%\winfoom-rust\config.toml`
- **Linux/macOS:** `~/.config/winfoom-rust/config.toml`

Exemple de configuration:

```toml
proxy_type = "HTTP"
proxy_host = "proxy.company.com"
proxy_port = 8080
local_port = 3129
use_current_credentials = true  # Windows uniquement
proxy_username = ""
proxy_password = ""
proxy_test_url = "https://example.com"
socket_timeout = 60
connect_timeout = 20
blacklist_timeout = 30
autostart = false
autodetect = false
api_port = 9999
log_level = "info"
```

## 🔧 Configuration du navigateur

### Firefox

1. Ouvrir les Préférences
2. Aller dans "Général" → "Paramètres réseau"
3. Configurer:
   - Proxy HTTP: `127.0.0.1` Port: `3129`
   - Cocher "Utiliser ce proxy pour tous les protocoles"

### Chrome/Edge

1. Paramètres système → Proxy
2. Configurer:
   - Proxy HTTP: `127.0.0.1:3129`

## 📝 Logs

Les logs sont disponibles dans:
- **Console** pendant l'exécution
- Niveau de log configurable: `trace`, `debug`, `info`, `warn`, `error`

Pour activer le mode debug:
```bash
RUST_LOG=debug cargo run --release
```

## 🏗️ Architecture

```
winfoom-rust/
├── src/
│   ├── main.rs          # Point d'entrée
│   ├── config.rs        # Gestion de la configuration
│   ├── proxy.rs         # Serveur proxy HTTP
│   ├── auth.rs          # Authentification NTLM/Basic
│   ├── pac.rs           # Support PAC
│   └── gui.rs           # Interface graphique egui
├── Cargo.toml           # Dépendances Rust
└── README.md
```

## 🛠️ Technologies utilisées

- **[Tokio](https://tokio.rs/)**: Runtime asynchrone
- **[Hyper](https://hyper.rs/)**: Serveur HTTP
- **[egui](https://www.egui.rs/)**: Interface graphique
- **[reqwest](https://github.com/seanmonstar/reqwest)**: Client HTTP
- **[serde](https://serde.rs/)**: Sérialisation/désérialisation

## 🐛 Dépannage

### Le proxy ne démarre pas
- Vérifier que le port local n'est pas déjà utilisé
- Vérifier les logs pour plus de détails

### Erreur d'authentification
- Vérifier les credentials
- Sur Windows, essayer "Utiliser les credentials Windows actuels"
- Vérifier que le protocole d'authentification est correct (NTLM/Basic)

### Impossible de se connecter au proxy upstream
- Vérifier l'hôte et le port du proxy
- Tester la connexion avec `ping` ou `telnet`
- Vérifier les timeouts dans les options avancées

## 🤝 Contribution

Les contributions sont les bienvenues! N'hésitez pas à:
- Ouvrir des issues pour les bugs ou suggestions
- Soumettre des Pull Requests
- Améliorer la documentation

## 📄 Licence

Apache License 2.0 - Voir le fichier LICENSE

## 🙏 Remerciements

Ce projet est inspiré de [Winfoom](https://github.com/ecovaci/winfoom) par Eugen Covaci.

## 🔗 Liens utiles

- [Documentation Rust](https://doc.rust-lang.org/)
- [Winfoom original](https://github.com/ecovaci/winfoom)
- [egui documentation](https://docs.rs/egui/)
- [Tokio documentation](https://docs.rs/tokio/)

## 📮 Support

Pour toute question ou problème:
- Ouvrir une issue sur GitHub
- Consulter la documentation
- Vérifier les logs pour plus de détails

---

**Note:** Ce projet est en développement actif. Certaines fonctionnalités avancées (comme le support complet NTLM/Kerberos et PAC) sont en cours d'implémentation.
