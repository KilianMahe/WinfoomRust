// Application configuration
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyType {
    HTTP,
    SOCKS4,
    SOCKS5,
    PAC,
    DIRECT,
}

impl Default for ProxyType {
    fn default() -> Self {
        ProxyType::HTTP
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HttpAuthProtocol {
    NTLM,
    BASIC,
    KERBEROS,
}

impl Default for HttpAuthProtocol {
    fn default() -> Self {
        HttpAuthProtocol::NTLM
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    // Configuration du proxy
    pub proxy_type: ProxyType,
    pub proxy_host: String,
    pub proxy_port: u16,
    
    // Port local
    pub local_port: u16,
    
    // Authentification
    pub use_current_credentials: bool,
    pub proxy_username: String,
    pub proxy_password: String,
    pub http_auth_protocol: HttpAuthProtocol,
    
    // Configuration PAC
    pub proxy_pac_file_location: String,
    pub pac_http_auth_protocol: Option<HttpAuthProtocol>,
    
    // Tests
    pub proxy_test_url: String,
    
    // Timeouts (en secondes)
    pub socket_timeout: u64,
    pub connect_timeout: u64,
    pub blacklist_timeout: u64,

    // Cache PAC (en secondes)
    pub pac_cache_ttl_seconds: u64,
    pub pac_stale_ttl_seconds: u64,
    
    // Auto-start
    pub autostart: bool,
    pub start_minimized: bool,
    pub autodetect: bool,
    
    // API
    pub api_port: u16,
    
    // Logging
    pub log_level: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            proxy_type: ProxyType::HTTP,
            proxy_host: String::new(),
            proxy_port: 80,
            local_port: 3129,
            use_current_credentials: cfg!(windows),
            proxy_username: String::new(),
            proxy_password: String::new(),
            http_auth_protocol: HttpAuthProtocol::NTLM,
            proxy_pac_file_location: String::new(),
            pac_http_auth_protocol: None,
            proxy_test_url: "https://example.com".to_string(),
            socket_timeout: 5,
            connect_timeout: 5,
            blacklist_timeout: 200,
            pac_cache_ttl_seconds: 300,
            pac_stale_ttl_seconds: 900,
            autostart: false,
            start_minimized: false,
            autodetect: false,
            api_port: 3128,
            log_level: "info".to_string(),
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;
        
        if !config_path.exists() {
            tracing::info!("Configuration not found, using default values");
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&config_path)?;
        let config: Config = toml::from_str(&content)?;
        
        tracing::info!("Configuration loaded from {:?}", config_path);
        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;
        
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)?;
        std::fs::write(&config_path, content)?;
        
        tracing::info!("Configuration saved to {:?}", config_path);
        Ok(())
    }

    fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("Unable to find configuration directory"))?;
        
        Ok(config_dir.join("winfoom-rust").join("config.toml"))
    }
}

// Pour dirs
#[cfg(windows)]
mod dirs {
    use std::path::PathBuf;
    
    pub fn config_dir() -> Option<PathBuf> {
        std::env::var("APPDATA")
            .ok()
            .map(PathBuf::from)
    }
}

#[cfg(not(windows))]
mod dirs {
    use std::path::PathBuf;
    
    pub fn config_dir() -> Option<PathBuf> {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".config"))
    }
}
