// Support pour Proxy Auto Config (PAC)
use anyhow::Result;
use std::collections::HashMap;
use url::Url;

pub struct PacResolver {
    pac_script: String,
    cache: HashMap<String, Vec<String>>,
}

impl PacResolver {
    pub async fn new(pac_location: &str) -> Result<Self> {
        let pac_script = Self::load_pac_script(pac_location).await?;
        
        Ok(PacResolver {
            pac_script,
            cache: HashMap::new(),
        })
    }

    async fn load_pac_script(location: &str) -> Result<String> {
        tracing::info!("Chargement du fichier PAC depuis: {}", location);
        
        if location.starts_with("http://") || location.starts_with("https://") {
            // Télécharger depuis une URL
            let response = reqwest::get(location).await?;
            let script = response.text().await?;
            tracing::debug!("Fichier PAC téléchargé, taille: {} octets", script.len());
            Ok(script)
        } else {
            // Lire depuis un fichier local
            let script = std::fs::read_to_string(location)?;
            tracing::debug!("Fichier PAC lu, taille: {} octets", script.len());
            Ok(script)
        }
    }
    
    /// Extrait les proxies du script PAC (parsing simplifié)
    pub fn extract_proxies(&self) -> Vec<String> {
        let mut proxies = Vec::new();
        
        // Chercher les patterns "PROXY host:port" dans le script
        for line in self.pac_script.lines() {
            // Pattern: return "PROXY proxy.example.com:8080"
            if let Some(start) = line.find("PROXY ") {
                let rest = &line[start + 6..];
                // Extraire jusqu'au guillemet ou point-virgule
                if let Some(end_pos) = rest.find(|c: char| c == '"' || c == ';' || c == ' ') {
                    let proxy = rest[..end_pos].trim().to_string();
                    if !proxy.is_empty() && proxy.contains(':') {
                        proxies.push(proxy);
                    }
                }
            }
        }
        
        if proxies.is_empty() {
            tracing::warn!("Aucun proxy trouvé dans le fichier PAC");
        } else {
            tracing::info!("Proxies extraits du PAC: {:?}", proxies);
        }
        
        proxies
    }

    pub fn resolve(&mut self, url: &str) -> Result<Vec<String>> {
        // Vérifier le cache
        if let Some(proxies) = self.cache.get(url) {
            return Ok(proxies.clone());
        }

        // Parser l'URL
        let parsed_url = Url::parse(url)?;
        let host = parsed_url.host_str().unwrap_or("");
        
        // TODO: Implémenter un vrai moteur JavaScript pour exécuter le script PAC
        // Pour l'instant, retourner DIRECT
        let proxies = vec!["DIRECT".to_string()];
        
        // Mettre en cache
        self.cache.insert(url.to_string(), proxies.clone());
        
        Ok(proxies)
    }

    pub fn parse_proxy_string(proxy_str: &str) -> Vec<ProxyInfo> {
        proxy_str
            .split(';')
            .filter_map(|s| {
                let s = s.trim();
                if s.is_empty() {
                    return None;
                }

                if s.eq_ignore_ascii_case("DIRECT") {
                    return Some(ProxyInfo::Direct);
                }

                let parts: Vec<&str> = s.split_whitespace().collect();
                if parts.len() != 2 {
                    return None;
                }

                let proxy_type = parts[0].to_uppercase();
                let host_port = parts[1];

                let host_port_parts: Vec<&str> = host_port.split(':').collect();
                if host_port_parts.len() != 2 {
                    return None;
                }

                let host = host_port_parts[0].to_string();
                let port = host_port_parts[1].parse().ok()?;

                match proxy_type.as_str() {
                    "PROXY" | "HTTP" => Some(ProxyInfo::Http { host, port }),
                    "SOCKS" | "SOCKS5" => Some(ProxyInfo::Socks5 { host, port }),
                    "SOCKS4" => Some(ProxyInfo::Socks4 { host, port }),
                    _ => None,
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub enum ProxyInfo {
    Direct,
    Http { host: String, port: u16 },
    Socks4 { host: String, port: u16 },
    Socks5 { host: String, port: u16 },
}

// Fonctions JavaScript PAC standard
pub struct PacFunctions;

impl PacFunctions {
    pub fn is_plain_host_name(host: &str) -> bool {
        !host.contains('.')
    }

    pub fn dns_domain_is(host: &str, domain: &str) -> bool {
        host.eq_ignore_ascii_case(domain)
    }

    pub fn local_host_or_domain_is(host: &str, hostdom: &str) -> bool {
        host.eq_ignore_ascii_case(hostdom) || 
        host.starts_with(&format!("{}.", hostdom))
    }
}
