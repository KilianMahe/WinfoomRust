// Support pour Proxy Auto Config (PAC)
use anyhow::Result;
use libproxy::ProxyFactory;
use std::sync::Mutex;

pub struct PacResolver {
    factory: Mutex<ProxyFactory>,
}

impl PacResolver {
    /// Crée une nouvelle instance de PacResolver avec libproxy
    pub fn new() -> Result<Self> {
        tracing::info!("Initialisation du PacResolver avec libproxy");
        
        let factory = ProxyFactory::new()
            .ok_or_else(|| anyhow::anyhow!("Impossible d'initialiser ProxyFactory"))?;
        
        Ok(PacResolver {
            factory: Mutex::new(factory),
        })
    }

    /// Résout les proxies pour une URL donnée
    pub fn resolve(&self, url: &str) -> Result<Vec<String>> {
        tracing::debug!("Résolution des proxies pour: {}", url);
        
        let factory = self.factory.lock().map_err(|e| {
            anyhow::anyhow!("Impossible d'acquérir le verrou du factory: {}", e)
        })?;
        
        match factory.get_proxies(url) {
            Ok(proxies) => {
                let proxy_list: Vec<String> = proxies
                    .iter()
                    .map(|p| p.to_string())
                    .collect();
                
                if proxy_list.is_empty() {
                    tracing::warn!("Aucun proxy trouvé pour: {}", url);
                    Ok(vec!["DIRECT".to_string()])
                } else {
                    tracing::info!("Proxies trouvés pour {}: {:?}", url, proxy_list);
                    Ok(proxy_list)
                }
            }
            Err(e) => {
                tracing::error!("Erreur lors de la résolution des proxies: {:?}", e);
                Ok(vec!["DIRECT".to_string()])
            }
        }
    }

}
