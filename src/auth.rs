// Gestion de l'authentification
use crate::config::Config;
use anyhow::Result;
use reqwest::Client;

pub struct AuthHandler {
    config: Config,
}

impl AuthHandler {
    pub fn new(config: Config) -> Self {
        AuthHandler { config }
    }

    pub async fn create_authenticated_client(&self, proxy_url: &str) -> Result<Client> {
        tracing::debug!("Création client avec proxy: {}", proxy_url);
        
        let mut client_builder = Client::builder();

        // Configurer le proxy avec authentification si nécessaire
        let proxy = match reqwest::Proxy::all(proxy_url) {
            Ok(p) => {
                if !self.config.use_current_credentials && !self.config.proxy_username.is_empty() {
                    // Ajouter l'authentification Basic
                    p.basic_auth(
                        &self.config.proxy_username,
                        &self.config.proxy_password,
                    )
                } else {
                    // Pas d'authentification ou credentials Windows (TODO)
                    p
                }
            },
            Err(e) => {
                tracing::error!("Erreur parsing proxy URL '{}': {}", proxy_url, e);
                return Err(anyhow::anyhow!("URL proxy invalide '{}': {}", proxy_url, e));
            }
        };

        // Ajouter le proxy au builder
        client_builder = client_builder.proxy(proxy);

        // Timeouts
        client_builder = client_builder
            .timeout(std::time::Duration::from_secs(self.config.socket_timeout))
            .connect_timeout(std::time::Duration::from_secs(self.config.connect_timeout));

        match client_builder.build() {
            Ok(client) => {
                tracing::debug!("Client créé avec succès");
                Ok(client)
            },
            Err(e) => {
                tracing::error!("Erreur construction client: {}", e);
                Err(anyhow::anyhow!("Impossible de construire le client HTTP: {}", e))
            }
        }
    }

    #[cfg(windows)]
    pub fn get_windows_credentials(&self) -> Result<(String, String)> {
        // TODO: Implémenter la récupération des credentials Windows
        // En utilisant l'API Windows Security
        Ok((String::new(), String::new()))
    }
}

// Authentification NTLM
pub struct NtlmAuthenticator {
    username: String,
    password: String,
    domain: Option<String>,
}

impl NtlmAuthenticator {
    pub fn new(username: String, password: String) -> Self {
        let (domain, user) = if username.contains('\\') {
            let parts: Vec<&str> = username.split('\\').collect();
            (Some(parts[0].to_string()), parts[1].to_string())
        } else {
            (None, username)
        };

        NtlmAuthenticator {
            username: user,
            password,
            domain,
        }
    }

    pub fn create_type1_message(&self) -> Result<String> {
        // TODO: Implémenter le message NTLM Type 1
        // Pour l'instant, retourner une string vide
        Ok(String::new())
    }

    pub fn create_type3_message(&self, type2_message: &str) -> Result<String> {
        // TODO: Implémenter le message NTLM Type 3
        // Pour l'instant, retourner une string vide
        Ok(String::new())
    }
}
