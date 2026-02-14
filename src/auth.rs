// Gestion de l'authentification
use crate::config::Config;
use crate::config::HttpAuthProtocol;
use anyhow::Result;
use base64::Engine;
use reqwest::Client;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyAuthMode {
    None,
    ManualBasic,
    WindowsCurrentCredentials,
    UnsupportedNtlmSspi,
}

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
        let auth_mode = self.auth_mode();

        tracing::debug!("Mode d'authentification sélectionné: {:?}", auth_mode);

        // Configurer le proxy avec authentification si nécessaire
        let proxy = match reqwest::Proxy::all(proxy_url) {
            Ok(p) => match auth_mode {
                ProxyAuthMode::ManualBasic => {
                    if self.config.proxy_password.is_empty() {
                        anyhow::bail!("Mode ManualBasic activé mais proxy_password est vide");
                    }

                    p.basic_auth(
                        &self.config.proxy_username,
                        &self.config.proxy_password,
                    )
                }
                ProxyAuthMode::WindowsCurrentCredentials => {
                    #[cfg(windows)]
                    {
                        let (username, password) = self.get_windows_credentials()?;
                        p.basic_auth(&username, &password)
                    }

                    #[cfg(not(windows))]
                    {
                        anyhow::bail!(
                            "Mode WindowsCurrentCredentials demandé sur un système non-Windows"
                        );
                    }
                }
                ProxyAuthMode::UnsupportedNtlmSspi => {
                    anyhow::bail!(
                        "Mode NTLM/SSPI non supporté actuellement: handshake NTLM/Kerberos complet non implémenté"
                    );
                }
                ProxyAuthMode::None => p,
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

    pub fn auth_mode(&self) -> ProxyAuthMode {
        let auth_requested = self.config.use_current_credentials
            || !self.config.proxy_username.is_empty()
            || !self.config.proxy_password.is_empty();

        if auth_requested
            && matches!(self.config.http_auth_protocol, HttpAuthProtocol::NTLM | HttpAuthProtocol::KERBEROS)
        {
            return ProxyAuthMode::UnsupportedNtlmSspi;
        }

        if self.config.use_current_credentials {
            ProxyAuthMode::WindowsCurrentCredentials
        } else if !self.config.proxy_username.is_empty() {
            ProxyAuthMode::ManualBasic
        } else {
            ProxyAuthMode::None
        }
    }

    #[cfg(windows)]
    pub fn get_windows_credentials(&self) -> Result<(String, String)> {
        let username = if !self.config.proxy_username.is_empty() {
            self.config.proxy_username.clone()
        } else {
            let user = std::env::var("USERNAME").unwrap_or_default();
            let domain = std::env::var("USERDOMAIN").unwrap_or_default();

            if user.is_empty() {
                anyhow::bail!("USERNAME introuvable dans l'environnement");
            }

            if domain.is_empty() {
                user
            } else {
                format!("{}\\{}", domain, user)
            }
        };

        let password = if !self.config.proxy_password.is_empty() {
            self.config.proxy_password.clone()
        } else {
            std::env::var("WINFOOM_PROXY_PASSWORD").unwrap_or_default()
        };

        if password.is_empty() {
            anyhow::bail!(
                "Mode WindowsCurrentCredentials: mot de passe introuvable. Définis proxy_password ou WINFOOM_PROXY_PASSWORD"
            );
        }

        Ok((username, password))
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
        let domain = self.domain.clone().unwrap_or_default().to_uppercase();
        let workstation = std::env::var("COMPUTERNAME").unwrap_or_default().to_uppercase();

        let domain_bytes = domain.as_bytes();
        let workstation_bytes = workstation.as_bytes();

        let payload_offset = 32u32;
        let workstation_offset = payload_offset;
        let domain_offset = payload_offset + workstation_bytes.len() as u32;

        let flags: u32 =
            0x0000_0001 | // NEGOTIATE_UNICODE
            0x0000_0200 | // NEGOTIATE_NTLM
            0x0000_1000 | // NEGOTIATE_OEM_DOMAIN_SUPPLIED
            0x0000_2000 | // NEGOTIATE_OEM_WORKSTATION_SUPPLIED
            0x0008_0000 | // NEGOTIATE_ALWAYS_SIGN
            0x2000_0000;  // NEGOTIATE_128

        let mut msg = Vec::with_capacity(32 + workstation_bytes.len() + domain_bytes.len());
        msg.extend_from_slice(b"NTLMSSP\0");
        msg.extend_from_slice(&1u32.to_le_bytes());
        msg.extend_from_slice(&flags.to_le_bytes());

        // Security buffer Domain (len, alloc, offset)
        msg.extend_from_slice(&(domain_bytes.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(domain_bytes.len() as u16).to_le_bytes());
        msg.extend_from_slice(&domain_offset.to_le_bytes());

        // Security buffer Workstation (len, alloc, offset)
        msg.extend_from_slice(&(workstation_bytes.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(workstation_bytes.len() as u16).to_le_bytes());
        msg.extend_from_slice(&workstation_offset.to_le_bytes());

        // Payload: Workstation puis Domain
        msg.extend_from_slice(workstation_bytes);
        msg.extend_from_slice(domain_bytes);

        Ok(base64::engine::general_purpose::STANDARD.encode(msg))
    }

    pub fn create_type3_message(&self, type2_message: &str) -> Result<String> {
        if type2_message.trim().is_empty() {
            anyhow::bail!("Message NTLM Type 2 vide");
        }

        anyhow::bail!(
            "NTLM Type 3 n'est pas encore supporté dans cette version (challenge-response NTLM complet requis)"
        )
    }
}
