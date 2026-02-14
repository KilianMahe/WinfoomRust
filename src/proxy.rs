// Serveur proxy HTTP
use crate::config::Config;
use crate::config::ProxyType;
use crate::auth::AuthHandler;
use anyhow::Result;
use reqwest::Client;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::io::AsyncWriteExt;

pub struct ProxyServer {
    config: Arc<Mutex<Config>>,
    auth_handler: Arc<AuthHandler>,
    listener: Option<TcpListener>,
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ProxyServer {
    pub fn new(config: Config) -> Self {
        ProxyServer {
            config: Arc::new(Mutex::new(config.clone())),
            auth_handler: Arc::new(AuthHandler::new(config)),
            listener: None,
            server_handle: None,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        // Arrêter le serveur précédent s'il existe
        if self.server_handle.is_some() {
            self.stop().await?;
        }
        
        let config = self.config.lock().await;
        let addr = SocketAddr::from(([127, 0, 0, 1], config.local_port));
        drop(config);

        tracing::info!("Démarrage du serveur proxy sur {}", addr);

        let listener = TcpListener::bind(addr).await?;
        
        let config = Arc::clone(&self.config);
        let auth_handler = Arc::clone(&self.auth_handler);
        
        // Lancer le serveur dans une tâche séparée
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, client_addr)) => {
                        tracing::debug!("Nouvelle connexion de {}", client_addr);
                        let config = Arc::clone(&config);
                        let auth_handler = Arc::clone(&auth_handler);
                        
                        tokio::spawn(async move {
                            use tokio::io::{AsyncReadExt};
                            
                            let mut stream = stream;
                            let mut buffer = vec![0u8; 4096];
                            
                            // Lire les données de la requête
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(10),
                                stream.read(&mut buffer)
                            ).await {
                                Ok(Ok(n)) if n > 0 => {
                                    let request_str = String::from_utf8_lossy(&buffer[..n]);
                                    let first_line = request_str.lines().next().unwrap_or("");
                                    
                                    // Détecter CONNECT
                                    if first_line.starts_with("CONNECT ") {
                                        tracing::debug!("Détection requête CONNECT depuis {}", client_addr);
                                        
                                        // Extraire host:port
                                        if let Some(host_port) = extract_connect_host(first_line) {
                                            // Envoyer "200 Connection Established"
                                            let response = b"HTTP/1.1 200 Connection Established\r\n\r\n";
                                            if let Err(e) = stream.write_all(response).await {
                                                tracing::error!("Erreur envoi réponse CONNECT: {}", e);
                                                return;
                                            }
                                            
                                            if let Err(e) = stream.flush().await {
                                                tracing::error!("Erreur flush réponse CONNECT: {}", e);
                                                return;
                                            }
                                            
                                            tracing::info!("Établissement tunnel CONNECT vers: {}", host_port);
                                            
                                            // Se connecter au serveur de destination
                                            let mut server_stream = match tokio::net::TcpStream::connect(&host_port).await {
                                                Ok(s) => {
                                                    tracing::debug!("Connecté avec succès à {}", host_port);
                                                    s
                                                },
                                                Err(e) => {
                                                    tracing::error!("Impossible de se connecter à {}: {}", host_port, e);
                                                    return;
                                                }
                                            };
                                            
                                            // Maintenant faire le tunneling
                                            tracing::debug!("Tunnel établi vers {} - démarrage du forwarding", host_port);
                                            
                                            let (mut client_read, mut client_write) = stream.split();
                                            let (mut server_read, mut server_write) = server_stream.split();
                                            
                                            tokio::select! {
                                                res = tokio::io::copy(&mut client_read, &mut server_write) => {
                                                    match res {
                                                        Ok(n) => tracing::debug!("Client->Server: {} bytes", n),
                                                        Err(e) => tracing::debug!("Erreur Client->Server: {}", e),
                                                    }
                                                }
                                                res = tokio::io::copy(&mut server_read, &mut client_write) => {
                                                    match res {
                                                        Ok(n) => tracing::debug!("Server->Client: {} bytes", n),
                                                        Err(e) => tracing::debug!("Erreur Server->Client: {}", e),
                                                    }
                                                }
                                            };
                                            
                                            let _ = client_write.shutdown().await;
                                            let _ = server_write.shutdown().await;
                                            
                                            tracing::debug!("Tunnel CONNECT vers {} fermé", host_port);
                                            return;
                                        }
                                        
                                        tracing::error!("Erreur gestion tunnel CONNECT");
                                        return;
                                    }
                                    
                                    // Si ce n'est pas CONNECT, traiter comme requête HTTP
                                    // Extraire méthode, URI et version
                                    let parts: Vec<&str> = first_line.split_whitespace().collect();
                                    if parts.len() >= 2 {
                                        let method = parts[0];
                                        let uri = parts[1];
                                        
                                        tracing::debug!("Requête HTTP: {} {}", method, uri);
                                        
                                        // Faire la requête directe
                                        let url = if uri.starts_with("http://") || uri.starts_with("https://") {
                                            uri.to_string()
                                        } else {
                                            format!("http://{}", uri)
                                        };

                                        let request_config = config.lock().await.clone();
                                        let client = match create_forward_client(&request_config, auth_handler.as_ref()).await {
                                            Ok(client) => client,
                                            Err(e) => {
                                                tracing::error!("Erreur création client proxy HTTP: {}", e);
                                                let body = format!("Proxy configuration error: {}", e);
                                                let response = format!(
                                                    "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
                                                    body.len(),
                                                    body
                                                );
                                                let _ = stream.write_all(response.as_bytes()).await;
                                                let _ = stream.flush().await;
                                                return;
                                            }
                                        };

                                        let response = match method {
                                            "GET" => client.get(&url).send().await,
                                            "HEAD" => client.head(&url).send().await,
                                            "POST" => client.post(&url).send().await,
                                            _ => {
                                                tracing::warn!("Méthode HTTP non supportée: {}", method);
                                                return;
                                            }
                                        };
                                        
                                        if let Ok(resp) = response {
                                            // Construire la réponse HTTP
                                            let status = resp.status();
                                            let mut response_str = format!("HTTP/1.1 {}\r\n", status);
                                            
                                            // Ajouter les headers importants
                                            for (name, value) in resp.headers() {
                                                if let Ok(val) = value.to_str() {
                                                    response_str.push_str(&format!("{}: {}\r\n", name, val));
                                                }
                                            }
                                            response_str.push_str("\r\n");
                                            
                                            // Envoyer les headers
                                            let _ = stream.write_all(response_str.as_bytes()).await;
                                            
                                            // Envoyer le body
                                            if let Ok(body) = resp.bytes().await {
                                                let _ = stream.write_all(&body).await;
                                            }
                                            
                                            let _ = stream.flush().await;
                                            tracing::debug!("Réponse HTTP envoyée: {} {}", status, uri);
                                        }
                                    }
                                    return;
                                    }
                                Ok(Ok(_)) => {
                                    tracing::debug!("Connexion fermée immédiatement par {}", client_addr);
                                }
                                Ok(Err(e)) => {
                                    tracing::error!("Erreur lecture depuis {}: {}", client_addr, e);
                                }
                                Err(_) => {
                                    tracing::warn!("Timeout lecture depuis {}", client_addr);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Erreur accept: {}", e);
                        break;
                    }
                }
            }
            
            tracing::info!("Boucle serveur terminée");
        });
        
        self.server_handle = Some(handle);
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        tracing::info!("Arrêt du serveur proxy");
        
        // Annuler la tâche serveur
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
            tracing::debug!("Tâche serveur annulée");
        }
        
        // Fermer le listener
        if let Some(listener) = self.listener.take() {
            drop(listener);
            tracing::debug!("Listener fermé");
        }
        
        // Attendre un peu pour que le port soit libéré
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        
        tracing::info!("Serveur proxy arrêté");
        Ok(())
    }

}

async fn create_forward_client(config: &Config, auth_handler: &AuthHandler) -> Result<Client> {
    if let Some(proxy_url) = build_upstream_proxy_url(config)? {
        tracing::debug!("Utilisation proxy upstream: {}", proxy_url);
        return auth_handler.create_authenticated_client(&proxy_url).await;
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.socket_timeout))
        .connect_timeout(std::time::Duration::from_secs(config.connect_timeout))
        .build()?;

    Ok(client)
}

fn build_upstream_proxy_url(config: &Config) -> Result<Option<String>> {
    match config.proxy_type {
        ProxyType::DIRECT => Ok(None),
        ProxyType::PAC => Err(anyhow::anyhow!(
            "Mode PAC non supporté pour le forwarding HTTP dans cette version"
        )),
        ProxyType::HTTP | ProxyType::SOCKS4 | ProxyType::SOCKS5 => {
            if config.proxy_host.trim().is_empty() {
                return Err(anyhow::anyhow!("proxy_host est vide"));
            }

            let scheme = match config.proxy_type {
                ProxyType::HTTP => "http",
                ProxyType::SOCKS4 => "socks4",
                ProxyType::SOCKS5 => "socks5h",
                _ => unreachable!(),
            };

            Ok(Some(format!("{}://{}:{}", scheme, config.proxy_host, config.proxy_port)))
        }
    }
}

// Extraire host:port de la ligne CONNECT
fn extract_connect_host(request_line: &str) -> Option<String> {
    // Format: "CONNECT host:port HTTP/1.1"
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() >= 2 && parts[0] == "CONNECT" {
        return Some(parts[1].to_string());
    }
    None
}
