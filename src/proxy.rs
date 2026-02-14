// Serveur proxy HTTP
use crate::config::Config;
use crate::config::HttpAuthProtocol;
use crate::config::ProxyType;
use crate::auth::AuthHandler;
use crate::pac::PacResolver;
use anyhow::Result;
use base64::Engine;
use reqwest::Client;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_socks::tcp::{Socks4Stream, Socks5Stream};

const DNS_NEGATIVE_TTL: Duration = Duration::from_secs(15);

pub struct ProxyServer {
    config: Arc<Mutex<Config>>,
    auth_handler: Arc<AuthHandler>,
    pac_resolver: Option<Arc<PacResolver>>,
    dns_negative_cache: Arc<StdMutex<HashMap<String, Instant>>>,
    listener: Option<TcpListener>,
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ProxyServer {
    pub fn new(config: Config) -> Self {
        let pac_resolver = if matches!(config.proxy_type, ProxyType::PAC) {
            match PacResolver::shared(
                config.pac_cache_ttl_seconds,
                config.pac_stale_ttl_seconds,
            ) {
                Ok(resolver) => Some(resolver),
                Err(e) => {
                    tracing::error!("Impossible d'initialiser PacResolver: {}", e);
                    None
                }
            }
        } else {
            None
        };

        ProxyServer {
            config: Arc::new(Mutex::new(config.clone())),
            auth_handler: Arc::new(AuthHandler::new(config)),
            pac_resolver,
            dns_negative_cache: Arc::new(StdMutex::new(HashMap::new())),
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
        let startup_config = config.clone();
        let addr = SocketAddr::from(([127, 0, 0, 1], config.local_port));
        drop(config);

        tracing::info!("Démarrage du serveur proxy sur {}", addr);

        let listener = TcpListener::bind(addr).await?;
        
        let config = Arc::clone(&self.config);
        let auth_handler = Arc::clone(&self.auth_handler);
        let pac_resolver = self.pac_resolver.clone();
        let dns_negative_cache = Arc::clone(&self.dns_negative_cache);

        if let Some(resolver) = self.pac_resolver.clone() {
            if matches!(startup_config.proxy_type, ProxyType::PAC) {
                let mut warmup_urls = Vec::new();
                if !startup_config.proxy_test_url.trim().is_empty() {
                    warmup_urls.push(startup_config.proxy_test_url.clone());
                }
                warmup_urls.push("https://example.com/".to_string());

                tokio::spawn(async move {
                    resolver.prewarm(&warmup_urls).await;
                    tracing::info!("Préchargement PAC terminé");
                });
            }
        }
        
        // Lancer le serveur dans une tâche séparée
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, client_addr)) => {
                        tracing::debug!("Nouvelle connexion de {}", client_addr);
                        let config = Arc::clone(&config);
                        let auth_handler = Arc::clone(&auth_handler);
                        let pac_resolver = pac_resolver.clone();
                        let dns_negative_cache = Arc::clone(&dns_negative_cache);
                        
                        tokio::spawn(async move {
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
                                            if is_dns_negative_cached(&dns_negative_cache, &host_port) {
                                                let body = "CONNECT temporairement bloqué après erreur DNS récente";
                                                let response = format!(
                                                    "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
                                                    body.len(),
                                                    body
                                                );
                                                let _ = stream.write_all(response.as_bytes()).await;
                                                let _ = stream.flush().await;
                                                return;
                                            }

                                            let request_config = config.lock().await.clone();

                                            let mut server_stream = match establish_connect_tunnel(
                                                &request_config,
                                                auth_handler.as_ref(),
                                                pac_resolver.clone(),
                                                &host_port,
                                            )
                                            .await
                                            {
                                                Ok(s) => s,
                                                Err(e) => {
                                                    if is_dns_resolution_error(&e) {
                                                        remember_dns_negative_failure(&dns_negative_cache, &host_port);
                                                    }
                                                    tracing::error!("Erreur tunnel CONNECT via upstream: {}", e);
                                                    let body = format!("CONNECT upstream error: {}", e);
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

                                            // Envoyer "200 Connection Established" uniquement si tunnel prêt
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
                                        let client = match create_forward_client(
                                            &request_config,
                                            auth_handler.as_ref(),
                                            pac_resolver.clone(),
                                            &url,
                                        ).await {
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

                                        let response = match auth_handler
                                            .send_authenticated_request(&client, method, &url)
                                            .await
                                        {
                                            Ok(resp) => Ok(resp),
                                            Err(e) => {
                                                tracing::error!("Erreur requête HTTP proxy: {}", e);
                                                Err(e)
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

async fn create_forward_client(
    config: &Config,
    auth_handler: &AuthHandler,
    pac_resolver: Option<Arc<PacResolver>>,
    request_url: &str,
) -> Result<Client> {
    if let Some(proxy_url) = build_upstream_proxy_url(config, pac_resolver, request_url).await? {
        tracing::debug!("Utilisation proxy upstream: {}", proxy_url);
        return auth_handler.create_authenticated_client(&proxy_url).await;
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.socket_timeout))
        .connect_timeout(std::time::Duration::from_secs(config.connect_timeout))
        .build()?;

    Ok(client)
}

async fn build_upstream_proxy_url(
    config: &Config,
    pac_resolver: Option<Arc<PacResolver>>,
    request_url: &str,
) -> Result<Option<String>> {
    match config.proxy_type {
        ProxyType::DIRECT => Ok(None),
        ProxyType::PAC => {
            let resolver = pac_resolver
                .ok_or_else(|| anyhow::anyhow!("PAC activé mais PacResolver non initialisé"))?;
            let proxies = resolver.resolve(request_url).await?;

            for pac_entry in proxies {
                if let Some(proxy_url) = map_pac_entry_to_proxy_url(&pac_entry) {
                    return Ok(Some(proxy_url));
                }
            }

            Ok(None)
        }
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

fn map_pac_entry_to_proxy_url(entry: &str) -> Option<String> {
    let trimmed = entry.trim();
    if trimmed.eq_ignore_ascii_case("DIRECT") {
        return None;
    }

    let mut parts = trimmed.split_whitespace();
    let kind = parts.next()?.to_ascii_uppercase();
    let endpoint = parts.next()?;

    if parts.next().is_some() {
        return None;
    }

    let scheme = match kind.as_str() {
        "PROXY" | "HTTP" => "http",
        "SOCKS" => "socks5h",
        "SOCKS4" => "socks4",
        "SOCKS5" => "socks5h",
        _ => return None,
    };

    Some(format!("{}://{}", scheme, endpoint))
}

async fn establish_connect_tunnel(
    config: &Config,
    auth_handler: &AuthHandler,
    pac_resolver: Option<Arc<PacResolver>>,
    target_host_port: &str,
) -> Result<tokio::net::TcpStream> {
    let connect_url = format!("https://{}/", target_host_port);

    let proxy_url = build_upstream_proxy_url(config, pac_resolver, &connect_url).await?;
    match proxy_url {
        None => {
            let stream = tokio::net::TcpStream::connect(target_host_port).await?;
            Ok(stream)
        }
        Some(url) => {
            if let Some(upstream) = url.strip_prefix("http://") {
                return connect_via_http_upstream(config, auth_handler, upstream, target_host_port).await;
            }

            if let Some(upstream) = url.strip_prefix("socks4://") {
                return connect_via_socks_upstream(config, "socks4", upstream, target_host_port).await;
            }

            if let Some(upstream) = url.strip_prefix("socks5://") {
                return connect_via_socks_upstream(config, "socks5", upstream, target_host_port).await;
            }

            if let Some(upstream) = url.strip_prefix("socks5h://") {
                return connect_via_socks_upstream(config, "socks5h", upstream, target_host_port).await;
            }

            anyhow::bail!(
                "CONNECT via upstream non supporté pour ce schéma: {}",
                url
            )
        }
    }
}

async fn connect_via_socks_upstream(
    config: &Config,
    socks_scheme: &str,
    upstream_host_port: &str,
    target_host_port: &str,
) -> Result<tokio::net::TcpStream> {
    let (target_host, target_port) = parse_host_port(target_host_port)?;

    match socks_scheme {
        "socks4" => {
            let stream = if config.proxy_username.is_empty() {
                Socks4Stream::connect(upstream_host_port, (target_host.as_str(), target_port)).await?
            } else {
                Socks4Stream::connect_with_userid(
                    upstream_host_port,
                    (target_host.as_str(), target_port),
                    &config.proxy_username,
                )
                .await?
            };

            Ok(stream.into_inner())
        }
        "socks5" | "socks5h" => {
            let stream = if config.proxy_username.is_empty() {
                Socks5Stream::connect(upstream_host_port, (target_host.as_str(), target_port)).await?
            } else {
                Socks5Stream::connect_with_password(
                    upstream_host_port,
                    (target_host.as_str(), target_port),
                    &config.proxy_username,
                    &config.proxy_password,
                )
                .await?
            };

            Ok(stream.into_inner())
        }
        _ => anyhow::bail!("Schéma SOCKS non supporté: {}", socks_scheme),
    }
}

fn parse_host_port(value: &str) -> Result<(String, u16)> {
    if let Some(rest) = value.strip_prefix('[') {
        if let Some(end_bracket) = rest.find(']') {
            let host = &rest[..end_bracket];
            let port_part = rest[end_bracket + 1..]
                .strip_prefix(':')
                .ok_or_else(|| anyhow::anyhow!("Port manquant dans {}", value))?;
            let port: u16 = port_part
                .parse()
                .map_err(|_| anyhow::anyhow!("Port invalide dans {}", value))?;
            return Ok((host.to_string(), port));
        }
    }

    let (host, port_part) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("Format host:port invalide: {}", value))?;

    let port: u16 = port_part
        .parse()
        .map_err(|_| anyhow::anyhow!("Port invalide dans {}", value))?;

    Ok((host.to_string(), port))
}

fn is_dns_negative_cached(cache: &StdMutex<HashMap<String, Instant>>, host_port: &str) -> bool {
    if let Ok(mut guard) = cache.lock() {
        if let Some(stored_at) = guard.get(host_port) {
            if stored_at.elapsed() <= DNS_NEGATIVE_TTL {
                return true;
            }
            guard.remove(host_port);
        }
    }

    false
}

fn remember_dns_negative_failure(cache: &StdMutex<HashMap<String, Instant>>, host_port: &str) {
    if let Ok(mut guard) = cache.lock() {
        guard.insert(host_port.to_string(), Instant::now());
    }
}

fn is_dns_resolution_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .and_then(|io| io.raw_os_error())
            == Some(11004)
    })
}

async fn connect_via_http_upstream(
    config: &Config,
    auth_handler: &AuthHandler,
    upstream_host_port: &str,
    target_host_port: &str,
) -> Result<tokio::net::TcpStream> {
    let mut stream = tokio::net::TcpStream::connect(upstream_host_port).await?;

    let mut connect_request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n",
        target_host_port,
        target_host_port
    );

    if let Some(auth_header) = build_proxy_authorization_header(config, auth_handler)? {
        connect_request.push_str(&format!("Proxy-Authorization: {}\r\n", auth_header));
    }
    connect_request.push_str("\r\n");

    stream.write_all(connect_request.as_bytes()).await?;
    stream.flush().await?;

    let mut response = Vec::with_capacity(1024);
    let mut temp = [0u8; 512];

    loop {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            anyhow::bail!("Connexion fermée par le proxy upstream pendant CONNECT");
        }
        response.extend_from_slice(&temp[..n]);

        if response.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }

        if response.len() > 32 * 1024 {
            anyhow::bail!("Réponse CONNECT upstream trop grande");
        }
    }

    let head_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(response.len());
    let head = String::from_utf8_lossy(&response[..head_end]);
    let status_line = head.lines().next().unwrap_or_default().to_string();

    if !status_line.contains(" 200 ") {
        anyhow::bail!("CONNECT refusé par upstream: {}", status_line);
    }

    Ok(stream)
}

fn build_proxy_authorization_header(
    config: &Config,
    auth_handler: &AuthHandler,
) -> Result<Option<String>> {
    if config.proxy_username.is_empty() && config.proxy_password.is_empty() && !config.use_current_credentials {
        return Ok(None);
    }

    if matches!(config.http_auth_protocol, HttpAuthProtocol::NTLM | HttpAuthProtocol::KERBEROS) {
        anyhow::bail!(
            "CONNECT avec NTLM/Kerberos upstream n'est pas encore implémenté dans le tunnel brut"
        );
    }

    let (username, password) = if config.use_current_credentials {
        #[cfg(windows)]
        {
            auth_handler.get_windows_credentials()?
        }
        #[cfg(not(windows))]
        {
            anyhow::bail!("Windows current credentials demandé hors Windows")
        }
    } else {
        if config.proxy_username.is_empty() {
            anyhow::bail!("proxy_username manquant pour authentification proxy CONNECT")
        }
        (config.proxy_username.clone(), config.proxy_password.clone())
    };

    let token = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", username, password));
    Ok(Some(format!("Basic {}", token)))
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
