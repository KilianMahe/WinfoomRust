// Serveur proxy HTTP
use crate::config::{Config, ProxyType};
use crate::auth::AuthHandler;
use anyhow::Result;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, body::Incoming};
use http_body_util::Full;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
                                        
                                        // Créer le client et faire la requête
                                        if let Ok(client) = reqwest::Client::builder()
                                            .timeout(std::time::Duration::from_secs(30))
                                            .build()
                                        {
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

    pub async fn is_running(&self) -> bool {
        self.server_handle.is_some()
    }
}

async fn handle_request(
    req: Request<Incoming>,
    config: Arc<Mutex<Config>>,
    auth_handler: Arc<AuthHandler>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let config_guard = config.lock().await;
    let method = req.method().clone();
    let uri = req.uri().clone();
    
    tracing::debug!("Requête: {} {}", method, uri);

    // Traiter selon le type de proxy configuré
    match config_guard.proxy_type {
        ProxyType::DIRECT => {
            // Mode direct - pas de proxy upstream
            handle_direct_request(req).await
        }
        ProxyType::HTTP => {
            // Proxy HTTP avec authentification NTLM/Basic
            drop(config_guard);
            handle_http_proxy_request(req, config, auth_handler).await
        }
        ProxyType::SOCKS4 | ProxyType::SOCKS5 => {
            // Proxy SOCKS
            drop(config_guard);
            handle_socks_proxy_request(req, config).await
        }
        ProxyType::PAC => {
            // Proxy Auto-Config
            drop(config_guard);
            handle_pac_proxy_request(req, config, auth_handler).await
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

async fn handle_direct_request(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    
    // CONNECT est géré au niveau TCP, ne devrait pas arriver ici
    if method == hyper::Method::CONNECT {
        tracing::warn!("CONNECT reçu dans handle_direct_request (devrait être géré avant)");
        return Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Full::new(Bytes::from("500 Internal Server Error")))
            .unwrap());
    }
    
    // Construire l'URL complète
    let url = if uri.scheme().is_none() {
        // Si pas de schéma, extraire le host du header Host:
        let host = req.headers()
            .get("Host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost");
        
        // Déterminer le schéma (http ou https)
        let scheme = if host.contains(":443") || req.uri().path().contains("https") {
            "https"
        } else {
            "http"
        };
        
        format!("{}://{}{}", scheme, host, uri)
    } else {
        uri.to_string()
    };
    
    tracing::debug!("Requête directe: {} {}", method, url);
    
    // Créer le client
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build() 
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Erreur création client: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("500 Internal Server Error")))
                .unwrap());
        }
    };
    
    // Faire la requête selon la méthode
    let result = match method {
        hyper::Method::GET => client.get(&url).send().await,
        hyper::Method::POST => client.post(&url).send().await,
        hyper::Method::PUT => client.put(&url).send().await,
        hyper::Method::DELETE => client.delete(&url).send().await,
        hyper::Method::HEAD => client.head(&url).send().await,
        _ => {
            tracing::warn!("Méthode HTTP non supportée: {}", method);
            return Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Full::new(Bytes::from("405 Method Not Allowed")))
                .unwrap());
        }
    };
    
    match result {
        Ok(response) => {
            let status = response.status();
            let body = response.bytes().await.unwrap_or_default();
            
            Ok(Response::builder()
                .status(status.as_u16())
                .body(Full::new(body))
                .unwrap())
        }
        Err(e) => {
            tracing::error!("Erreur requête directe vers {}: {}", url, e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("502 Bad Gateway")))
                .unwrap())
        }
    }
}

async fn handle_http_proxy_request(
    req: Request<Incoming>,
    config: Arc<Mutex<Config>>,
    auth_handler: Arc<AuthHandler>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let config_guard = config.lock().await;
    
    // Valider la configuration
    if config_guard.proxy_host.is_empty() {
        tracing::error!("Proxy host non configuré");
        drop(config_guard);
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("502 Bad Gateway - Proxy host not configured")))
            .unwrap());
    }
    
    let proxy_url = format!("http://{}:{}", config_guard.proxy_host, config_guard.proxy_port);
    let method = req.method().clone();
    let uri = req.uri().clone();
    drop(config_guard);

    // Gérer les requêtes CONNECT (tunneling HTTPS)
    if method == hyper::Method::CONNECT {
        tracing::debug!("Requête CONNECT via proxy HTTP: {} -> {}", uri, proxy_url);
        // Retourner 200 OK pour simuler l'établissement du tunnel
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    tracing::debug!("Requête HTTP via proxy: {} -> {}", uri, proxy_url);

    // Créer le client avec authentification
    let client = match auth_handler.create_authenticated_client(&proxy_url).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Erreur création client pour {}: {}", proxy_url, e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!("502 Bad Gateway - {}", e))))
                .unwrap());
        }
    };

    // Faire la requête via le proxy
    match client.get(uri.to_string()).send().await {
        Ok(response) => {
            let status = response.status();
            let body = response.bytes().await.unwrap_or_default();
            
            Ok(Response::builder()
                .status(status.as_u16())
                .body(Full::new(body))
                .unwrap())
        }
        Err(e) => {
            tracing::error!("Erreur requête proxy: {}", e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("502 Bad Gateway")))
                .unwrap())
        }
    }
}

async fn handle_socks_proxy_request(
    req: Request<Incoming>,
    config: Arc<Mutex<Config>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let config_guard = config.lock().await;
    let proxy_url = format!("socks5://{}:{}", config_guard.proxy_host, config_guard.proxy_port);
    let uri = req.uri().clone();
    drop(config_guard);

    // Créer le client SOCKS
    let client = match reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&proxy_url).unwrap())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Erreur création client SOCKS: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("502 Bad Gateway")))
                .unwrap());
        }
    };

    match client.get(uri.to_string()).send().await {
        Ok(response) => {
            let status = response.status();
            let body = response.bytes().await.unwrap_or_default();
            
            Ok(Response::builder()
                .status(status.as_u16())
                .body(Full::new(body))
                .unwrap())
        }
        Err(e) => {
            tracing::error!("Erreur requête SOCKS: {}", e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("502 Bad Gateway")))
                .unwrap())
        }
    }
}

async fn handle_pac_proxy_request(
    req: Request<Incoming>,
    config: Arc<Mutex<Config>>,
    auth_handler: Arc<AuthHandler>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    use crate::pac::PacResolver;
    
    let method = req.method().clone();
    let uri = req.uri().clone();
    
    let config_guard = config.lock().await;
    let pac_location = config_guard.proxy_pac_file_location.clone();
    drop(config_guard);
    
    if pac_location.is_empty() {
        tracing::error!("Fichier PAC non configuré");
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("502 Bad Gateway - PAC file not configured")))
            .unwrap());
    }
    
    // Charger et parser le fichier PAC
    let pac_resolver = match PacResolver::new(&pac_location).await {
        Ok(resolver) => resolver,
        Err(e) => {
            tracing::error!("Erreur chargement PAC depuis {}: {}", pac_location, e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!("502 Bad Gateway - Cannot load PAC file: {}", e))))
                .unwrap());
        }
    };
    
    // Extraire les proxies du fichier PAC
    let proxies = pac_resolver.extract_proxies();
    
    if proxies.is_empty() {
        tracing::error!("Aucun proxy trouvé dans le fichier PAC");
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("502 Bad Gateway - No proxy found in PAC file")))
            .unwrap());
    }
    
    // Utiliser le premier proxy trouvé (implémentation simplifiée)
    let proxy_host_port = &proxies[0];
    let proxy_parts: Vec<&str> = proxy_host_port.split(':').collect();
    
    if proxy_parts.len() != 2 {
        tracing::error!("Format proxy invalide: {}", proxy_host_port);
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("502 Bad Gateway - Invalid proxy format in PAC")))
            .unwrap());
    }
    
    let proxy_host = proxy_parts[0];
    let proxy_port: u16 = match proxy_parts[1].parse() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Port proxy invalide: {} - {}", proxy_parts[1], e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("502 Bad Gateway - Invalid proxy port in PAC")))
                .unwrap());
        }
    };
    
    tracing::debug!("Utilisation du proxy PAC: {}:{} pour {} {}", proxy_host, proxy_port, method, uri);
    
    // Utiliser le proxy extrait du PAC pour router la requête
    let proxy_url = format!("http://{}:{}", proxy_host, proxy_port);
    
    // Pour CONNECT (HTTPS), simuler l'établissement du tunnel
    if method == hyper::Method::CONNECT {
        tracing::debug!("CONNECT via PAC vers {} via proxy {}:{}", uri, proxy_host, proxy_port);
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }
    
    // Pour les autres méthodes, utiliser le proxy HTTP
    let client = match auth_handler.create_authenticated_client(&proxy_url).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Erreur création client pour proxy PAC {}: {}", proxy_url, e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!("502 Bad Gateway - {}", e))))
                .unwrap());
        }
    };
    
    // Faire la requête via le proxy
    let url = if uri.scheme().is_none() {
        format!("http://{}", uri)
    } else {
        uri.to_string()
    };
    
    let result = match method {
        hyper::Method::GET => client.get(&url).send().await,
        hyper::Method::POST => client.post(&url).send().await,
        hyper::Method::PUT => client.put(&url).send().await,
        hyper::Method::DELETE => client.delete(&url).send().await,
        hyper::Method::HEAD => client.head(&url).send().await,
        _ => {
            tracing::warn!("Méthode HTTP non supportée: {}", method);
            return Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Full::new(Bytes::from("405 Method Not Allowed")))
                .unwrap());
        }
    };
    
    match result {
        Ok(response) => {
            let status = response.status();
            let body = response.bytes().await.unwrap_or_default();
            
            Ok(Response::builder()
                .status(status.as_u16())
                .body(Full::new(body))
                .unwrap())
        }
        Err(e) => {
            tracing::error!("Erreur requête via proxy PAC vers {}: {}", url, e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("502 Bad Gateway")))
                .unwrap())
        }
    }
}
