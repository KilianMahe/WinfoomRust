// HTTP proxy server
use crate::config::Config;
use crate::config::HttpAuthProtocol;
use crate::config::ProxyType;
use crate::auth::AuthHandler;
use crate::pac::PacResolver;
use anyhow::Result;
use base64::Engine;
use reqwest::Client;
use futures::StreamExt;
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
    client_cache: Arc<Mutex<HashMap<String, Client>>>,
    listener: Option<TcpListener>,
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ProxyServer {
    pub fn new(config: Config) -> Self {
        let pac_resolver = if matches!(config.proxy_type, ProxyType::PAC) {
            match PacResolver::shared(
                &config.proxy_pac_file_location,
                config.pac_cache_ttl_seconds,
                config.pac_stale_ttl_seconds,
            ) {
                Ok(resolver) => Some(resolver),
                Err(e) => {
                    tracing::error!("Unable to initialize PacResolver: {}", e);
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
            client_cache: Arc::new(Mutex::new(HashMap::new())),
            listener: None,
            server_handle: None,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        // Stop previous server if it exists
        if self.server_handle.is_some() {
            self.stop().await?;
        }
        
        let config = self.config.lock().await;
        let startup_config = config.clone();
        let addr = SocketAddr::from(([127, 0, 0, 1], config.local_port));
        drop(config);

        if matches!(startup_config.proxy_type, ProxyType::PAC) {
            self.pac_resolver = Some(PacResolver::reload_shared(
                &startup_config.proxy_pac_file_location,
                startup_config.pac_cache_ttl_seconds,
                startup_config.pac_stale_ttl_seconds,
            )?);
        } else {
            self.pac_resolver = None;
        }

        tracing::info!("Starting proxy server on {}", addr);

        let listener = TcpListener::bind(addr).await?;
        
        let config = Arc::clone(&self.config);
        let auth_handler = Arc::clone(&self.auth_handler);
        let pac_resolver = self.pac_resolver.clone();
        let dns_negative_cache = Arc::clone(&self.dns_negative_cache);
        let client_cache = Arc::clone(&self.client_cache);

        if let Some(resolver) = self.pac_resolver.clone() {
            if matches!(startup_config.proxy_type, ProxyType::PAC) {
                let mut warmup_urls = Vec::new();
                if !startup_config.proxy_test_url.trim().is_empty() {
                    warmup_urls.push(startup_config.proxy_test_url.clone());
                }
                warmup_urls.push("https://example.com/".to_string());

                tokio::spawn(async move {
                    resolver.prewarm(&warmup_urls).await;
                    tracing::info!("PAC preloading completed");
                });
            }
        }
        
        // Launch the server in a separate task
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, client_addr)) => {
                        tracing::debug!("New connection from {}", client_addr);
                        let config = Arc::clone(&config);
                        let auth_handler = Arc::clone(&auth_handler);
                        let pac_resolver = pac_resolver.clone();
                        let dns_negative_cache = Arc::clone(&dns_negative_cache);
                        let client_cache = Arc::clone(&client_cache);
                        
                        tokio::spawn(async move {
                            let mut stream = stream;
                            let mut buffer = vec![0u8; 4096];
                            
                            // Read request data
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(10),
                                stream.read(&mut buffer)
                            ).await {
                                Ok(Ok(n)) if n > 0 => {
                                    let request_str = String::from_utf8_lossy(&buffer[..n]);
                                    let first_line = request_str.lines().next().unwrap_or("");
                                    
                                    // Detect CONNECT
                                    if first_line.starts_with("CONNECT ") {
                                        tracing::debug!("CONNECT request detected from {}", client_addr);
                                        
                                        // Extraire host:port
                                        if let Some(host_port) = extract_connect_host(first_line) {
                                            if is_dns_negative_cached(&dns_negative_cache, &host_port) {
                                                let body = "CONNECT temporarily blocked after recent DNS error";
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
                                                    tracing::error!("CONNECT tunnel error via upstream: {}", e);
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

                                            // Send "200 Connection Established" only when tunnel is ready
                                            let response = b"HTTP/1.1 200 Connection Established\r\n\r\n";
                                            if let Err(e) = stream.write_all(response).await {
                                                tracing::error!("Error sending CONNECT response: {}", e);
                                                return;
                                            }
                                            
                                            if let Err(e) = stream.flush().await {
                                                tracing::error!("Error flushing CONNECT response: {}", e);
                                                return;
                                            }
                                            
                                            tracing::info!("Establishing CONNECT tunnel to: {}", host_port);
                                            
                                            // Now do the tunneling
                                            tracing::debug!("Tunnel established to {} - starting forwarding", host_port);
                                            
                                            let (mut client_read, mut client_write) = stream.split();
                                            let (mut server_read, mut server_write) = server_stream.split();
                                            
                                            tokio::select! {
                                                res = tokio::io::copy(&mut client_read, &mut server_write) => {
                                                    match res {
                                                        Ok(n) => tracing::debug!("Client->Server: {} bytes", n),
                                                        Err(e) => tracing::debug!("Error Client->Server: {}", e),
                                                    }
                                                }
                                                res = tokio::io::copy(&mut server_read, &mut client_write) => {
                                                    match res {
                                                        Ok(n) => tracing::debug!("Server->Client: {} bytes", n),
                                                        Err(e) => tracing::debug!("Error Server->Client: {}", e),
                                                    }
                                                }
                                            };
                                            
                                            let _ = client_write.shutdown().await;
                                            let _ = server_write.shutdown().await;
                                            
                                            tracing::debug!("CONNECT tunnel to {} closed", host_port);
                                            return;
                                        }
                                        
                                        tracing::error!("CONNECT tunnel handling error");
                                        return;
                                    }
                                    
                                    // If not CONNECT, treat as HTTP request
                                    // Extract method and URI without extra allocations
                                    let mut parts = first_line.split_whitespace();
                                    if let (Some(method), Some(uri)) = (parts.next(), parts.next()) {
                                        
                                        tracing::debug!("HTTP request: {} {}", method, uri);
                                        
    // Make the direct request
                                        let url = if uri.starts_with("http://") || uri.starts_with("https://") {
                                            uri.to_string()
                                        } else {
                                            format!("http://{}", uri)
                                        };

                                        let request_config = config.lock().await.clone();
                                        let proxy_candidates = match build_upstream_proxy_candidates(
                                            &request_config,
                                            pac_resolver.clone(),
                                            &url,
                                        )
                                        .await
                                        {
                                            Ok(candidates) => candidates,
                                            Err(e) => {
                                                tracing::error!("Error resolving upstream HTTP proxies: {}", e);
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

                                        let mut response = None;
                                        let mut last_error: Option<String> = None;

                                        for (index, proxy_candidate) in proxy_candidates.iter().enumerate() {
                                            let total = proxy_candidates.len();
                                            let candidate_label = proxy_candidate.as_deref().unwrap_or("DIRECT");

                                            tracing::debug!(
                                                "HTTP attempt {}/{} for {} via {}",
                                                index + 1,
                                                total,
                                                url,
                                                candidate_label
                                            );

                                            let client = match create_forward_client_for_proxy(
                                                &client_cache,
                                                &request_config,
                                                auth_handler.as_ref(),
                                                proxy_candidate.as_deref(),
                                            )
                                            .await
                                            {
                                                Ok(client) => client,
                                                Err(e) => {
                                                    let err_msg = format!(
                                                        "Client creation failed via {}: {}",
                                                        candidate_label,
                                                        e
                                                    );
                                                    tracing::warn!("{}", err_msg);
                                                    last_error = Some(err_msg);
                                                    continue;
                                                }
                                            };

                                            match auth_handler
                                                .send_authenticated_request(&client, method, &url)
                                                .await
                                            {
                                                Ok(resp) => {
                                                    response = Some(resp);
                                                    break;
                                                }
                                                Err(e) => {
                                                    let err_msg = format!(
                                                        "HTTP request failed via {}: {}",
                                                        candidate_label,
                                                        e
                                                    );
                                                    tracing::warn!("{}", err_msg);
                                                    last_error = Some(err_msg);
                                                }
                                            }
                                        }
                                        
                                        if let Some(resp) = response {
                                            // Build the HTTP response
                                            let status = resp.status();
                                            let mut response_str = format!("HTTP/1.1 {}\r\n", status);
                                            
                                            // Add important headers
                                            for (name, value) in resp.headers() {
                                                if let Ok(val) = value.to_str() {
                                                    response_str.push_str(&format!("{}: {}\r\n", name, val));
                                                }
                                            }
                                            response_str.push_str("\r\n");
                                            
                                            // Send headers
                                            let _ = stream.write_all(response_str.as_bytes()).await;
                                            
                                            // Send body
                                            let mut body_stream = resp.bytes_stream();
                                            while let Some(chunk) = body_stream.next().await {
                                                match chunk {
                                                    Ok(bytes) => {
                                                        if stream.write_all(&bytes).await.is_err() {
                                                            break;
                                                        }
                                                    }
                                                    Err(e) => {
                                                        tracing::debug!("HTTP body stream error: {}", e);
                                                        break;
                                                    }
                                                }
                                            }
                                            
                                            let _ = stream.flush().await;
                                            tracing::debug!("HTTP response sent: {} {}", status, uri);
                                        } else {
                                            let body = format!(
                                                "HTTP upstream error: {}",
                                                last_error.unwrap_or_else(|| "No proxy attempt succeeded".to_string())
                                            );
                                            let response = format!(
                                                "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
                                                body.len(),
                                                body
                                            );
                                            let _ = stream.write_all(response.as_bytes()).await;
                                            let _ = stream.flush().await;
                                        }
                                    }
                                    return;
                                    }
                                Ok(Ok(_)) => {
                                    tracing::debug!("Connection closed immediately by {}", client_addr);
                                }
                                Ok(Err(e)) => {
                                    tracing::error!("Read error from {}: {}", client_addr, e);
                                }
                                Err(_) => {
                                    tracing::warn!("Read timeout from {}", client_addr);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Accept error: {}", e);
                        break;
                    }
                }
            }
            
            tracing::info!("Server loop terminated");
        });
        
        self.server_handle = Some(handle);
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        tracing::info!("Stopping proxy server");
        
        // Cancel the server task
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
            tracing::debug!("Server task cancelled");
        }
        
        // Close the listener
        if let Some(listener) = self.listener.take() {
            drop(listener);
            tracing::debug!("Listener closed");
        }
        
        // Wait a bit for the port to be released
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        if matches!(self.config.lock().await.proxy_type, ProxyType::PAC) {
            PacResolver::clear_shared();
            self.pac_resolver = None;
        }
        
        tracing::info!("Proxy server stopped");
        Ok(())
    }

}

async fn create_forward_client_for_proxy(
    client_cache: &Mutex<HashMap<String, Client>>,
    config: &Config,
    auth_handler: &AuthHandler,
    proxy_url: Option<&str>,
) -> Result<Client> {
    let cache_key = match proxy_url {
        Some(url) => format!("proxy:{}", url),
        None => "direct".to_string(),
    };

    if let Some(client) = {
        let guard = client_cache.lock().await;
        guard.get(&cache_key).cloned()
    } {
        return Ok(client);
    }

    let client = if let Some(proxy_url) = proxy_url {
        tracing::debug!("Using upstream proxy: {}", proxy_url);
        auth_handler.create_authenticated_client(&proxy_url).await?
    } else {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.socket_timeout))
            .connect_timeout(std::time::Duration::from_secs(config.connect_timeout))
            .build()?
    };

    let mut guard = client_cache.lock().await;
    let entry = guard.entry(cache_key).or_insert_with(|| client.clone());
    Ok(entry.clone())
}

async fn build_upstream_proxy_candidates(
    config: &Config,
    pac_resolver: Option<Arc<PacResolver>>,
    request_url: &str,
) -> Result<Vec<Option<String>>> {
    match config.proxy_type {
        ProxyType::DIRECT => {
            tracing::debug!(
                "DIRECT mode for URL {} -> no upstream proxy",
                request_url
            );
            Ok(vec![None])
        }
        ProxyType::PAC => {
            let resolver = pac_resolver
                .ok_or_else(|| anyhow::anyhow!("PAC enabled but PacResolver not initialized"))?;
            let proxies = resolver.resolve(request_url).await?;
            let mut candidates: Vec<Option<String>> = Vec::new();

            for pac_entry in proxies {
                if let Some(proxy_url) = map_pac_entry_to_proxy_url(&pac_entry) {
                    tracing::debug!(
                        "PAC selection for URL {} -> entry '{}' -> upstream {}",
                        request_url,
                        pac_entry,
                        proxy_url
                    );
                    candidates.push(Some(proxy_url));
                    continue;
                }

                if pac_entry.trim().eq_ignore_ascii_case("DIRECT")
                    || pac_entry.trim().eq_ignore_ascii_case("direct://")
                {
                    tracing::debug!(
                        "PAC selection for URL {} -> entry 'DIRECT'",
                        request_url
                    );
                    candidates.push(None);
                } else {
                    tracing::debug!(
                        "PAC entry ignored for URL {}: '{}'",
                        request_url,
                        pac_entry
                    );
                }
            }

            if candidates.is_empty() {
                tracing::debug!(
                    "PAC returns no usable proxy for URL {} -> DIRECT",
                    request_url
                );
                return Ok(vec![None]);
            }

            Ok(candidates)
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

            let upstream = format!("{}://{}:{}", scheme, config.proxy_host, config.proxy_port);
            tracing::debug!(
                "Static proxy selected for URL {} -> {}",
                request_url,
                upstream
            );
            Ok(vec![Some(upstream)])
        }
    }
}

fn map_pac_entry_to_proxy_url(entry: &str) -> Option<String> {
    let trimmed = entry.trim();
    if trimmed.eq_ignore_ascii_case("DIRECT") || trimmed.eq_ignore_ascii_case("direct://") {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("socks://")
        || lower.starts_with("socks4://")
        || lower.starts_with("socks5://")
        || lower.starts_with("socks5h://")
    {
        return Some(trimmed.to_string());
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

    let proxy_candidates = build_upstream_proxy_candidates(config, pac_resolver, &connect_url).await?;
    let total = proxy_candidates.len();
    let mut last_error: Option<anyhow::Error> = None;

    for (index, proxy_candidate) in proxy_candidates.into_iter().enumerate() {
        let candidate_label = proxy_candidate.clone().unwrap_or_else(|| "DIRECT".to_string());
        tracing::debug!(
            "CONNECT attempt {}/{} to {} via {}",
            index + 1,
            total,
            target_host_port,
            candidate_label
        );

        let attempt = match proxy_candidate {
            None => tokio::net::TcpStream::connect(target_host_port)
                .await
                .map_err(|e| anyhow::anyhow!(e)),
            Some(url) => {
                if let Some(upstream) = url.strip_prefix("http://") {
                    connect_via_http_upstream(config, auth_handler, upstream, target_host_port).await
                } else if let Some(upstream) = url.strip_prefix("socks4://") {
                    connect_via_socks_upstream(config, "socks4", upstream, target_host_port).await
                } else if let Some(upstream) = url.strip_prefix("socks5://") {
                    connect_via_socks_upstream(config, "socks5", upstream, target_host_port).await
                } else if let Some(upstream) = url.strip_prefix("socks5h://") {
                    connect_via_socks_upstream(config, "socks5h", upstream, target_host_port).await
                } else if let Some(upstream) = url.strip_prefix("socks://") {
                    connect_via_socks_upstream(config, "socks5", upstream, target_host_port).await
                } else {
                    Err(anyhow::anyhow!(
                        "CONNECT via upstream not supported for this scheme: {}",
                        url
                    ))
                }
            }
        };

        match attempt {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                tracing::warn!(
                    "CONNECT failed via {} (attempt {}/{}): {}",
                    candidate_label,
                    index + 1,
                    total,
                    e
                );
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No CONNECT attempt succeeded")))
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
        _ => anyhow::bail!("Unsupported SOCKS scheme: {}", socks_scheme),
    }
}

fn parse_host_port(value: &str) -> Result<(String, u16)> {
    if let Some(rest) = value.strip_prefix('[') {
        if let Some(end_bracket) = rest.find(']') {
            let host = &rest[..end_bracket];
            let port_part = rest[end_bracket + 1..]
                .strip_prefix(':')
                .ok_or_else(|| anyhow::anyhow!("Missing port in {}", value))?;
            let port: u16 = port_part
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid port in {}", value))?;
            return Ok((host.to_string(), port));
        }
    }

    let (host, port_part) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("Invalid host:port format: {}", value))?;

    let port: u16 = port_part
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid port in {}", value))?;

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
            anyhow::bail!("Connection closed by upstream proxy during CONNECT");
        }
        response.extend_from_slice(&temp[..n]);

        if response.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }

        if response.len() > 32 * 1024 {
            anyhow::bail!("CONNECT upstream response too large");
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
        anyhow::bail!("CONNECT refused by upstream: {}", status_line);
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
            "CONNECT with NTLM/Kerberos upstream is not yet implemented in the raw tunnel"
        );
    }

    let (username, password) = if config.use_current_credentials {
        #[cfg(windows)]
        {
            auth_handler.get_windows_credentials()?
        }
        #[cfg(not(windows))]
        {
            anyhow::bail!("Windows current credentials requested on non-Windows system")
        }
    } else {
        if config.proxy_username.is_empty() {
            anyhow::bail!("proxy_username missing for CONNECT proxy authentication")
        }
        (config.proxy_username.clone(), config.proxy_password.clone())
    };

    let token = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", username, password));
    Ok(Some(format!("Basic {}", token)))
}

// Extract host:port from CONNECT line
fn extract_connect_host(request_line: &str) -> Option<&str> {
    // Format: "CONNECT host:port HTTP/1.1"
    let mut parts = request_line.split_whitespace();
    if parts.next()? == "CONNECT" {
        return parts.next();
    }
    None
}
