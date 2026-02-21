// Support for Proxy Auto Config (PAC) — built-in evaluator
use anyhow::Result;
use boa_engine::{Context, JsArgs, JsResult, JsValue, Source, js_string};
use boa_engine::NativeFunction;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as TokioMutex, Notify};

const PAC_NEGATIVE_TTL: Duration = Duration::from_secs(15);

pub struct PacResolver {
    pac_script: Mutex<String>,
    _pac_url: String,
    state: TokioMutex<PacState>,
    cache_ttl: Duration,
    stale_ttl: Duration,
}

struct PacState {
    cache: HashMap<String, CacheEntry>,
    in_flight: HashMap<String, Arc<Notify>>,
}

#[derive(Clone)]
struct CacheEntry {
    stored_at: Instant,
    proxies: Vec<String>,
    kind: CacheEntryKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CacheEntryKind {
    Positive,
    Negative,
}

struct SharedResolverState {
    pac_url: String,
    cache_ttl_seconds: u64,
    stale_ttl_seconds: u64,
    resolver: Arc<PacResolver>,
}

static SHARED_PAC_RESOLVER: Lazy<Mutex<Option<SharedResolverState>>> =
    Lazy::new(|| Mutex::new(None));

impl PacResolver {
    pub fn shared(pac_url: &str, cache_ttl_seconds: u64, stale_ttl_seconds: u64) -> Result<Arc<Self>> {
        let mut guard = SHARED_PAC_RESOLVER.lock().map_err(|e| {
            anyhow::anyhow!("Unable to acquire shared PAC resolver lock: {}", e)
        })?;

        if let Some(state) = guard.as_ref() {
            if state.pac_url == pac_url
                && state.cache_ttl_seconds == cache_ttl_seconds
                && state.stale_ttl_seconds == stale_ttl_seconds
            {
                return Ok(Arc::clone(&state.resolver));
            }
        }

        let resolver = Arc::new(Self::new(pac_url, cache_ttl_seconds, stale_ttl_seconds)?);
        *guard = Some(SharedResolverState {
            pac_url: pac_url.to_string(),
            cache_ttl_seconds,
            stale_ttl_seconds,
            resolver: Arc::clone(&resolver),
        });

        Ok(resolver)
    }

    /// Creates a new PacResolver instance with built-in JS evaluator
    pub fn new(pac_url: &str, cache_ttl_seconds: u64, stale_ttl_seconds: u64) -> Result<Self> {
        tracing::info!(
            "Initializing PacResolver (pac_url={}, ttl={}s, stale={}s)",
            pac_url,
            cache_ttl_seconds,
            stale_ttl_seconds
        );

        let cache_ttl = Duration::from_secs(cache_ttl_seconds.max(1));
        let stale_ttl = Duration::from_secs(stale_ttl_seconds.max(cache_ttl_seconds.max(1)));

        // Load PAC file content
        let pac_script = load_pac_script(pac_url)?;
        tracing::info!("PAC file loaded ({} bytes) from: {}", pac_script.len(), pac_url);
        tracing::debug!("PAC content:\n{}", pac_script);

        Ok(PacResolver {
            pac_script: Mutex::new(pac_script),
            _pac_url: pac_url.to_string(),
            state: TokioMutex::new(PacState {
                cache: HashMap::new(),
                in_flight: HashMap::new(),
            }),
            cache_ttl,
            stale_ttl,
        })
    }

    /// Resolves proxies for a given URL
    pub async fn resolve(self: &Arc<Self>, url: &str) -> Result<Vec<String>> {
        let keys = cache_keys(url);
        let parent_key = keys.parent_key.clone();
        let url_owned = url.to_string();

        loop {
            let mut state = self.state.lock().await;

            if let Some((cached, is_fresh)) =
                get_cached_from_state(&mut state, &keys, self.cache_ttl, self.stale_ttl)
            {
                if is_fresh {
                    tracing::debug!(
                        "PAC cache hit (fresh) for key={} (url={})",
                        keys.exact_key,
                        url
                    );
                    return Ok(cached);
                }

                tracing::debug!(
                    "PAC cache hit (stale) for key={} (url={}), background refresh",
                    keys.exact_key,
                    url
                );

                self.spawn_refresh_if_needed(&mut state, &parent_key, &url_owned);

                return Ok(cached);
            }

            if let Some(notify) = state.in_flight.get(&parent_key).cloned() {
                drop(state);
                notify.notified().await;
                continue;
            }

            let notify = Arc::new(Notify::new());
            state.in_flight.insert(parent_key.clone(), Arc::clone(&notify));
            drop(state);

            return self.resolve_for_key(parent_key.clone(), url_owned.clone()).await;
        }
    }

    fn spawn_refresh_if_needed(
        self: &Arc<Self>,
        state: &mut PacState,
        parent_key: &str,
        url: &str,
    ) {
        if state.in_flight.contains_key(parent_key) {
            return;
        }

        let notify = Arc::new(Notify::new());
        state.in_flight.insert(parent_key.to_string(), Arc::clone(&notify));

        let resolver = Arc::clone(self);
        let refresh_url = url.to_string();
        let refresh_key = parent_key.to_string();
        tokio::spawn(async move {
            let _ = resolver.resolve_for_key(refresh_key, refresh_url).await;
        });
    }

    pub async fn prewarm(self: &Arc<Self>, urls: &[String]) {
        for url in urls {
            let _ = self.resolve(url).await;
        }
    }

    async fn resolve_for_key(self: &Arc<Self>, parent_key: String, url: String) -> Result<Vec<String>> {
        let resolver = Arc::clone(self);
        let url_for_blocking = url.clone();
        let resolved = tokio::task::spawn_blocking(move || resolver.resolve_blocking(&url_for_blocking)).await;

        let (result, kind) = match resolved {
            Ok(Ok(proxies)) => (proxies, CacheEntryKind::Positive),
            Ok(Err(e)) => {
                tracing::error!("Error during proxy resolution: {:?}", e);
                (vec!["DIRECT".to_string()], CacheEntryKind::Negative)
            }
            Err(e) => {
                tracing::error!("PAC spawn_blocking task error: {}", e);
                (vec!["DIRECT".to_string()], CacheEntryKind::Negative)
            }
        };

        let keys = cache_keys(&url);
        let mut state = self.state.lock().await;
        put_cache_in_state(&mut state, &keys, result.clone(), kind);

        if let Some(notify) = state.in_flight.remove(&parent_key) {
            notify.notify_waiters();
        }

        Ok(result)
    }

    fn resolve_blocking(&self, url: &str) -> Result<Vec<String>> {
        let pac_script = self.pac_script.lock().map_err(|e| {
            anyhow::anyhow!("Unable to acquire PAC script lock: {}", e)
        })?;

        // Normalize URL: add trailing '/' if path is empty
        let normalized_url = normalize_url_path(url);
        let effective_url = normalized_url.as_deref().unwrap_or(url);

        if normalized_url.is_some() {
            tracing::debug!("URL normalized for PAC: '{}' -> '{}'", url, effective_url);
        }

        // Extract host from URL
        let host = extract_host(effective_url);

        tracing::debug!("PAC evaluation for URL='{}', host='{}'", effective_url, host);

        // Evaluate PAC script with boa_engine
        let result = evaluate_pac_script(&pac_script, effective_url, &host)?;

        tracing::debug!("PAC FindProxyForURL('{}', '{}') => '{}'", effective_url, host, result);

        // Parse PAC result (e.g.: "PROXY proxy:8080; DIRECT")
        let proxy_list = parse_pac_result(&result);

        if proxy_list.is_empty() {
            tracing::warn!("No proxy found for: {}", url);
            Ok(vec!["DIRECT".to_string()])
        } else {
            tracing::debug!("Proxies found for {}: {:?}", url, proxy_list);
            Ok(proxy_list)
        }
    }
}

// ─── PAC file loading ───────────────────────────────────────────────────────────────

fn load_pac_script(pac_url: &str) -> Result<String> {
    let trimmed = pac_url.trim();

    if trimmed.is_empty() {
        return Err(anyhow::anyhow!("PAC file URL is empty"));
    }

    // Remote URL (http/https)
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        tracing::info!("Downloading PAC file from: {}", trimmed);
        let response = reqwest::blocking::get(trimmed)
            .map_err(|e| anyhow::anyhow!("PAC download error from {}: {}", trimmed, e))?;
        let content = response.text()
            .map_err(|e| anyhow::anyhow!("PAC content read error from {}: {}", trimmed, e))?;
        return Ok(content);
    }

    // Local file — convert path
    let file_path = if trimmed.starts_with("file:///") {
        let path = trimmed.strip_prefix("file:///").unwrap();
        path.replace('/', "\\")
    } else if trimmed.starts_with("file://") {
        let path = trimmed.strip_prefix("file://").unwrap();
        path.to_string()
    } else {
        // Raw path (e.g.: C:\Users\...\file.pac)
        trimmed.to_string()
    };

    tracing::info!("Reading local PAC file: {}", file_path);
    let content = std::fs::read_to_string(&file_path)
        .map_err(|e| anyhow::anyhow!("PAC file read error '{}': {}", file_path, e))?;
    Ok(content)
}

// ─── PAC JavaScript evaluation ──────────────────────────────────────────────────────────

fn evaluate_pac_script(pac_script: &str, url: &str, host: &str) -> Result<String> {
    let mut context = Context::default();

    // Register PAC helper functions
    register_pac_helpers(&mut context)?;

    // Load the PAC script
    context
        .eval(Source::from_bytes(pac_script.as_bytes()))
        .map_err(|e| anyhow::anyhow!("PAC script parsing error: {}", e))?;

    // Call FindProxyForURL(url, host)
    let call_script = format!(
        "FindProxyForURL(\"{}\", \"{}\")",
        url.replace('\\', "\\\\").replace('"', "\\\""),
        host.replace('\\', "\\\\").replace('"', "\\\"")
    );

    let result = context
        .eval(Source::from_bytes(call_script.as_bytes()))
        .map_err(|e| anyhow::anyhow!("FindProxyForURL execution error: {}", e))?;

    let result_str = result
        .to_string(&mut context)
        .map_err(|e| anyhow::anyhow!("PAC result to string conversion error: {}", e))?;

    Ok(result_str.to_std_string_escaped())
}

fn register_pac_helpers(context: &mut Context) -> Result<()> {
    fn register(
        context: &mut Context,
        name: &'static str,
        length: usize,
        func: fn(&JsValue, &[JsValue], &mut Context) -> JsResult<JsValue>,
    ) -> Result<()> {
        context
            .register_global_builtin_callable(
                js_string!(name),
                length,
                NativeFunction::from_fn_ptr(func),
            )
            .map_err(|e| anyhow::anyhow!("Error registering {}: {}", name, e))
    }

    register(context, "isPlainHostName", 1, pac_is_plain_host_name)?;
    register(context, "dnsDomainIs", 2, pac_dns_domain_is)?;
    register(context, "localHostOrDomainIs", 2, pac_local_host_or_domain_is)?;
    register(context, "isResolvable", 1, pac_is_resolvable)?;
    register(context, "isInNet", 3, pac_is_in_net)?;
    register(context, "dnsResolve", 1, pac_dns_resolve)?;
    register(context, "myIpAddress", 0, pac_my_ip_address)?;
    register(context, "dnsDomainLevels", 1, pac_dns_domain_levels)?;
    register(context, "shExpMatch", 2, pac_sh_exp_match)?;
    register(context, "weekdayRange", 3, pac_weekday_range)?;
    register(context, "dateRange", 7, pac_date_range)?;
    register(context, "timeRange", 7, pac_time_range)?;
    register(context, "alert", 1, pac_alert)?;

    Ok(())
}

// ─── PAC helper function implementations ─────────────────────────────────────────────

/// isPlainHostName(host) — true if hostname does not contain a dot
fn pac_is_plain_host_name(_this: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let host = args.get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    Ok(JsValue::Boolean(!host.contains('.')))
}

/// dnsDomainIs(host, domain) — true if host ends with domain
fn pac_dns_domain_is(_this: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let host = args.get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    let domain = args.get_or_undefined(1)
        .to_string(context)?
        .to_std_string_escaped();
    Ok(JsValue::Boolean(
        host.to_ascii_lowercase().ends_with(&domain.to_ascii_lowercase()),
    ))
}

/// localHostOrDomainIs(host, hostdom)
fn pac_local_host_or_domain_is(_this: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let host = args.get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped()
        .to_ascii_lowercase();
    let hostdom = args.get_or_undefined(1)
        .to_string(context)?
        .to_std_string_escaped()
        .to_ascii_lowercase();
    Ok(JsValue::Boolean(host == hostdom || hostdom.starts_with(&format!("{}.", host))))
}

/// isResolvable(host) — true if hostname can be resolved via DNS
fn pac_is_resolvable(_this: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let host = args.get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    let resolvable = format!("{}:0", host)
        .to_socket_addrs()
        .map(|mut addrs| addrs.next().is_some())
        .unwrap_or(false);
    Ok(JsValue::Boolean(resolvable))
}

/// isInNet(host, pattern, mask) — true if resolved IP is in the subnet
fn pac_is_in_net(_this: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let host = args.get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    let pattern = args.get_or_undefined(1)
        .to_string(context)?
        .to_std_string_escaped();
    let mask = args.get_or_undefined(2)
        .to_string(context)?
        .to_std_string_escaped();

    let result = (|| -> Option<bool> {
        let host_ip = resolve_host_to_ipv4(&host)?;
        let pattern_ip: std::net::Ipv4Addr = pattern.parse().ok()?;
        let mask_ip: std::net::Ipv4Addr = mask.parse().ok()?;

        let host_bits = u32::from(host_ip);
        let pattern_bits = u32::from(pattern_ip);
        let mask_bits = u32::from(mask_ip);

        Some((host_bits & mask_bits) == (pattern_bits & mask_bits))
    })();

    Ok(JsValue::Boolean(result.unwrap_or(false)))
}

/// dnsResolve(host) — resolves hostname to IP address
fn pac_dns_resolve(_this: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let host = args.get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();

    match resolve_host_to_ipv4(&host) {
        Some(ip) => Ok(JsValue::String(js_string!(ip.to_string()))),
        None => Ok(JsValue::null()),
    }
}

/// myIpAddress() — returns the local IP address
fn pac_my_ip_address(_this: &JsValue, _args: &[JsValue], _context: &mut Context) -> JsResult<JsValue> {
    let ip = get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    Ok(JsValue::String(js_string!(ip)))
}

/// dnsDomainLevels(host) — returns the number of dots in the hostname
fn pac_dns_domain_levels(_this: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let host = args.get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    let count = host.chars().filter(|&c| c == '.').count();
    Ok(JsValue::Integer(count as i32))
}

/// shExpMatch(str, shexp) — shell expression match (glob)
fn pac_sh_exp_match(_this: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let s = args.get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    let pattern = args.get_or_undefined(1)
        .to_string(context)?
        .to_std_string_escaped();

    let matched = sh_exp_match(&s, &pattern);
    Ok(JsValue::Boolean(matched))
}

/// weekdayRange — simplified, always returns true
fn pac_weekday_range(_this: &JsValue, _args: &[JsValue], _context: &mut Context) -> JsResult<JsValue> {
    Ok(JsValue::Boolean(true))
}

/// dateRange — simplified, always returns true
fn pac_date_range(_this: &JsValue, _args: &[JsValue], _context: &mut Context) -> JsResult<JsValue> {
    Ok(JsValue::Boolean(true))
}

/// timeRange — simplified, always returns true
fn pac_time_range(_this: &JsValue, _args: &[JsValue], _context: &mut Context) -> JsResult<JsValue> {
    Ok(JsValue::Boolean(true))
}

/// alert(msg) — logs the message for debugging
fn pac_alert(_this: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let msg = args.get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    tracing::debug!("PAC alert: {}", msg);
    Ok(JsValue::undefined())
}

// ─── Utility functions ─────────────────────────────────────────────────────────────

/// Implementation of shExpMatch (shell expression / glob matching)
fn sh_exp_match(s: &str, pattern: &str) -> bool {
    // Convert glob pattern to regex
    let mut regex_str = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '*' => regex_str.push_str(".*"),
            '?' => regex_str.push('.'),
            '.' => regex_str.push_str("\\."),
            '\\' => regex_str.push_str("\\\\"),
            '^' | '$' | '|' | '+' | '(' | ')' | '[' | ']' | '{' | '}' => {
                regex_str.push('\\');
                regex_str.push(ch);
            }
            _ => regex_str.push(ch),
        }
    }
    regex_str.push('$');

    match regex::Regex::new(&regex_str) {
        Ok(re) => re.is_match(s),
        Err(_) => false,
    }
}

/// DNS resolution host -> IPv4
fn resolve_host_to_ipv4(host: &str) -> Option<std::net::Ipv4Addr> {
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return Some(ip);
    }

    format!("{}:0", host)
        .to_socket_addrs()
        .ok()?
        .filter_map(|addr| match addr.ip() {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .next()
}

/// Get the local IP address
fn get_local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:53").ok()?;
    let local_addr = socket.local_addr().ok()?;
    Some(local_addr.ip().to_string())
}

/// Extract the host from a URL
fn extract_host(url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            return host.to_string();
        }
    }
    url.to_string()
}

/// Parse PAC result (e.g.: "PROXY proxy:8080; DIRECT" -> vec!["PROXY proxy:8080", "DIRECT"])
fn parse_pac_result(result: &str) -> Vec<String> {
    result
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

// ─── Cache et helpers ────────────────────────────────────────────────────────

struct CacheKeys {
    exact_key: String,
    parent_key: String,
}

fn cache_keys(url: &str) -> CacheKeys {
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            let host_lc = host.to_ascii_lowercase();
            let port = parsed.port_or_known_default().unwrap_or(0);
            let exact_key = format!("{}:{}", host_lc, port);

            let parent_host = parent_domain(&host_lc).unwrap_or_else(|| host_lc.clone());
            let parent_key = format!("{}:{}", parent_host, port);

            return CacheKeys { exact_key, parent_key };
        }
    }

    let fallback = url.to_ascii_lowercase();
    CacheKeys {
        exact_key: fallback.clone(),
        parent_key: fallback,
    }
}

fn parent_domain(host: &str) -> Option<String> {
    let parts: Vec<&str> = host.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() >= 2 {
        Some(format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]))
    } else {
        None
    }
}

fn get_cached_from_state(
    state: &mut PacState,
    keys: &CacheKeys,
    cache_ttl: Duration,
    stale_ttl: Duration,
) -> Option<(Vec<String>, bool)> {
    if let Some(entry) = state.cache.get(&keys.exact_key).cloned() {
        if let Some(result) = cache_entry_status(&entry, cache_ttl, stale_ttl) {
            return Some(result);
        }
    }
    state.cache.remove(&keys.exact_key);

    if keys.parent_key != keys.exact_key {
        if let Some(entry) = state.cache.get(&keys.parent_key).cloned() {
            if let Some(result) = cache_entry_status(&entry, cache_ttl, stale_ttl) {
                return Some(result);
            }
        }
        state.cache.remove(&keys.parent_key);
    }

    None
}

fn cache_entry_status(
    entry: &CacheEntry,
    cache_ttl: Duration,
    stale_ttl: Duration,
) -> Option<(Vec<String>, bool)> {
    let age = entry.stored_at.elapsed();

    if entry.kind == CacheEntryKind::Negative {
        if age <= PAC_NEGATIVE_TTL {
            return Some((entry.proxies.clone(), true));
        }
        return None;
    }

    if age <= cache_ttl {
        Some((entry.proxies.clone(), true))
    } else if age <= stale_ttl {
        Some((entry.proxies.clone(), false))
    } else {
        None
    }
}

fn put_cache_in_state(
    state: &mut PacState,
    keys: &CacheKeys,
    proxies: Vec<String>,
    kind: CacheEntryKind,
) {
    let now = Instant::now();
    state.cache.insert(
        keys.exact_key.clone(),
        CacheEntry {
            stored_at: now,
            proxies: proxies.clone(),
            kind,
        },
    );

    if kind == CacheEntryKind::Positive && keys.parent_key != keys.exact_key {
        state.cache.insert(
            keys.parent_key.clone(),
            CacheEntry {
                stored_at: now,
                proxies,
                kind,
            },
        );
    }
}

/// Normalizes the URL path: if the path is empty, adds a trailing `/`.
fn normalize_url_path(url: &str) -> Option<String> {
    if let Ok(mut parsed) = url::Url::parse(url) {
        if parsed.path().is_empty() || parsed.path() == "" {
            parsed.set_path("/");
            return Some(parsed.to_string());
        }
        let original_has_slash = url.contains("://")
            && url[url.find("://").unwrap() + 3..].contains('/');
        if !original_has_slash && parsed.path() == "/" {
            return Some(parsed.to_string());
        }
    }
    None
}
