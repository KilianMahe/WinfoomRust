// Support pour Proxy Auto Config (PAC) — évaluateur intégré
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
            anyhow::anyhow!("Impossible d'acquérir le verrou du resolver PAC partagé: {}", e)
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

    /// Crée une nouvelle instance de PacResolver avec évaluateur JS intégré
    pub fn new(pac_url: &str, cache_ttl_seconds: u64, stale_ttl_seconds: u64) -> Result<Self> {
        tracing::info!(
            "Initialisation du PacResolver (pac_url={}, ttl={}s, stale={}s)",
            pac_url,
            cache_ttl_seconds,
            stale_ttl_seconds
        );

        let cache_ttl = Duration::from_secs(cache_ttl_seconds.max(1));
        let stale_ttl = Duration::from_secs(stale_ttl_seconds.max(cache_ttl_seconds.max(1)));

        // Charger le contenu du fichier PAC
        let pac_script = load_pac_script(pac_url)?;
        tracing::info!("Fichier PAC chargé ({} octets) depuis: {}", pac_script.len(), pac_url);
        tracing::debug!("Contenu PAC:\n{}", pac_script);

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

    /// Résout les proxies pour une URL donnée
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
                        "PAC cache hit (fresh) pour key={} (url={})",
                        keys.exact_key,
                        url
                    );
                    return Ok(cached);
                }

                tracing::debug!(
                    "PAC cache hit (stale) pour key={} (url={}), refresh en arrière-plan",
                    keys.exact_key,
                    url
                );

                if !state.in_flight.contains_key(&parent_key) {
                    let notify = Arc::new(Notify::new());
                    state.in_flight.insert(parent_key.clone(), Arc::clone(&notify));

                    let resolver = Arc::clone(self);
                    let refresh_url = url_owned.clone();
                    let refresh_key = parent_key.clone();
                    tokio::spawn(async move {
                        let _ = resolver.resolve_for_key(refresh_key, refresh_url).await;
                    });
                }

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
                tracing::error!("Erreur lors de la résolution des proxies: {:?}", e);
                (vec!["DIRECT".to_string()], CacheEntryKind::Negative)
            }
            Err(e) => {
                tracing::error!("Erreur task spawn_blocking PAC: {}", e);
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
            anyhow::anyhow!("Impossible d'acquérir le verrou du script PAC: {}", e)
        })?;

        // Normalise l'URL : ajoute un '/' final si le chemin est vide
        let normalized_url = normalize_url_path(url);
        let effective_url = normalized_url.as_deref().unwrap_or(url);

        if normalized_url.is_some() {
            tracing::debug!("URL normalisée pour PAC: '{}' -> '{}'", url, effective_url);
        }

        // Extraire le host de l'URL
        let host = extract_host(effective_url);

        tracing::debug!("Évaluation PAC pour URL='{}', host='{}'", effective_url, host);

        // Évaluer le script PAC avec boa_engine
        let result = evaluate_pac_script(&pac_script, effective_url, &host)?;

        tracing::debug!("PAC FindProxyForURL('{}', '{}') => '{}'", effective_url, host, result);

        // Parser le résultat PAC (ex: "PROXY proxy:8080; DIRECT")
        let proxy_list = parse_pac_result(&result);

        if proxy_list.is_empty() {
            tracing::warn!("Aucun proxy trouvé pour: {}", url);
            Ok(vec!["DIRECT".to_string()])
        } else {
            tracing::debug!("Proxies trouvés pour {}: {:?}", url, proxy_list);
            Ok(proxy_list)
        }
    }
}

// ─── Chargement du fichier PAC ───────────────────────────────────────────────

fn load_pac_script(pac_url: &str) -> Result<String> {
    let trimmed = pac_url.trim();

    if trimmed.is_empty() {
        return Err(anyhow::anyhow!("URL du fichier PAC vide"));
    }

    // URL distante (http/https)
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        tracing::info!("Téléchargement du fichier PAC depuis: {}", trimmed);
        let response = reqwest::blocking::get(trimmed)
            .map_err(|e| anyhow::anyhow!("Erreur téléchargement PAC depuis {}: {}", trimmed, e))?;
        let content = response.text()
            .map_err(|e| anyhow::anyhow!("Erreur lecture contenu PAC depuis {}: {}", trimmed, e))?;
        return Ok(content);
    }

    // Fichier local — convertir le chemin
    let file_path = if trimmed.starts_with("file:///") {
        let path = trimmed.strip_prefix("file:///").unwrap();
        path.replace('/', "\\")
    } else if trimmed.starts_with("file://") {
        let path = trimmed.strip_prefix("file://").unwrap();
        path.to_string()
    } else {
        // Chemin brut (ex: C:\Users\...\file.pac)
        trimmed.to_string()
    };

    tracing::info!("Lecture du fichier PAC local: {}", file_path);
    let content = std::fs::read_to_string(&file_path)
        .map_err(|e| anyhow::anyhow!("Erreur lecture fichier PAC '{}': {}", file_path, e))?;
    Ok(content)
}

// ─── Évaluation JavaScript du PAC ────────────────────────────────────────────

fn evaluate_pac_script(pac_script: &str, url: &str, host: &str) -> Result<String> {
    let mut context = Context::default();

    // Enregistrer les fonctions helper PAC
    register_pac_helpers(&mut context)?;

    // Charger le script PAC
    context
        .eval(Source::from_bytes(pac_script.as_bytes()))
        .map_err(|e| anyhow::anyhow!("Erreur parsing script PAC: {}", e))?;

    // Appeler FindProxyForURL(url, host)
    let call_script = format!(
        "FindProxyForURL(\"{}\", \"{}\")",
        url.replace('\\', "\\\\").replace('"', "\\\""),
        host.replace('\\', "\\\\").replace('"', "\\\"")
    );

    let result = context
        .eval(Source::from_bytes(call_script.as_bytes()))
        .map_err(|e| anyhow::anyhow!("Erreur exécution FindProxyForURL: {}", e))?;

    let result_str = result
        .to_string(&mut context)
        .map_err(|e| anyhow::anyhow!("Erreur conversion résultat PAC en string: {}", e))?;

    Ok(result_str.to_std_string_escaped())
}

fn register_pac_helpers(context: &mut Context) -> Result<()> {
    // isPlainHostName(host)
    context.register_global_builtin_callable(
        js_string!("isPlainHostName"),
        1,
        NativeFunction::from_fn_ptr(pac_is_plain_host_name),
    ).map_err(|e| anyhow::anyhow!("Erreur enregistrement isPlainHostName: {}", e))?;

    // dnsDomainIs(host, domain)
    context.register_global_builtin_callable(
        js_string!("dnsDomainIs"),
        2,
        NativeFunction::from_fn_ptr(pac_dns_domain_is),
    ).map_err(|e| anyhow::anyhow!("Erreur enregistrement dnsDomainIs: {}", e))?;

    // localHostOrDomainIs(host, hostdom)
    context.register_global_builtin_callable(
        js_string!("localHostOrDomainIs"),
        2,
        NativeFunction::from_fn_ptr(pac_local_host_or_domain_is),
    ).map_err(|e| anyhow::anyhow!("Erreur enregistrement localHostOrDomainIs: {}", e))?;

    // isResolvable(host)
    context.register_global_builtin_callable(
        js_string!("isResolvable"),
        1,
        NativeFunction::from_fn_ptr(pac_is_resolvable),
    ).map_err(|e| anyhow::anyhow!("Erreur enregistrement isResolvable: {}", e))?;

    // isInNet(host, pattern, mask)
    context.register_global_builtin_callable(
        js_string!("isInNet"),
        3,
        NativeFunction::from_fn_ptr(pac_is_in_net),
    ).map_err(|e| anyhow::anyhow!("Erreur enregistrement isInNet: {}", e))?;

    // dnsResolve(host)
    context.register_global_builtin_callable(
        js_string!("dnsResolve"),
        1,
        NativeFunction::from_fn_ptr(pac_dns_resolve),
    ).map_err(|e| anyhow::anyhow!("Erreur enregistrement dnsResolve: {}", e))?;

    // myIpAddress()
    context.register_global_builtin_callable(
        js_string!("myIpAddress"),
        0,
        NativeFunction::from_fn_ptr(pac_my_ip_address),
    ).map_err(|e| anyhow::anyhow!("Erreur enregistrement myIpAddress: {}", e))?;

    // dnsDomainLevels(host)
    context.register_global_builtin_callable(
        js_string!("dnsDomainLevels"),
        1,
        NativeFunction::from_fn_ptr(pac_dns_domain_levels),
    ).map_err(|e| anyhow::anyhow!("Erreur enregistrement dnsDomainLevels: {}", e))?;

    // shExpMatch(str, shexp)
    context.register_global_builtin_callable(
        js_string!("shExpMatch"),
        2,
        NativeFunction::from_fn_ptr(pac_sh_exp_match),
    ).map_err(|e| anyhow::anyhow!("Erreur enregistrement shExpMatch: {}", e))?;

    // weekdayRange(...)
    context.register_global_builtin_callable(
        js_string!("weekdayRange"),
        3,
        NativeFunction::from_fn_ptr(pac_weekday_range),
    ).map_err(|e| anyhow::anyhow!("Erreur enregistrement weekdayRange: {}", e))?;

    // dateRange(...)
    context.register_global_builtin_callable(
        js_string!("dateRange"),
        7,
        NativeFunction::from_fn_ptr(pac_date_range),
    ).map_err(|e| anyhow::anyhow!("Erreur enregistrement dateRange: {}", e))?;

    // timeRange(...)
    context.register_global_builtin_callable(
        js_string!("timeRange"),
        7,
        NativeFunction::from_fn_ptr(pac_time_range),
    ).map_err(|e| anyhow::anyhow!("Erreur enregistrement timeRange: {}", e))?;

    // alert(msg)
    context.register_global_builtin_callable(
        js_string!("alert"),
        1,
        NativeFunction::from_fn_ptr(pac_alert),
    ).map_err(|e| anyhow::anyhow!("Erreur enregistrement alert: {}", e))?;

    Ok(())
}

// ─── Implémentation des fonctions helper PAC ─────────────────────────────────

/// isPlainHostName(host) — true si le hostname ne contient pas de point
fn pac_is_plain_host_name(_this: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let host = args.get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    Ok(JsValue::Boolean(!host.contains('.')))
}

/// dnsDomainIs(host, domain) — true si le host se termine par domain
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

/// isResolvable(host) — true si le hostname peut être résolu par DNS
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

/// isInNet(host, pattern, mask) — true si l'IP résolue est dans le sous-réseau
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

/// dnsResolve(host) — résout le hostname en adresse IP
fn pac_dns_resolve(_this: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let host = args.get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();

    match resolve_host_to_ipv4(&host) {
        Some(ip) => Ok(JsValue::String(js_string!(ip.to_string()))),
        None => Ok(JsValue::null()),
    }
}

/// myIpAddress() — retourne l'adresse IP locale
fn pac_my_ip_address(_this: &JsValue, _args: &[JsValue], _context: &mut Context) -> JsResult<JsValue> {
    let ip = get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    Ok(JsValue::String(js_string!(ip)))
}

/// dnsDomainLevels(host) — retourne le nombre de points dans le hostname
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

/// weekdayRange — simplifié, retourne toujours true
fn pac_weekday_range(_this: &JsValue, _args: &[JsValue], _context: &mut Context) -> JsResult<JsValue> {
    Ok(JsValue::Boolean(true))
}

/// dateRange — simplifié, retourne toujours true
fn pac_date_range(_this: &JsValue, _args: &[JsValue], _context: &mut Context) -> JsResult<JsValue> {
    Ok(JsValue::Boolean(true))
}

/// timeRange — simplifié, retourne toujours true
fn pac_time_range(_this: &JsValue, _args: &[JsValue], _context: &mut Context) -> JsResult<JsValue> {
    Ok(JsValue::Boolean(true))
}

/// alert(msg) — log le message pour le debug
fn pac_alert(_this: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let msg = args.get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    tracing::debug!("PAC alert: {}", msg);
    Ok(JsValue::undefined())
}

// ─── Fonctions utilitaires ───────────────────────────────────────────────────

/// Implémentation de shExpMatch (shell expression / glob matching)
fn sh_exp_match(s: &str, pattern: &str) -> bool {
    // Convertir le pattern glob en regex
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

/// Résolution DNS host -> IPv4
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

/// Obtenir l'adresse IP locale
fn get_local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:53").ok()?;
    let local_addr = socket.local_addr().ok()?;
    Some(local_addr.ip().to_string())
}

/// Extraire le host d'une URL
fn extract_host(url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            return host.to_string();
        }
    }
    url.to_string()
}

/// Parser le résultat PAC (ex: "PROXY proxy:8080; DIRECT" -> vec!["PROXY proxy:8080", "DIRECT"])
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
        let age = entry.stored_at.elapsed();
        if entry.kind == CacheEntryKind::Negative {
            if age <= PAC_NEGATIVE_TTL {
                return Some((entry.proxies, true));
            }
        } else if age <= cache_ttl {
            return Some((entry.proxies, true));
        } else if age <= stale_ttl {
            return Some((entry.proxies, false));
        }
    }
    state.cache.remove(&keys.exact_key);

    if keys.parent_key != keys.exact_key {
        if let Some(entry) = state.cache.get(&keys.parent_key).cloned() {
            let age = entry.stored_at.elapsed();
            if entry.kind == CacheEntryKind::Negative {
                if age <= PAC_NEGATIVE_TTL {
                    return Some((entry.proxies, true));
                }
            } else if age <= cache_ttl {
                return Some((entry.proxies, true));
            } else if age <= stale_ttl {
                return Some((entry.proxies, false));
            }
        }
        state.cache.remove(&keys.parent_key);
    }

    None
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

/// Normalise le chemin d'une URL : si le chemin est vide, ajoute un `/` final.
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
