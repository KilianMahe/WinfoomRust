// Support pour Proxy Auto Config (PAC)
use anyhow::Result;
use libproxy::ProxyFactory;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as TokioMutex, Notify};

const PAC_NEGATIVE_TTL: Duration = Duration::from_secs(15);

pub struct PacResolver {
    factory: Mutex<ProxyFactory>,
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
    cache_ttl_seconds: u64,
    stale_ttl_seconds: u64,
    resolver: Arc<PacResolver>,
}

static SHARED_PAC_RESOLVER: Lazy<Mutex<Option<SharedResolverState>>> =
    Lazy::new(|| Mutex::new(None));

impl PacResolver {
    pub fn shared(cache_ttl_seconds: u64, stale_ttl_seconds: u64) -> Result<Arc<Self>> {
        let mut guard = SHARED_PAC_RESOLVER.lock().map_err(|e| {
            anyhow::anyhow!("Impossible d'acquérir le verrou du resolver PAC partagé: {}", e)
        })?;

        if let Some(state) = guard.as_ref() {
            if state.cache_ttl_seconds == cache_ttl_seconds
                && state.stale_ttl_seconds == stale_ttl_seconds
            {
                return Ok(Arc::clone(&state.resolver));
            }
        }

        let resolver = Arc::new(Self::new(cache_ttl_seconds, stale_ttl_seconds)?);
        *guard = Some(SharedResolverState {
            cache_ttl_seconds,
            stale_ttl_seconds,
            resolver: Arc::clone(&resolver),
        });

        Ok(resolver)
    }

    /// Crée une nouvelle instance de PacResolver avec libproxy
    pub fn new(cache_ttl_seconds: u64, stale_ttl_seconds: u64) -> Result<Self> {
        tracing::info!(
            "Initialisation du PacResolver avec libproxy (ttl={}s, stale={}s)",
            cache_ttl_seconds,
            stale_ttl_seconds
        );

        let cache_ttl = Duration::from_secs(cache_ttl_seconds.max(1));
        let stale_ttl = Duration::from_secs(stale_ttl_seconds.max(cache_ttl_seconds.max(1)));
        
        let factory = ProxyFactory::new()
            .ok_or_else(|| anyhow::anyhow!("Impossible d'initialiser ProxyFactory"))?;
        
        Ok(PacResolver {
            factory: Mutex::new(factory),
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
        let factory = self.factory.lock().map_err(|e| {
            anyhow::anyhow!("Impossible d'acquérir le verrou du factory: {}", e)
        })?;

        match factory.get_proxies(url) {
            Ok(proxies) => {
                let proxy_list: Vec<String> = proxies.iter().map(|p| p.to_string()).collect();

                if proxy_list.is_empty() {
                    tracing::warn!("Aucun proxy trouvé pour: {}", url);
                    Ok(vec!["DIRECT".to_string()])
                } else {
                    tracing::debug!("Proxies trouvés pour {}: {:?}", url, proxy_list);
                    Ok(proxy_list)
                }
            }
            Err(e) => Err(anyhow::anyhow!("Erreur libproxy: {:?}", e)),
        }
    }
}

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
