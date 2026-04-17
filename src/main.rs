use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use futures_util::StreamExt;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, watch};
use tokio_tungstenite::connect_async;
use tower_http::services::ServeDir;
use tracing::{error, info, warn};

// ─── Rule type ────────────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RuleType {
    /// Automatically infer from value (IP→IP-CIDR, hostname→DOMAIN-SUFFIX)
    Auto,
    Domain,
    DomainSuffix,
    DomainKeyword,
    IpCidr,
    IpCidr6,
}

// ─── Domain entry (with metadata) ─────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct DomainEntry {
    pub first_seen: u64,
    pub last_seen: u64,
    pub hit_count: u32,
    pub rule_type: RuleType,
}

impl DomainEntry {
    fn new() -> Self {
        let now = now_unix();
        Self { first_seen: now, last_seen: now, hit_count: 1, rule_type: RuleType::Auto }
    }

    fn bump(&mut self) {
        self.last_seen = now_unix();
        self.hit_count = self.hit_count.saturating_add(1);
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

const RECORD_FUSE_WINDOW_SECS: u64 = 15;
const RECORD_FUSE_TOTAL_THRESHOLD: usize = 40;
const RECORD_FUSE_UNIQUE_THRESHOLD: usize = 15;
const RECORD_FUSE_COOLDOWN_SECS: u64 = 90;
const REQUIRED_LOG_MARKER: &str = "(match Match/)";

struct RecordFuse {
    recent: VecDeque<(u64, String)>,
    open_until: Option<u64>,
}

impl RecordFuse {
    fn new() -> Self {
        Self { recent: VecDeque::new(), open_until: None }
    }

    fn reset(&mut self) {
        self.recent.clear();
        self.open_until = None;
    }

    fn allows(&mut self, key: &str) -> bool {
        let now = now_unix();

        if let Some(until) = self.open_until {
            if now < until {
                return false;
            }

            info!("[Fuse] Recording resumed after cooldown.");
            self.open_until = None;
            self.recent.clear();
        }

        self.recent.push_back((now, key.to_string()));
        while let Some((seen_at, _)) = self.recent.front() {
            if now.saturating_sub(*seen_at) > RECORD_FUSE_WINDOW_SECS {
                let _ = self.recent.pop_front();
            } else {
                break;
            }
        }

        if self.recent.len() < RECORD_FUSE_TOTAL_THRESHOLD {
            return true;
        }

        let unique_count = self.recent
            .iter()
            .map(|(_, key)| key.as_str())
            .collect::<HashSet<_>>()
            .len();

        if unique_count >= RECORD_FUSE_UNIQUE_THRESHOLD {
            let until = now.saturating_add(RECORD_FUSE_COOLDOWN_SECS);
            self.open_until = Some(until);
            self.recent.clear();
            warn!(
                "[Fuse] Recording paused for {}s after {} matched failures across {} unique targets in {}s.",
                RECORD_FUSE_COOLDOWN_SECS,
                RECORD_FUSE_TOTAL_THRESHOLD,
                unique_count,
                RECORD_FUSE_WINDOW_SECS
            );
            return false;
        }

        true
    }
}

// ─── Config ───────────────────────────────────────────────────────────────────

fn default_min_hit() -> u32 { 1 }
fn default_cidr_agg() -> u32 { 3 }

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(rename = "wsUrl")]
    pub ws_url: String,
    #[serde(rename = "filterKeyword")]
    pub filter_keyword: String,
    #[serde(rename = "matchRegex")]
    pub match_regex: String,
    /// Minimum times a target must appear before being included in the YAML
    #[serde(rename = "minHitCount", default = "default_min_hit")]
    pub min_hit_count: u32,
    /// Days after last_seen before a rule is excluded (0 = never expire)
    #[serde(rename = "ruleTtlDays", default)]
    pub rule_ttl_days: u32,
    /// Number of IPs from the same /24 needed to aggregate into a /24 rule (0 = disabled)
    #[serde(rename = "cidrAggThreshold", default = "default_cidr_agg")]
    pub cidr_agg_threshold: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ws_url: "ws://192.168.100.1:9090/logs?token=cEtch6ZJ&level=info".into(),
            filter_keyword: " error: ".into(),
            match_regex: r"-->\s+([^\s:]+):\d+\s+error:".into(),
            min_hit_count: 1,
            rule_ttl_days: 0,
            cidr_agg_threshold: 3,
        }
    }
}

// ─── YAML params (cheap copy; extracted before acquiring other locks) ─────────

#[derive(Clone)]
struct YamlParams {
    min_hit_count: u32,
    rule_ttl_days: u32,
    cidr_agg_threshold: u32,
}

impl YamlParams {
    /// Borrow config lock, clone params, then immediately release the lock.
    async fn from_state(state: &AppState) -> Self {
        let cfg = state.config.lock().await;
        Self::from_config(&cfg)
        // cfg lock released here
    }

    fn from_config(cfg: &Config) -> Self {
        Self {
            min_hit_count: cfg.min_hit_count,
            rule_ttl_days: cfg.rule_ttl_days,
            cidr_agg_threshold: cfg.cidr_agg_threshold,
        }
    }
}

// ─── App state ────────────────────────────────────────────────────────────────
//
// Lock acquisition order (always respect to avoid deadlocks):
//   1. entries
//   2. blacklist
//   3. yaml_cache  (only locked inside sync_all; get_yaml holds no other locks)

#[derive(Clone)]
struct AppState {
    config: Arc<Mutex<Config>>,
    entries: Arc<Mutex<HashMap<String, DomainEntry>>>,
    blacklist: Arc<Mutex<HashSet<String>>>,
    yaml_cache: Arc<Mutex<String>>,
    ws_connected: Arc<AtomicBool>,
    rules_path: PathBuf,
    entries_path: PathBuf,
    config_path: PathBuf,
    blacklist_path: PathBuf,
    ws_restart_tx: watch::Sender<Config>,
}

// ─── Persistence ──────────────────────────────────────────────────────────────

fn load_config(path: &PathBuf) -> Config {
    if path.exists() {
        if let Ok(s) = std::fs::read_to_string(path) {
            if let Ok(c) = serde_json::from_str(&s) {
                return c;
            }
        }
    }
    Config::default()
}

fn save_config(path: &PathBuf, config: &Config) {
    let _ = std::fs::write(path, serde_json::to_string_pretty(config).unwrap());
}

/// Load entries.json; if absent, attempt migration from old dynamic_rule.yaml.
fn load_entries(entries_path: &PathBuf, rules_path: &PathBuf) -> HashMap<String, DomainEntry> {
    if entries_path.exists() {
        if let Ok(s) = std::fs::read_to_string(entries_path) {
            if let Ok(m) = serde_json::from_str::<HashMap<String, DomainEntry>>(&s) {
                return m;
            }
        }
    }
    // Migrate from old dynamic_rule.yaml (individual /32 and DOMAIN-SUFFIX entries only)
    let mut map = HashMap::new();
    if let Ok(content) = std::fs::read_to_string(rules_path) {
        for line in content.lines() {
            let t = line.trim();
            let key: Option<String> = if let Some(r) = t.strip_prefix("- DOMAIN-SUFFIX,") {
                Some(r.trim().to_string())
            } else if let Some(r) = t.strip_prefix("- DOMAIN,") {
                Some(r.trim().to_string())
            } else if let Some(r) = t.strip_prefix("- IP-CIDR,") {
                // Skip aggregated /24 or /16 rules; only migrate explicit /32
                if r.ends_with("/32") {
                    r.split('/').next().map(|s| s.to_string())
                } else {
                    None
                }
            } else if let Some(r) = t.strip_prefix("- IP-CIDR6,") {
                if r.ends_with("/128") {
                    r.split('/').next().map(|s| s.to_string())
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(k) = key {
                if !k.is_empty() {
                    map.insert(k, DomainEntry::new());
                }
            }
        }
    }
    map
}

fn save_entries(path: &PathBuf, entries: &HashMap<String, DomainEntry>) {
    let content = serde_json::to_string_pretty(entries).unwrap_or_default();
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, &content).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

fn load_blacklist(path: &PathBuf) -> HashSet<String> {
    if path.exists() {
        if let Ok(s) = std::fs::read_to_string(path) {
            if let Ok(v) = serde_json::from_str::<Vec<String>>(&s) {
                return v.into_iter().collect();
            }
        }
    }
    HashSet::new()
}

fn save_blacklist(path: &PathBuf, bl: &HashSet<String>) {
    let v: Vec<&str> = bl.iter().map(|s| s.as_str()).collect();
    let _ = std::fs::write(path, serde_json::to_string_pretty(&v).unwrap());
}

// ─── YAML building ────────────────────────────────────────────────────────────

fn ip_version(s: &str) -> Option<u8> {
    IpAddr::from_str(s).ok().map(|ip| match ip {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 6,
    })
}

fn resolve_rule_type(key: &str, rt: &RuleType) -> RuleType {
    match rt {
        RuleType::Auto => match ip_version(key) {
            Some(4) => RuleType::IpCidr,
            Some(6) => RuleType::IpCidr6,
            _ => RuleType::DomainSuffix,
        },
        other => other.clone(),
    }
}

fn is_entry_active(
    key: &str,
    entry: &DomainEntry,
    blacklist: &HashSet<String>,
    params: &YamlParams,
) -> bool {
    if blacklist.contains(key) { return false; }
    if entry.hit_count < params.min_hit_count { return false; }
    if params.rule_ttl_days > 0 {
        let ttl_secs = params.rule_ttl_days as u64 * 86400;
        if now_unix().saturating_sub(entry.last_seen) > ttl_secs { return false; }
    }
    true
}

/// Group IPv4 addresses by /24; emit subnet rule if count >= threshold, else /32 per IP.
fn aggregate_ipv4(addrs: Vec<Ipv4Addr>, threshold: u32) -> Vec<String> {
    let mut by_24: HashMap<[u8; 3], Vec<Ipv4Addr>> = HashMap::new();
    for ip in addrs {
        let o = ip.octets();
        by_24.entry([o[0], o[1], o[2]]).or_default().push(ip);
    }
    let mut rules = Vec::new();
    for (prefix, ips) in by_24 {
        if threshold > 0 && ips.len() >= threshold as usize {
            rules.push(format!("  - IP-CIDR,{}.{}.{}.0/24", prefix[0], prefix[1], prefix[2]));
        } else {
            for ip in ips {
                rules.push(format!("  - IP-CIDR,{}/32", ip));
            }
        }
    }
    rules
}

fn build_yaml(
    entries: &HashMap<String, DomainEntry>,
    blacklist: &HashSet<String>,
    params: &YamlParams,
) -> String {
    let mut ipv4_addrs: Vec<Ipv4Addr> = Vec::new();
    let mut ipv6_rules: Vec<String> = Vec::new();
    let mut domain_exact: Vec<String> = Vec::new();
    let mut domain_suffix: Vec<String> = Vec::new();
    let mut domain_keyword: Vec<String> = Vec::new();

    for (key, entry) in entries {
        if !is_entry_active(key, entry, blacklist, params) {
            continue;
        }
        match resolve_rule_type(key, &entry.rule_type) {
            RuleType::IpCidr => {
                if let Ok(ip) = key.parse::<Ipv4Addr>() {
                    ipv4_addrs.push(ip);
                }
            }
            RuleType::IpCidr6 => {
                ipv6_rules.push(format!("  - IP-CIDR6,{}/128", key));
            }
            RuleType::Domain => {
                domain_exact.push(format!("  - DOMAIN,{}", key));
            }
            RuleType::DomainSuffix => {
                domain_suffix.push(format!("  - DOMAIN-SUFFIX,{}", key));
            }
            RuleType::DomainKeyword => {
                domain_keyword.push(format!("  - DOMAIN-KEYWORD,{}", key));
            }
            RuleType::Auto => unreachable!(),
        }
    }

    // Aggregate IPv4 by /24 if threshold met
    let mut ipv4_rules = aggregate_ipv4(ipv4_addrs, params.cidr_agg_threshold);

    // Sort each section for deterministic, readable output
    ipv4_rules.sort();
    ipv6_rules.sort();
    domain_exact.sort();
    domain_suffix.sort();
    domain_keyword.sort();

    // Ordered output: specific IPs first, then domains (broad last)
    let mut yaml = String::from("payload:\n");
    for rule in ipv4_rules.iter()
        .chain(ipv6_rules.iter())
        .chain(domain_exact.iter())
        .chain(domain_suffix.iter())
        .chain(domain_keyword.iter())
    {
        yaml.push_str(rule);
        yaml.push('\n');
    }
    yaml
}

/// Atomic YAML write (tmp → rename), update entries.json, refresh in-memory cache.
/// Call while holding entries + blacklist locks (in that order).
async fn sync_all(
    state: &AppState,
    entries: &HashMap<String, DomainEntry>,
    bl: &HashSet<String>,
    params: &YamlParams,
) {
    let yaml = build_yaml(entries, bl, params);
    let tmp = state.rules_path.with_extension("tmp");
    if std::fs::write(&tmp, &yaml).is_ok() {
        let _ = std::fs::rename(&tmp, &state.rules_path);
    }
    save_entries(&state.entries_path, entries);
    *state.yaml_cache.lock().await = yaml;
}

fn extract_payload(text: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        v.get("payload")
            .and_then(|p| p.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| text.to_string())
    } else {
        text.to_string()
    }
}

// ─── WS watcher ───────────────────────────────────────────────────────────────

async fn ws_watcher(state: AppState, mut restart_rx: watch::Receiver<Config>) {
    let mut record_fuse = RecordFuse::new();

    loop {
        let cfg = restart_rx.borrow_and_update().clone();
        let params = YamlParams::from_config(&cfg);
        record_fuse.reset();
        state.ws_connected.store(false, Ordering::Relaxed);
        info!("[WS] Connecting to {}", cfg.ws_url);

        let regex = match Regex::new(&cfg.match_regex) {
            Ok(r) => r,
            Err(e) => {
                error!("[WS] Invalid regex: {}", e);
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    _ = restart_rx.changed() => {}
                }
                continue;
            }
        };

        match connect_async(&cfg.ws_url).await {
            Err(e) => {
                error!("[WS] Connection failed: {}. Retrying in 5s...", e);
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    _ = restart_rx.changed() => {}
                }
            }
            Ok((ws_stream, _)) => {
                state.ws_connected.store(true, Ordering::Relaxed);
                info!("[WS] Connected.");
                let (_write_half, mut read) = ws_stream.split();

                'msg_loop: loop {
                    tokio::select! {
                        msg = read.next() => {
                            match msg {
                                None => {
                                    info!("[WS] Connection closed. Reconnecting in 5s...");
                                    state.ws_connected.store(false, Ordering::Relaxed);
                                    tokio::time::sleep(Duration::from_secs(5)).await;
                                    break 'msg_loop;
                                }
                                Some(Err(e)) => {
                                    error!("[WS] Error: {}. Reconnecting in 5s...", e);
                                    state.ws_connected.store(false, Ordering::Relaxed);
                                    tokio::time::sleep(Duration::from_secs(5)).await;
                                    break 'msg_loop;
                                }
                                Some(Ok(msg)) => {
                                    let text = msg.to_text().unwrap_or("").to_string();
                                    let payload = extract_payload(&text);

                                    if payload.contains(&cfg.filter_keyword)
                                        && payload.contains(REQUIRED_LOG_MARKER)
                                    {
                                        if let Some(caps) = regex.captures(&payload) {
                                            if let Some(m) = caps.get(1) {
                                                let key = m.as_str().to_string();

                                                if !record_fuse.allows(&key) {
                                                    continue;
                                                }

                                                let mut entries = state.entries.lock().await;
                                                let bl = state.blacklist.lock().await;

                                                if bl.contains(&key) {
                                                    continue;
                                                }

                                                let needs_sync = if let Some(e) = entries.get_mut(&key) {
                                                    let before = e.hit_count;
                                                    e.bump();
                                                    // Sync when crossing threshold, or every 10 hits
                                                    (before + 1 == params.min_hit_count)
                                                        || e.hit_count % 10 == 0
                                                } else {
                                                    entries.insert(key.clone(), DomainEntry::new());
                                                    info!("Captured: {}", key);
                                                    true
                                                };

                                                if needs_sync {
                                                    sync_all(&state, &entries, &bl, &params).await;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ = restart_rx.changed() => {
                            info!("[WS] Config changed, reconnecting...");
                            state.ws_connected.store(false, Ordering::Relaxed);
                            break 'msg_loop;
                        }
                    }
                }
                // _write_half dropped here → socket closes cleanly
            }
        }
    }
}

// ─── API handlers ─────────────────────────────────────────────────────────────

async fn get_config(State(state): State<AppState>) -> Json<Config> {
    Json(state.config.lock().await.clone())
}

async fn post_config(
    State(state): State<AppState>,
    Json(body): Json<Config>,
) -> Json<serde_json::Value> {
    let new_cfg = {
        let mut cfg = state.config.lock().await;
        *cfg = body.clone();
        save_config(&state.config_path, &cfg);
        body
        // config lock released here
    };
    let params = YamlParams::from_config(&new_cfg);
    // Rebuild YAML immediately with new threshold/TTL/aggregation settings
    let entries = state.entries.lock().await;
    let bl = state.blacklist.lock().await;
    sync_all(&state, &entries, &bl, &params).await;
    drop(bl);
    drop(entries);
    let _ = state.ws_restart_tx.send(new_cfg);
    Json(serde_json::json!({ "success": true }))
}

#[derive(Serialize)]
struct DomainInfo {
    domain: String,
    hit_count: u32,
    first_seen: u64,
    last_seen: u64,
    /// The persisted value selected by the user or inferred on first insert.
    rule_type: RuleType,
    /// The rule type currently applied when generating YAML.
    resolved_rule_type: RuleType,
    /// Whether this entry currently appears in the generated YAML
    in_yaml: bool,
}

#[derive(Serialize)]
struct DomainsResponse {
    domains: Vec<DomainInfo>,
    blacklist: Vec<String>,
}

async fn get_domains(State(state): State<AppState>) -> Json<DomainsResponse> {
    let params = YamlParams::from_state(&state).await;
    let entries = state.entries.lock().await;
    let bl = state.blacklist.lock().await;

    let mut domains: Vec<DomainInfo> = entries
        .iter()
        .map(|(key, entry)| DomainInfo {
            domain: key.clone(),
            hit_count: entry.hit_count,
            first_seen: entry.first_seen,
            last_seen: entry.last_seen,
            rule_type: entry.rule_type.clone(),
            resolved_rule_type: resolve_rule_type(key, &entry.rule_type),
            in_yaml: is_entry_active(key, entry, &bl, &params),
        })
        .collect();

    // Newest first
    domains.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));

    let blacklist: Vec<String> = bl.iter().cloned().collect();
    Json(DomainsResponse { domains, blacklist })
}

#[derive(Deserialize)]
struct DomainBody {
    domain: String,
}

#[derive(Deserialize)]
struct UpdateRuleTypeBody {
    domain: String,
    rule_type: RuleType,
}

async fn update_rule_type(
    State(state): State<AppState>,
    Json(body): Json<UpdateRuleTypeBody>,
) -> Json<serde_json::Value> {
    let params = YamlParams::from_state(&state).await;
    let mut entries = state.entries.lock().await;
    let bl = state.blacklist.lock().await;
    if let Some(entry) = entries.get_mut(&body.domain) {
        entry.rule_type = body.rule_type;
        sync_all(&state, &entries, &bl, &params).await;
    }
    Json(serde_json::json!({ "success": true }))
}

async fn add_blacklist(
    State(state): State<AppState>,
    Json(body): Json<DomainBody>,
) -> Json<serde_json::Value> {
    let params = YamlParams::from_state(&state).await;
    let entries = state.entries.lock().await;
    let mut bl = state.blacklist.lock().await;
    bl.insert(body.domain.clone());
    save_blacklist(&state.blacklist_path, &bl);
    sync_all(&state, &entries, &bl, &params).await;
    Json(serde_json::json!({ "success": true }))
}

async fn remove_blacklist(
    State(state): State<AppState>,
    Json(body): Json<DomainBody>,
) -> Json<serde_json::Value> {
    let params = YamlParams::from_state(&state).await;
    let entries = state.entries.lock().await;
    let mut bl = state.blacklist.lock().await;
    bl.remove(&body.domain);
    save_blacklist(&state.blacklist_path, &bl);
    sync_all(&state, &entries, &bl, &params).await;
    Json(serde_json::json!({ "success": true }))
}

async fn delete_domain(
    State(state): State<AppState>,
    Json(body): Json<DomainBody>,
) -> Json<serde_json::Value> {
    let params = YamlParams::from_state(&state).await;
    let mut entries = state.entries.lock().await;
    let bl = state.blacklist.lock().await;
    entries.remove(&body.domain);
    sync_all(&state, &entries, &bl, &params).await;
    Json(serde_json::json!({ "success": true }))
}

async fn get_yaml(State(state): State<AppState>) -> impl IntoResponse {
    let content = state.yaml_cache.lock().await.clone();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        content,
    )
}

#[derive(Serialize)]
struct StatusResponse {
    ws_connected: bool,
}

async fn get_status(State(state): State<AppState>) -> Json<StatusResponse> {
    Json(StatusResponse { ws_connected: state.ws_connected.load(Ordering::Relaxed) })
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let base_dir = std::env::var("DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().unwrap());

    let public_dir = std::env::var("PUBLIC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| base_dir.join("public"));

    let rules_path = base_dir.join("dynamic_rule.yaml");
    let entries_path = base_dir.join("entries.json");
    let config_path = base_dir.join("config.json");
    let blacklist_path = base_dir.join("blacklist.json");

    let config = load_config(&config_path);
    save_config(&config_path, &config);
    let params = YamlParams::from_config(&config);

    let blacklist = load_blacklist(&blacklist_path);
    let entries = load_entries(&entries_path, &rules_path);

    let initial_yaml = build_yaml(&entries, &blacklist, &params);
    let tmp = rules_path.with_extension("tmp");
    if std::fs::write(&tmp, &initial_yaml).is_ok() {
        let _ = std::fs::rename(&tmp, &rules_path);
    }

    let (ws_restart_tx, ws_restart_rx) = watch::channel(config.clone());

    let state = AppState {
        config: Arc::new(Mutex::new(config)),
        entries: Arc::new(Mutex::new(entries)),
        blacklist: Arc::new(Mutex::new(blacklist)),
        yaml_cache: Arc::new(Mutex::new(initial_yaml)),
        ws_connected: Arc::new(AtomicBool::new(false)),
        rules_path,
        entries_path,
        config_path,
        blacklist_path,
        ws_restart_tx,
    };

    let ws_state = state.clone();
    tokio::spawn(async move { ws_watcher(ws_state, ws_restart_rx).await });

    let app = Router::new()
        .route("/dynamic_rule.yaml", get(get_yaml))
        .route("/api/status", get(get_status))
        .route("/api/config", get(get_config).post(post_config))
        .route("/api/domains", get(get_domains).delete(delete_domain))
        .route("/api/domains/rule-type", post(update_rule_type))
        .route("/api/blacklist", post(add_blacklist))
        .route("/api/blacklist/remove", post(remove_blacklist))
        .nest_service("/", ServeDir::new(public_dir))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    info!("mihomo-logfence started on http://localhost:3000");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
