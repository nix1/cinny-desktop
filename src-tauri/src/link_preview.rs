//! Link previews fetched by the desktop app itself, so links from encrypted rooms are
//! never sent to the homeserver. The result has the same shape as Matrix's
//! `/preview_url` response (`og:title`, `og:description`, `og:image`, ...).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::Duration;

use regex::Regex;
use tauri_plugin_http::reqwest::{self, redirect, Url};

const MAX_BYTES: usize = 1024 * 1024;
const USER_AGENT: &str = "Mozilla/5.0 (compatible; Cannella link preview; +https://github.com/nix1/cinny-desktop)";

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64) // CGNAT
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || (first & 0xfe00) == 0xfc00 // unique local
                || (first & 0xffc0) == 0xfe80) // link local
        }
    }
}

/// Refuses URLs that point at this machine or the local network: a message must not be
/// able to make the app read internal services.
async fn check_url(url: &Url) -> Result<(), String> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err("unsupported scheme".into());
    }
    let host = url.host_str().ok_or("no host")?;
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".local") {
        return Err("local host".into());
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs = tokio::net::lookup_host((host.trim_matches(['[', ']']), port))
        .await
        .map_err(|e| e.to_string())?;
    for addr in addrs {
        if !is_public_ip(addr.ip()) {
            return Err("private address".into());
        }
    }
    Ok(())
}

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(10))
            .redirect(redirect::Policy::custom(|attempt| {
                let blocked = attempt.previous().len() >= 5
                    || match attempt.url().host() {
                        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
                        Some(url::Host::Ipv4(ip)) => !is_public_ip(IpAddr::V4(ip)),
                        Some(url::Host::Ipv6(ip)) => !is_public_ip(IpAddr::V6(ip)),
                        None => true,
                    };
                if blocked {
                    attempt.stop()
                } else {
                    attempt.follow()
                }
            }))
            .build()
            .expect("http client")
    })
}

fn decode_entities(s: &str) -> String {
    static NUM: OnceLock<Regex> = OnceLock::new();
    let num = NUM.get_or_init(|| Regex::new(r"&#(x[0-9a-fA-F]+|[0-9]+);").unwrap());
    let s = num.replace_all(s, |c: &regex::Captures| {
        let v = &c[1];
        let code = if let Some(hex) = v.strip_prefix('x') {
            u32::from_str_radix(hex, 16).ok()
        } else {
            v.parse().ok()
        };
        code.and_then(char::from_u32).map(String::from).unwrap_or_default()
    });
    s.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .trim()
        .to_string()
}

fn parse_html(html: &str, base: &Url) -> HashMap<String, String> {
    static META: OnceLock<Regex> = OnceLock::new();
    static ATTR: OnceLock<Regex> = OnceLock::new();
    static TITLE: OnceLock<Regex> = OnceLock::new();
    let meta = META.get_or_init(|| Regex::new(r"(?is)<meta\b[^>]*>").unwrap());
    let attr = ATTR.get_or_init(|| {
        Regex::new(r#"(?is)([a-z:_-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"#).unwrap()
    });
    let title = TITLE.get_or_init(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap());

    let mut tags: HashMap<String, String> = HashMap::new();
    for tag in meta.find_iter(html) {
        let mut key = None;
        let mut content = None;
        for a in attr.captures_iter(tag.as_str()) {
            let value = a.get(2).or(a.get(3)).or(a.get(4)).map_or("", |m| m.as_str());
            match a[1].to_ascii_lowercase().as_str() {
                "property" | "name" | "itemprop" => key = Some(value.to_ascii_lowercase()),
                "content" => content = Some(decode_entities(value)),
                _ => {}
            }
        }
        if let (Some(k), Some(c)) = (key, content) {
            if !c.is_empty() {
                tags.entry(k).or_insert(c);
            }
        }
    }

    let mut out = HashMap::new();
    let pick = |keys: &[&str]| keys.iter().find_map(|k| tags.get(*k).cloned());
    let page_title = title.captures(html).map(|c| decode_entities(&c[1]));
    if let Some(v) = pick(&["og:title", "twitter:title"]).or(page_title) {
        out.insert("og:title".into(), v);
    }
    if let Some(v) = pick(&["og:description", "twitter:description", "description"]) {
        out.insert("og:description".into(), v);
    }
    if let Some(v) = pick(&["og:site_name", "application-name"]) {
        out.insert("og:site_name".into(), v);
    }
    if let Some(v) = pick(&["og:image", "og:image:url", "og:image:secure_url", "twitter:image", "twitter:image:src", "image"]) {
        if let Ok(abs) = base.join(&v) {
            if matches!(abs.scheme(), "http" | "https") {
                out.insert("og:image".into(), abs.to_string());
            }
        }
    }
    out
}

#[tauri::command]
pub async fn link_preview(url: String) -> Result<HashMap<String, String>, String> {
    let url = Url::parse(&url).map_err(|e| e.to_string())?;
    check_url(&url).await?;

    let mut resp = client()
        .get(url.clone())
        .header("Accept", "text/html,application/xhtml+xml,image/*;q=0.8,*/*;q=0.5")
        .header("Accept-Language", "pl,en;q=0.8")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("status {}", resp.status()));
    }
    let final_url = resp.url().clone();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    if content_type.starts_with("image/") {
        return Ok(HashMap::from([("og:image".to_string(), final_url.to_string())]));
    }
    if !content_type.contains("html") {
        return Err("not html".into());
    }

    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        body.extend_from_slice(&chunk);
        if body.len() >= MAX_BYTES {
            break;
        }
    }
    let html = String::from_utf8_lossy(&body);
    let preview = parse_html(&html, &final_url);
    if preview.is_empty() {
        return Err("no metadata".into());
    }
    Ok(preview)
}
