//! Optional IP geolocation for the client-IP modal.
//!
//! Uses a free, key-less HTTPS service (ipwho.is by default) through curl —
//! the codebase carries no HTTP client. The lookup is opt-out: clearing
//! `geoip_url` in config.toml disables it entirely. Results are cached on disk
//! for 30 days, so an address is looked up once, not on every view.
//!
//! Privacy: the address being investigated is sent to the configured provider.
//! Nothing else leaves the server — no message data, no server identity.

use crate::json::Json;
use crate::Config;
use std::path::PathBuf;
use std::process::Command;

const CACHE_TTL_SECS: u64 = 30 * 86_400;

fn cache_path(config_file: &std::path::Path, ip: &str) -> PathBuf {
    let safe: String = ip
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    config_file
        .parent()
        .unwrap_or(std::path::Path::new("/etc/msfe-ng"))
        .join("cache/geoip")
        .join(format!("{safe}.json"))
}

fn fresh(path: &std::path::Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    let age = meta.modified().ok()?.elapsed().ok()?;
    (age.as_secs() < CACHE_TTL_SECS)
        .then(|| std::fs::read_to_string(path).ok())
        .flatten()
}

/// Raw provider response for `ip`, from cache when recent.
fn fetch(cfg: &Config, config_file: &std::path::Path, ip: &str) -> Option<String> {
    if cfg.geoip_url.trim().is_empty() {
        return None;
    }
    let path = cache_path(config_file, ip);
    if let Some(hit) = fresh(&path) {
        return Some(hit);
    }
    let url = cfg.geoip_url.replace("{ip}", ip);
    let out = Command::new("curl")
        .args(["-sS", "--max-time", "6", "-A", "msfe-ng", &url])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let body = String::from_utf8_lossy(&out.stdout).into_owned();
    if body.trim().is_empty() {
        return None;
    }
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&path, &body);
    Some(body)
}

/// First present value among `keys`, looked up at the top level and inside the
/// nested objects providers like to use (`connection`, `asn`).
fn field(v: &Json, keys: &[&str]) -> Option<String> {
    let render = |j: &Json| -> Option<String> {
        match j {
            Json::Str(s) if !s.trim().is_empty() => Some(s.clone()),
            Json::Int(n) => Some(n.to_string()),
            Json::Num(n) => Some(n.clone()),
            _ => None,
        }
    };
    for k in keys {
        if let Some(x) = v.get(k).and_then(&render) {
            return Some(x);
        }
        for nest in ["connection", "asn", "company"] {
            if let Some(x) = v.get(nest).and_then(|n| n.get(k)).and_then(&render) {
                return Some(x);
            }
        }
    }
    None
}

/// Human-readable location rows for the UI: (label, value), empty when the
/// lookup is disabled, fails, or the provider reports nothing useful.
/// Field names cover ipwho.is and ip-api.com shapes.
pub fn lookup(cfg: &Config, config_file: &std::path::Path, ip: &str) -> Vec<(String, String)> {
    let Some(body) = fetch(cfg, config_file, ip) else {
        return Vec::new();
    };
    let Ok(v) = Json::parse(&body) else {
        return Vec::new();
    };
    // providers signal failure differently: {"success":false} / {"status":"fail"}
    if matches!(v.get("success"), Some(Json::Bool(false)))
        || v.get("status").and_then(Json::as_str) == Some("fail")
    {
        return Vec::new();
    }
    let mut rows = Vec::new();
    let mut push = |label: &str, val: Option<String>| {
        if let Some(x) = val {
            if !x.trim().is_empty() {
                rows.push((label.to_string(), x));
            }
        }
    };
    let country = field(&v, &["country"]);
    let code = field(&v, &["country_code", "countryCode"]);
    push(
        "Country",
        match (country, code) {
            (Some(c), Some(cc)) => Some(format!("{c} ({cc})")),
            (c, cc) => c.or(cc),
        },
    );
    push(
        "Region",
        field(&v, &["region", "regionName", "region_name"]),
    );
    push("City", field(&v, &["city"]));
    push("Organisation", field(&v, &["org", "organisation", "isp"]));
    push("ASN", field(&v, &["asn", "as"]));
    push("Timezone", field(&v, &["timezone", "id"]));
    let (lat, lon) = (
        field(&v, &["latitude", "lat"]),
        field(&v, &["longitude", "lon"]),
    );
    if let (Some(la), Some(lo)) = (lat, lon) {
        rows.push(("Coordinates".into(), format!("{la}, {lo}")));
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipwhois_shape() {
        let body = r#"{"ip":"49.12.174.167","success":true,"country":"Germany","country_code":"DE",
            "region":"Bavaria","city":"Nuremberg","latitude":49.45,"longitude":11.07,
            "connection":{"asn":24940,"org":"Hetzner Online GmbH","isp":"Hetzner"},"timezone":{"id":"Europe/Berlin"}}"#;
        let v = Json::parse(body).unwrap();
        assert_eq!(field(&v, &["country"]).unwrap(), "Germany");
        assert_eq!(field(&v, &["org", "isp"]).unwrap(), "Hetzner Online GmbH");
        assert_eq!(field(&v, &["asn", "as"]).unwrap(), "24940");
    }

    #[test]
    fn parses_ip_api_shape() {
        let body = r#"{"status":"success","country":"Germany","countryCode":"DE","regionName":"Bavaria",
            "city":"Nuremberg","isp":"Hetzner Online GmbH","as":"AS24940 Hetzner","lat":49.45,"lon":11.07}"#;
        let v = Json::parse(body).unwrap();
        assert_eq!(field(&v, &["country_code", "countryCode"]).unwrap(), "DE");
        assert_eq!(field(&v, &["region", "regionName"]).unwrap(), "Bavaria");
        assert_eq!(field(&v, &["asn", "as"]).unwrap(), "AS24940 Hetzner");
    }

    #[test]
    fn disabled_when_url_empty() {
        let cfg = Config {
            geoip_url: String::new(),
            ..Default::default()
        };
        assert!(lookup(
            &cfg,
            std::path::Path::new("/etc/msfe-ng/config.toml"),
            "8.8.8.8"
        )
        .is_empty());
    }

    #[test]
    fn failure_responses_yield_nothing() {
        for body in [
            r#"{"success":false,"message":"reserved range"}"#,
            r#"{"status":"fail"}"#,
        ] {
            let v = Json::parse(body).unwrap();
            let failed = matches!(v.get("success"), Some(Json::Bool(false)))
                || v.get("status").and_then(Json::as_str) == Some("fail");
            assert!(failed);
        }
    }
}
