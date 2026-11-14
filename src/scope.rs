//! Validación de scope: ¿está esta URL dentro del alcance permitido? Portado de
//! `scope.py` (wildcard + CIDR). Es también una salvaguarda anti-baneo indirecta:
//! no escanear fuera de scope evita golpear a quien no debe.

use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub enum ScopeRule {
    /// Dominio exacto.
    Domain(String),
    /// Comodín: `*.example.com` cubre example.com y cualquier subdominio.
    Wildcard(String),
    /// Rango CIDR.
    Cidr(IpNet),
}

impl ScopeRule {
    pub fn parse(identifier: &str, is_wildcard: bool) -> Option<Self> {
        if is_wildcard || identifier.starts_with("*.") {
            let base = identifier.trim_start_matches("*.").to_string();
            return Some(ScopeRule::Wildcard(base));
        }
        if let Ok(net) = IpNet::from_str(identifier) {
            return Some(ScopeRule::Cidr(net));
        }
        if identifier.contains('.') {
            return Some(ScopeRule::Domain(identifier.to_lowercase()));
        }
        None
    }

    /// ¿El host (dominio o IP) casa con esta regla?
    pub fn matches(&self, host: &str) -> bool {
        let host = host.to_lowercase();
        match self {
            ScopeRule::Domain(d) => &host == d,
            ScopeRule::Wildcard(base) => host == *base || host.ends_with(&format!(".{base}")),
            ScopeRule::Cidr(net) => IpAddr::from_str(&host).map(|ip| net.contains(&ip)).unwrap_or(false),
        }
    }
}

/// Extrae el host de una URL (sin esquema, sin puerto, sin path).
pub fn host_of(url: &str) -> String {
    let s = url.split("://").last().unwrap_or(url);
    let s = s.split('/').next().unwrap_or(s);
    s.split(':').next().unwrap_or(s).to_lowercase()
}

/// ¿La URL está en scope según CUALQUIERA de las reglas?
pub fn in_scope(url: &str, rules: &[ScopeRule]) -> bool {
    let host = host_of(url);
    rules.iter().any(|r| r.matches(&host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_cubre_subdominios_y_base() {
        let r = ScopeRule::parse("*.example.com", true).unwrap();
        assert!(r.matches("api.example.com"));
        assert!(r.matches("example.com"));
        assert!(!r.matches("notexample.com"));
        assert!(!r.matches("example.com.evil.com"));
    }

    #[test]
    fn dominio_exacto() {
        let r = ScopeRule::parse("example.com", false).unwrap();
        assert!(r.matches("example.com"));
        assert!(!r.matches("sub.example.com"));
    }

    #[test]
    fn cidr() {
        let r = ScopeRule::parse("10.0.0.0/8", false).unwrap();
        assert!(r.matches("10.1.2.3"));
        assert!(!r.matches("11.0.0.1"));
    }

    #[test]
    fn host_de_url() {
        assert_eq!(host_of("https://api.example.com:443/path?q=1"), "api.example.com");
    }

    #[test]
    fn in_scope_combinado() {
        let rules = vec![
            ScopeRule::parse("*.example.com", true).unwrap(),
            ScopeRule::parse("10.0.0.0/8", false).unwrap(),
        ];
        assert!(in_scope("https://x.example.com/a", &rules));
        assert!(in_scope("http://10.2.3.4", &rules));
        assert!(!in_scope("https://evil.com", &rules));
    }
}
