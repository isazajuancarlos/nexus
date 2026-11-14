// SPDX-License-Identifier: LicenseRef-Propietario
//! LLAVERO MAESTRO — fingerprint del TIPO DE CLIENTE y despacho de la estrategia de
//! extracción de superficie de API correcta. Principio (2026-08-24): el SERVIDOR esconde
//! su API; el CLIENTE la contiene entera — pero el artefacto-cliente varía (SPA JS,
//! Flutter compilado, API JSON pura, server clásico), y cada uno exige su llave. Esto es
//! bespoke elevado a arquitectura: fingerprint → método a medida, en vez de correr todas
//! las llaves a lo bruto (que en unico dio +0: crawler de JS sobre Flutter/API).
//!
//! Todo GET/lectura de artefactos, no destructivo (estatuto nexus-detector). El transporte
//! es `impersonate::fetch_evasion` (cruza WAF).

/// El tipo de cliente de un objetivo, que decide la estrategia de extracción.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipoCliente {
    /// SPA con bundles JS legibles (React/Vue/Angular/Next): las rutas están en el JS.
    SpaJs,
    /// App Flutter web: las rutas están en el `main.dart.js` compilado (extracción agresiva).
    Flutter,
    /// API JSON pura (sin HTML/JS): la superficie se descubre por wordlist de rutas / APK.
    ApiJson,
    /// Server-rendered clásico: enlaces y formularios en el HTML.
    ServerRendered,
    /// No determinado: se intenta SPA + sondeo de API como cascada.
    Desconocido,
}

/// FINGERPRINT del cliente a partir de la respuesta raíz (puro, testeable). Orden por
/// especificidad: Flutter (marcador único) → API JSON (content-type/forma) → SPA (bundles
/// + marcador de framework) → server clásico (HTML con formularios) → desconocido.
pub fn fingerprint_cliente(status: u16, content_type: &str, body: &str) -> TipoCliente {
    let ct = content_type.to_ascii_lowercase();
    let b = body.to_ascii_lowercase();
    let bt = body.trim_start();

    // Flutter: marcador inequívoco de su bootstrap.
    if b.contains("flutter.js") || b.contains("main.dart.js") || b.contains("flutter_bootstrap") || b.contains("_flutter.loader") {
        return TipoCliente::Flutter;
    }
    // API JSON pura: el content-type es JSON, o el cuerpo es JSON y no hay HTML.
    if ct.contains("application/json")
        || ((bt.starts_with('{') || bt.starts_with('[')) && !b.contains("<html") && !b.contains("<!doctype"))
    {
        return TipoCliente::ApiJson;
    }
    // SPA JS: hay bundle .js Y un marcador de framework/SPA.
    let tiene_bundle = b.contains(".js\"") || b.contains(".js'") || b.contains("/static/js/") || b.contains("/_next/") || b.contains("/assets/");
    let marcador_spa = b.contains("__next_data__")
        || b.contains("data-reactroot")
        || b.contains("ng-version")
        || b.contains("window.__nuxt__")
        || b.contains("id=\"root\"")
        || b.contains("id=\"app\"")
        || b.contains("__vue__");
    if tiene_bundle && marcador_spa {
        return TipoCliente::SpaJs;
    }
    // Server clásico: HTML con formularios o varios enlaces.
    if (b.contains("<html") || b.contains("<!doctype")) && (b.contains("<form") || b.matches("<a ").count() >= 2) {
        return TipoCliente::ServerRendered;
    }
    // Un HTML con bundles pero sin marcador claro: tratarlo como SPA (mejor extraer que no).
    if tiene_bundle && (b.contains("<html") || b.contains("<script")) {
        return TipoCliente::SpaJs;
    }
    let _ = status;
    TipoCliente::Desconocido
}

/// Wordlist curada de rutas de API comunes (el fallback para API JSON pura, estilo
/// kiterunner acotado). Se prueban vía evasión; `es_descubrimiento_real`/no-catch-all
/// discrimina las que existen.
pub const RUTAS_API_COMUNES: &[&str] = &[
    "/api", "/api/v1", "/api/v2", "/v1", "/v2", "/v3", "/rest", "/rest/v1", "/rest/v2",
    "/graphql", "/query", "/api/graphql",
    "/api/health", "/health", "/healthz", "/status", "/ping", "/version", "/api/version",
    "/api/users", "/api/v1/users", "/api/user", "/api/me", "/api/account", "/api/accounts",
    "/api/auth", "/api/login", "/api/token", "/oauth/token", "/auth/token",
    "/api/v1/auth", "/api/config", "/api/settings",
    "/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs", "/api-docs",
    "/.well-known/openid-configuration", "/actuator", "/actuator/health", "/metrics",
];

/// Extrae endpoints (URLs absolutas y rutas de API) de un TEXTO cualquiera — para minar
/// un JS compilado de Flutter (agresivo) o la salida DECOMPILADA de un APK (jadx). Puro.
/// Más permisivo que `js_extract`: capta cualquier URL http(s) y cualquier `/segmento/...`
/// con pinta de ruta. Deduplica.
pub fn extraer_endpoints_texto(texto: &str) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut out: BTreeSet<String> = BTreeSet::new();
    let bytes = texto.as_bytes();
    let n = bytes.len();
    // 1) URLs absolutas https?://... hasta un delimitador.
    for pat in ["https://", "http://"] {
        let mut i = 0;
        while let Some(pos) = texto[i..].find(pat) {
            let start = i + pos;
            let mut end = start + pat.len();
            while end < n {
                let c = bytes[end];
                // Fin de URL: comillas, espacios, paréntesis, backtick, coma, angulares.
                if c == b'"' || c == b'\'' || c == b'`' || c == b' ' || c == b'\n' || c == b'\r'
                    || c == b'\t' || c == b'<' || c == b'>' || c == b')' || c == b'(' || c == b',' || c == b'\\' {
                    break;
                }
                end += 1;
            }
            let u = &texto[start..end];
            // URL sana y con host (evita "https://" suelto).
            if u.len() > pat.len() + 3 && u.len() <= 300 && !u.contains("..") {
                out.insert(u.trim_end_matches(['/', '.', ';']).to_string());
            }
            i = start + pat.len();
        }
    }
    // 2) Rutas de API entre comillas: "/api/...", "/v1/...", "/oauth/...", etc.
    for q in ['"', '\''] {
        let mut i = 0;
        while let Some(pos) = texto[i..].find(q) {
            let s = i + pos + 1;
            if let Some(rel) = texto[s..].find(q) {
                let val = &texto[s..s + rel];
                if es_ruta_api_amplia(val) {
                    out.insert(val.to_string());
                }
                i = s + rel + 1;
            } else {
                break;
            }
        }
    }
    out.into_iter().collect()
}

/// ¿La cadena parece una ruta de API? (amplia, para Flutter/APK). Empieza por `/`, tiene
/// al menos un segmento, sin espacios, longitud sana, y casa un prefijo típico o `/vN/`.
fn es_ruta_api_amplia(s: &str) -> bool {
    if !s.starts_with('/') || s.len() < 3 || s.len() > 200 || s.contains(' ') || s.contains("//") {
        return false;
    }
    // Solo caracteres de ruta.
    if !s.bytes().all(|c| c.is_ascii_alphanumeric() || b"/_-.{}:?=&".contains(&c)) {
        return false;
    }
    let l = s.to_ascii_lowercase();
    let prefijos = ["/api", "/v1", "/v2", "/v3", "/rest", "/oauth", "/auth", "/graphql", "/users", "/account", "/token", "/login", "/services", "/internal"];
    prefijos.iter().any(|p| l.starts_with(p)) || l.contains("/api/")
}

/// EL DESPACHADOR: fingerprintea el host y aplica la estrategia de extracción correcta.
/// Devuelve el tipo detectado y los endpoints/URLs descubiertos (absolutos, deduplicados).
/// Reusa el crawler de JS (rastreo) para SPA, el extractor agresivo para Flutter, y la
/// wordlist para API pura. Antibaneo por el `Guard`.
#[allow(clippy::too_many_arguments)]
pub async fn despachar(
    cliente: &reqwest::Client,
    host: &str,
    curl_impersonate_path: &str,
    max_js: usize,
    guard: &mut crate::protection::Guard,
    deadline: Option<std::time::Instant>,
    mut rng: impl FnMut() -> f64,
) -> (TipoCliente, Vec<String>) {
    use std::collections::BTreeSet;
    let base = if host.starts_with("http") {
        host.trim_end_matches('/').to_string()
    } else {
        format!("https://{}", host.trim_end_matches('/'))
    };
    let root = crate::impersonate::fetch_evasion(cliente, &base, &[], curl_impersonate_path, 15).await;
    tokio::time::sleep(guard.cooldown(1, rng())).await;
    // El content-type no lo trae `Respuesta`; se infiere del cuerpo (fingerprint tolerante).
    let tipo = fingerprint_cliente(root.status, "", &root.body);
    let mut endpoints: BTreeSet<String> = BTreeSet::new();
    let resolver = |rel: &str| crate::enhanced::resolver_endpoint(&base, rel);

    match tipo {
        TipoCliente::SpaJs | TipoCliente::Flutter => {
            // Bajar los bundles JS y extraer. Flutter usa el extractor AGRESIVO (Dart
            // compilado); SPA usa js_extract (rutas limpias) + el agresivo como respaldo.
            for js in crate::rastreo::extraer_scripts_js(&root.body).into_iter().take(max_js) {
                if crate::autz::deadline_vencido(deadline) {
                    break;
                }
                let r = crate::impersonate::fetch_evasion(cliente, &resolver(&js), &[], curl_impersonate_path, 20).await;
                tokio::time::sleep(guard.cooldown(1, rng())).await;
                if matches!(r.status, 200..=299) {
                    let eps = if tipo == TipoCliente::Flutter {
                        extraer_endpoints_texto(&r.body)
                    } else {
                        let mut e = crate::js_extract::extraer_endpoints(&r.body);
                        e.extend(extraer_endpoints_texto(&r.body));
                        e
                    };
                    for ep in eps {
                        endpoints.insert(resolver(&ep));
                    }
                }
            }
        }
        TipoCliente::ServerRendered => {
            for enlace in crate::rastreo::extraer_enlaces(&root.body) {
                endpoints.insert(resolver(&enlace));
            }
        }
        TipoCliente::ApiJson | TipoCliente::Desconocido => {
            // API pura (o incierto): sondear la wordlist de rutas vía evasión.
            for ruta in RUTAS_API_COMUNES {
                if crate::autz::deadline_vencido(deadline) {
                    break;
                }
                let url = format!("{base}{ruta}");
                let r = crate::impersonate::fetch_evasion(cliente, &url, &[], curl_impersonate_path, 12).await;
                tokio::time::sleep(guard.cooldown(1, rng())).await;
                // Endpoint real: descubrimiento con forma, o un 401/403/200 que NO es el
                // catch-all del root (una API viva responde distinto del root a sus rutas).
                let real = crate::rastreo::es_descubrimiento_real(r.status, &r.body, &root.body)
                    || (matches!(r.status, 200 | 401 | 403 | 405 | 500) && r.body != root.body && !r.body.is_empty());
                if real {
                    endpoints.insert(url);
                }
            }
        }
    }
    (tipo, endpoints.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_distingue_los_tipos() {
        // Flutter.
        assert_eq!(fingerprint_cliente(200, "text/html", r#"<script src="flutter.js"></script><script src="main.dart.js">"#), TipoCliente::Flutter);
        // API JSON (por content-type).
        assert_eq!(fingerprint_cliente(200, "application/json; charset=utf-8", r#"{"error":"not found"}"#), TipoCliente::ApiJson);
        // API JSON (por forma, sin content-type).
        assert_eq!(fingerprint_cliente(200, "", r#"{"data":[]}"#), TipoCliente::ApiJson);
        // SPA React.
        assert_eq!(fingerprint_cliente(200, "text/html", r#"<html><body><div id="root"></div><script src="/static/js/main.js"></script></body></html>"#), TipoCliente::SpaJs);
        // Server clásico.
        assert_eq!(fingerprint_cliente(200, "text/html", r#"<html><body><form action="/login"><a href="/x">x</a><a href="/y">y</a></form></body></html>"#), TipoCliente::ServerRendered);
        // Desconocido.
        assert_eq!(fingerprint_cliente(200, "text/plain", "hola"), TipoCliente::Desconocido);
    }

    #[test]
    fn extraer_endpoints_texto_saca_urls_y_rutas() {
        // Simula JS de Flutter/APK compilado con endpoints embebidos.
        let dart = r#"...const _url="https://api.idcloud.uat.unico.app/v1/authenticate";
            var p='/api/v2/users/current';x("/oauth/token");noEs("hola mundo");y("/static/x.png")"#;
        let e = extraer_endpoints_texto(dart);
        assert!(e.iter().any(|u| u == "https://api.idcloud.uat.unico.app/v1/authenticate"));
        assert!(e.iter().any(|u| u == "/api/v2/users/current"));
        assert!(e.iter().any(|u| u == "/oauth/token"));
        // NO debe capturar texto normal ni assets no-API.
        assert!(!e.iter().any(|u| u.contains("hola")));
        assert!(!e.iter().any(|u| u.ends_with(".png")));
    }

    #[test]
    fn ruta_api_amplia_discrimina() {
        assert!(es_ruta_api_amplia("/api/v1/users"));
        assert!(es_ruta_api_amplia("/oauth/token"));
        assert!(es_ruta_api_amplia("/v2/accounts/123"));
        // ROJO (pareja): no-rutas.
        assert!(!es_ruta_api_amplia("hola"));
        assert!(!es_ruta_api_amplia("/con espacio"));
        assert!(!es_ruta_api_amplia("/style.css/foo")); // no casa prefijo API
        assert!(!es_ruta_api_amplia("//cdn.x.com"));
    }
}
