// SPDX-License-Identifier: LicenseRef-Propietario
//! RASTREO CON EVASIÓN — la "llave maestra" validada el 2026-08-24 contra unico: el
//! `params 0` / `crawl 0` no era falta de superficie, era que katana (binario externo,
//! sin nuestra evasión TLS) recibía 403 del WAF. Medido: `idcash-uat.unico.io` pasó de
//! 403 (curl normal) a 200 con 45 KB de app real vía curl-impersonate, y apareció el
//! `/.well-known/openid-configuration` que el crawler no vio.
//!
//! Este crawler usa `impersonate::fetch_evasion` (reqwest→curl-impersonate ante muro WAF),
//! baja el HTML/JS que katana no alcanza, y `js_extract` saca los endpoints de API. Además
//! sondea endpoints de DESCUBRIMIENTO (well-known/openid, swagger, api-docs) que revelan la
//! superficie de auth/API. Todo GET, no destructivo (estatuto nexus-detector).

/// Extrae valores de un atributo HTML (`src`, `href`, `action`) — comillas simples o
/// dobles. Puro y testeable. Simple a propósito: un enlace de más no hace daño (autz/las
/// fases lo filtran), y un parser HTML completo sería una dependencia por poco.
fn extraer_attr(html: &str, attr: &str) -> Vec<String> {
    let mut out = Vec::new();
    let needle = format!("{attr}=");
    let bytes = html.as_bytes();
    let mut i = 0;
    while let Some(pos) = html[i..].find(&needle) {
        let start = i + pos + needle.len();
        if start >= bytes.len() {
            break;
        }
        let q = bytes[start];
        if q == b'"' || q == b'\'' {
            if let Some(rel) = html[start + 1..].find(q as char) {
                let val = &html[start + 1..start + 1 + rel];
                if !val.is_empty() {
                    out.push(val.to_string());
                }
            }
        }
        i = start;
    }
    out
}

/// Los `src` de `<script>` que apuntan a un `.js` (los bundles a minar con js_extract).
pub fn extraer_scripts_js(html: &str) -> Vec<String> {
    extraer_attr(html, "src")
        .into_iter()
        .filter(|s| {
            let base = s.split(['?', '#']).next().unwrap_or(s).to_ascii_lowercase();
            base.ends_with(".js") || base.ends_with(".mjs")
        })
        .collect()
}

/// Los enlaces navegables del HTML (`href`/`action`) — para seguir el rastro. Filtra los
/// no-http (mailto:, javascript:, tel:, anclas puras).
pub fn extraer_enlaces(html: &str) -> Vec<String> {
    let mut v = extraer_attr(html, "href");
    v.extend(extraer_attr(html, "action"));
    v.into_iter()
        .filter(|s| {
            let l = s.to_ascii_lowercase();
            !l.starts_with("mailto:")
                && !l.starts_with("javascript:")
                && !l.starts_with("tel:")
                && !l.starts_with("data:")
                && !s.starts_with('#')
                && !s.trim().is_empty()
        })
        .collect()
}

/// Endpoints de DESCUBRIMIENTO: revelan la superficie de API/auth sin crawl. El
/// openid-configuration expone los endpoints del servidor de auth (token, jwks, authz);
/// swagger/openapi exponen TODA la API. Encontrar uno es abrir la puerta entera.
pub const ENDPOINTS_DESCUBRIMIENTO: &[&str] = &[
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/swagger.json",
    "/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/graphql",
    "/api/swagger.json",
];

/// ¿La respuesta a un endpoint de descubrimiento es REAL (no un catch-all de SPA)? Puro.
/// Un catch-all devuelve el mismo HTML del root; un descubrimiento real es JSON con la
/// forma esperada (issuer/paths/swagger/openapi/__schema).
pub fn es_descubrimiento_real(status: u16, body: &str, body_root: &str) -> bool {
    if !matches!(status, 200..=299) {
        return false;
    }
    // Catch-all: idéntico (o casi) al root → no es un endpoint real.
    if body == body_root {
        return false;
    }
    let b = body.to_ascii_lowercase();
    b.contains("\"issuer\"") // openid-configuration
        || b.contains("\"authorization_endpoint\"")
        || b.contains("\"swagger\"")
        || b.contains("\"openapi\"")
        || (b.contains("\"paths\"") && b.contains(':'))
        || b.contains("\"__schema\"") // GraphQL introspection
        || b.contains("\"data\"") && b.contains("\"__typename\"")
}

/// Resuelve una URL relativa contra la base del documento (reusa la lógica RFC de enhanced).
pub(crate) fn resolver(base: &str, rel: &str) -> String {
    crate::enhanced::resolver_endpoint(base, rel)
}

/// EL CRAWLER CON EVASIÓN: por cada host, baja el root (vía evasión, cruza WAF), extrae los
/// `.js` y los minifica con js_extract, sigue los enlaces mismo-host, y sondea los endpoints
/// de descubrimiento. Devuelve las URLs/endpoints descubiertos (absolutos), deduplicados —
/// el material que el `params 0` no tenía. Antibaneo por el `Guard`, respeta el deadline.
#[allow(clippy::too_many_arguments)]
pub async fn rastrear_con_evasion(
    cliente: &reqwest::Client,
    hosts: &[String],
    curl_impersonate_path: &str,
    max_hosts: usize,
    max_js_por_host: usize,
    guard: &mut crate::protection::Guard,
    deadline: Option<std::time::Instant>,
    mut rng: impl FnMut() -> f64,
) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut descubierto: BTreeSet<String> = BTreeSet::new();
    for host in hosts.iter().take(max_hosts) {
        if crate::autz::deadline_vencido(deadline) || guard.should_pause() {
            break;
        }
        let base = if host.starts_with("http") {
            host.trim_end_matches('/').to_string()
        } else {
            format!("https://{}", host.trim_end_matches('/'))
        };
        // 1) Root vía evasión (cruza el WAF que frena a katana).
        let root = crate::impersonate::fetch_evasion(cliente, &base, &[], curl_impersonate_path, 15).await;
        tokio::time::sleep(guard.cooldown(1, rng())).await;
        if matches!(root.status, 200..=299) && !root.body.is_empty() {
            // 2) Bundles JS → js_extract → endpoints de API.
            for js in extraer_scripts_js(&root.body).into_iter().take(max_js_por_host) {
                if crate::autz::deadline_vencido(deadline) {
                    break;
                }
                let js_url = resolver(&base, &js);
                let r = crate::impersonate::fetch_evasion(cliente, &js_url, &[], curl_impersonate_path, 15).await;
                tokio::time::sleep(guard.cooldown(1, rng())).await;
                if matches!(r.status, 200..=299) {
                    for ep in crate::js_extract::extraer_endpoints(&r.body) {
                        descubierto.insert(resolver(&base, &ep));
                    }
                }
            }
            // 3) Enlaces navegables mismo-host.
            let host_solo = crate::scope::host_of(&base);
            for enlace in extraer_enlaces(&root.body) {
                let abs = resolver(&base, &enlace);
                if crate::scope::host_of(&abs) == host_solo {
                    descubierto.insert(abs);
                }
            }
        }
        // 4) Endpoints de descubrimiento (well-known/swagger…), aunque el root no sea 2xx.
        for ep in ENDPOINTS_DESCUBRIMIENTO {
            if crate::autz::deadline_vencido(deadline) {
                break;
            }
            let url = format!("{base}{ep}");
            let r = crate::impersonate::fetch_evasion(cliente, &url, &[], curl_impersonate_path, 12).await;
            tokio::time::sleep(guard.cooldown(1, rng())).await;
            if es_descubrimiento_real(r.status, &r.body, &root.body) {
                descubierto.insert(url);
            }
        }
    }
    descubierto.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extrae_scripts_js_y_no_otros() {
        let html = r#"<script src="/assets/main.abc123.js"></script>
            <script src='https://cdn.x.com/vendor.js?v=2'></script>
            <link href="/style.css"><img src="/logo.png">
            <script src="/inline.mjs"></script>"#;
        let js = extraer_scripts_js(html);
        assert!(js.iter().any(|s| s == "/assets/main.abc123.js"));
        assert!(js.iter().any(|s| s.starts_with("https://cdn.x.com/vendor.js")));
        assert!(js.iter().any(|s| s == "/inline.mjs"));
        assert!(!js.iter().any(|s| s.ends_with(".css") || s.ends_with(".png")));
    }

    #[test]
    fn extrae_enlaces_y_filtra_no_http() {
        let html = r##"<a href="/login">L</a><a href="mailto:x@y.com">m</a>
            <form action="/api/submit">...<a href="javascript:void(0)">j</a>
            <a href="#top">t</a>"##;
        let e = extraer_enlaces(html);
        assert!(e.contains(&"/login".to_string()));
        assert!(e.contains(&"/api/submit".to_string()));
        assert!(!e.iter().any(|s| s.contains("mailto") || s.contains("javascript") || s == "#top"));
    }

    #[test]
    fn descubrimiento_real_discrimina_catchall() {
        let root = "<html><body>SPA shell</body></html>";
        // VERDE: openid-configuration real (JSON con issuer).
        assert!(es_descubrimiento_real(200, r#"{"issuer":"https://id.x.com","authorization_endpoint":"..."}"#, root));
        // VERDE: swagger real.
        assert!(es_descubrimiento_real(200, r#"{"swagger":"2.0","paths":{"/u":{}}}"#, root));
        // ROJO (pareja, dir. 33): catch-all de SPA — mismo cuerpo que el root → NO es real.
        assert!(!es_descubrimiento_real(200, root, root));
        // ROJO: 200 pero HTML cualquiera (no la forma esperada) → NO.
        assert!(!es_descubrimiento_real(200, "<html>otra pagina</html>", root));
        // ROJO: 404 → NO.
        assert!(!es_descubrimiento_real(404, r#"{"issuer":"x"}"#, root));
    }
}
