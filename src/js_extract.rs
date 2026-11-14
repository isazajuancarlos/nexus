// SPDX-License-Identifier: LicenseRef-Propietario
//! Extracción de ENDPOINTS de JavaScript (fase 2.1). Rust-nativo, sin dependencia
//! externa nueva (el protocolo solo-local prefiere deps mínimas; `jsluice` sería
//! un binario Go más en producción).
//!
//! Los endpoints extraídos alimentan el corpus de recon y `autz_semillas` — más
//! superficie para el foso de control de acceso. Los SECRETOS en JS NO se manejan
//! aquí: ya los cubre la fase 0.1 (`secretos::detectar` dentro de
//! `verify::content_check`) cuando el `.js` se toca como exposición.
//!
//! El estado del arte dice «parser > regex» para bajar FP; aquí un FP es barato
//! (un endpoint de más que autz simplemente no marca), así que el escaneo por
//! patrón es suficiente y no arrastra un parser.

use std::collections::BTreeSet;

/// Extrae endpoints de un cuerpo JS: URLs absolutas y rutas de API entre comillas.
/// Ordenado y sin duplicados. Puro y testable.
pub fn extraer_endpoints(js: &str) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    // 1) URLs absolutas.
    for p in ["https://", "http://"] {
        for u in urls_con_prefijo(js, p) {
            out.insert(u);
        }
    }
    // 2) Rutas de API entre comillas ("/api/…", "/v1/…", …).
    for comilla in ['"', '\'', '`'] {
        for s in cadenas_entre(js, comilla) {
            if es_ruta_api(&s) {
                out.insert(s);
            }
        }
    }
    out.into_iter().collect()
}

fn es_char_url(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-._~:/?#[]@!$&'()*+,;=%".contains(c)
}

fn urls_con_prefijo(js: &str, prefijo: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = js.as_bytes();
    let mut i = 0;
    while let Some(pos) = js[i..].find(prefijo) {
        let inicio = i + pos;
        let mut j = inicio + prefijo.len();
        while j < bytes.len() && es_char_url(bytes[j] as char) {
            j += 1;
        }
        let u = js[inicio..j].trim_end_matches(['.', ',', ')', '"', '\'']).to_string();
        if u.len() > prefijo.len() + 3 {
            out.push(u);
        }
        i = (inicio + prefijo.len()).max(i + pos + 1);
    }
    out
}

/// Extrae las cadenas literales delimitadas por `comilla` (sin manejar escapes
/// complejos: basta para pescar rutas). Corta a 512 chars para no capturar blobs.
fn cadenas_entre(js: &str, comilla: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut dentro = false;
    let mut actual = String::new();
    for c in js.chars() {
        if c == comilla {
            if dentro {
                if !actual.is_empty() {
                    out.push(std::mem::take(&mut actual));
                }
                dentro = false;
            } else {
                dentro = true;
                actual.clear();
            }
        } else if dentro {
            if c == '\n' || actual.len() >= 512 {
                dentro = false;
                actual.clear();
            } else {
                actual.push(c);
            }
        }
    }
    out
}

/// ¿La cadena parece una ruta de API? Empieza por `/`, longitud razonable, charset
/// de ruta, y NO es un asset estático (`.js/.css/.png/…`) ni una ruta trivial.
fn es_ruta_api(s: &str) -> bool {
    if !s.starts_with('/') || s.len() < 4 || s.starts_with("//") {
        return false;
    }
    // Solo charset de ruta URL (descarta cadenas con espacios, `${}`, etc.).
    if !s.chars().all(es_char_url) {
        return false;
    }
    let base = s.split(['?', '#']).next().unwrap_or(s);
    const ASSETS: &[&str] = &[
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
        ".woff2", ".ttf", ".map", ".webp", ".mp4", ".pdf",
    ];
    if ASSETS.iter().any(|e| base.to_ascii_lowercase().ends_with(e)) {
        return false;
    }
    // Debe tener al menos un segmento con letra (evita `/1234`, `/////`).
    base.split('/').any(|seg| seg.chars().any(|c| c.is_ascii_alphabetic()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extrae_urls_y_rutas_api() {
        let js = r#"
            const API = "https://api.acme.com/v2/users";
            fetch('/api/v1/orders/' + id);
            axios.get(`/internal/config`);
            const img = "/assets/logo.png";   // asset → NO
            const x = "/";                      // trivial → NO
            const css = "/styles/main.css";     // asset → NO
        "#;
        let e = extraer_endpoints(js);
        assert!(e.iter().any(|u| u == "https://api.acme.com/v2/users"));
        assert!(e.iter().any(|u| u == "/api/v1/orders/"));
        assert!(e.iter().any(|u| u == "/internal/config"));
        // PAREJA: assets estáticos y rutas triviales NO se extraen.
        assert!(!e.iter().any(|u| u == "/assets/logo.png"));
        assert!(!e.iter().any(|u| u == "/styles/main.css"));
        assert!(!e.iter().any(|u| u == "/"));
    }

    #[test]
    fn descarta_ruido() {
        // Sin rutas: texto suelto, no cadenas con espacios.
        let e = extraer_endpoints("let mensaje = 'hola mundo con espacios';");
        assert!(e.is_empty());
        // `//comentario` no es ruta.
        assert!(extraer_endpoints("// https-like //foo/bar").iter().all(|u| !u.starts_with("//")));
    }
}
