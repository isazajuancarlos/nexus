// SPDX-License-Identifier: LicenseRef-Propietario
//! EVASIÓN DE FRONTERA por impersonación TLS/HTTP2 de navegador (curl-impersonate).
//!
//! El muro medido el 2026-08-24: Akamai Bot Manager (y muchos WAFs) bloquean por el
//! FINGERPRINT TLS/JA3 + HTTP2 del cliente. reqwest/rustls tiene una firma distinta a
//! la de Chrome → 403 "Access Denied" en el borde, ANTES de evaluar la auth. Medido:
//! `curl` normal (OpenSSL) → 403 Akamai en `www.drogas.lv`; `curl-impersonate` (TLS de
//! Chrome) → 301, la petición LLEGA AL ORIGEN. Con token, pasó de 403-Akamai a
//! 401-`invalid_token` de la app: la frontera se cruza, el WAF ya no ve un bot.
//!
//! Es evasión LEGÍTIMA de sombrero gris: se dispara solo dentro del scope autorizado de
//! un programa de bug bounty (que nos invitó y paga). No inyecta nada; solo hace que
//! nuestro TLS se vea como un navegador de verdad, que es lo que la app espera.
//!
//! No es dependencia de código (directiva 9): curl-impersonate es un binario externo,
//! como subfinder/httpx/nuclei. Se invoca por su ruta (`NEXUS_CURL_IMPERSONATE`).

use crate::error::{NexusError, Result};
use std::time::Duration;

/// La respuesta de una petición impersonada.
#[derive(Debug, Clone)]
pub struct Respuesta {
    pub status: u16,
    pub body: String,
}

/// ¿La respuesta es un MURO de WAF (bloqueo del cliente, no de la app)? Puro y
/// testeable. Distingue "el WAF te bloqueó a TI" (Akamai/Cloudflare edge) de una
/// respuesta legítima de la app (incluido un 401/403 de autorización real).
pub fn es_muro_waf(status: u16, body: &str) -> bool {
    let b = body.to_ascii_lowercase();
    // Firmas de bloqueo de borde (el cliente fue vetado, no el recurso).
    b.contains("access denied") && b.contains("edgesuite") // Akamai
        || b.contains("errors.edgesuite.net")
        || b.contains("attention required") && b.contains("cloudflare") // Cloudflare challenge
        || b.contains("just a moment") && b.contains("challenge-platform") // CF JS challenge
        || b.contains("请开启javascript") // algunos WAFs asiáticos
        || (status == 403 && b.contains("reference #") && b.contains("edgesuite"))
}

/// Construye los args de curl-impersonate para un GET con cabeceras. Puro (testeable):
/// separa la construcción del comando de su ejecución.
pub fn build_args(url: &str, headers: &[(String, String)], timeout_secs: u64) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "-s".into(),
        "-o".into(),
        "-".into(), // el cuerpo va a stdout
        "-w".into(),
        "\n%{http_code}".into(), // el status, en la ÚLTIMA línea, tras el cuerpo
        "--max-time".into(),
        timeout_secs.to_string(),
    ];
    for (k, v) in headers {
        args.push("-H".into());
        args.push(format!("{k}: {v}"));
    }
    args.push(url.to_string());
    args
}

/// Separa el cuerpo del status en la salida de curl-impersonate (que pusimos como
/// `<cuerpo>\n<status>`). Puro. El status es SIEMPRE la última línea (`-w \n%{http_code}`).
pub fn parse_salida(salida: &str) -> Option<Respuesta> {
    let (body, code) = salida.rsplit_once('\n')?;
    let status: u16 = code.trim().parse().ok()?;
    Some(Respuesta { status, body: body.to_string() })
}

/// Hace un GET impersonado (TLS/HTTP2 de Chrome) por curl-impersonate. Cruza la
/// frontera de WAFs que bloquean por fingerprint. `None`/Err si la herramienta falla.
pub async fn fetch(
    curl_impersonate_path: &str,
    url: &str,
    headers: &[(String, String)],
    timeout_secs: u64,
) -> Result<Respuesta> {
    let args = build_args(url, headers, timeout_secs);
    let out = crate::tools::run(
        curl_impersonate_path,
        &args,
        Duration::from_secs(timeout_secs + 5),
    )
    .await?;
    let n = out.stdout.len();
    parse_salida(&out.stdout)
        .ok_or_else(|| NexusError::Other(format!("curl-impersonate: salida ilegible ({n} bytes)")))
}

/// ¿Hay que REINTENTAR con evasión TLS? Puro: sí solo si la respuesta es un muro de WAF
/// Y tenemos curl-impersonate configurado. Separa la decisión (testeable) del efecto.
pub fn debe_evadir(status: u16, body: &str, impersonate_configurado: bool) -> bool {
    impersonate_configurado && es_muro_waf(status, body)
}

/// TRANSPORTE DE EVASIÓN: hace el GET por reqwest (rápido); si topa un muro de WAF y hay
/// curl-impersonate configurado, REINTENTA impersonado (TLS de navegador) — que cruza el
/// bloqueo por fingerprint. Los objetivos normales usan reqwest; solo los amurallados
/// pagan el reintento. Une el camino y por fin USA `impersonate.rs`.
pub async fn fetch_evasion(
    cliente: &reqwest::Client,
    url: &str,
    headers: &[(String, String)],
    curl_impersonate_path: &str,
    timeout_secs: u64,
) -> Respuesta {
    // 1) Intento normal por reqwest.
    let mut req = cliente.get(url);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let (status, body) = match req.send().await {
        Ok(r) => {
            let s = r.status().as_u16();
            (s, r.text().await.unwrap_or_default())
        }
        Err(_) => (0, String::new()),
    };
    // 2) Si es muro y hay evasión, reintentar impersonado.
    if debe_evadir(status, &body, !curl_impersonate_path.is_empty()) {
        if let Ok(r) = fetch(curl_impersonate_path, url, headers, timeout_secs).await {
            return r;
        }
    }
    Respuesta { status, body }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debe_evadir_solo_ante_muro_y_con_impersonate() {
        // Muro Akamai + impersonate configurado → reintentar.
        assert!(debe_evadir(403, "Access Denied ... errors.edgesuite.net", true));
        // Muro pero SIN impersonate → no se puede evadir.
        assert!(!debe_evadir(403, "errors.edgesuite.net", false));
        // No es muro (401 de auth real) → no reintentar aunque haya impersonate.
        assert!(!debe_evadir(401, "{\"error\":\"invalid_token\"}", true));
        // 200 normal → no.
        assert!(!debe_evadir(200, "<html>ok</html>", true));
    }

    #[test]
    fn es_muro_waf_discrimina() {
        // ROJO: bloqueo Akamai de borde (el cliente vetado).
        assert!(es_muro_waf(403, "<HTML><H1>Access Denied</H1> ... errors.edgesuite.net ...</HTML>"));
        // ROJO: challenge de Cloudflare.
        assert!(es_muro_waf(403, "<title>Attention Required! | Cloudflare</title>"));
        assert!(es_muro_waf(503, "Just a moment... challenge-platform"));
        // VERDE (pareja, dir. 33): un 401 de AUTORIZACIÓN real de la app NO es muro WAF.
        assert!(!es_muro_waf(401, "{\"error\":\"invalid_token\",\"error_description\":\"Invalid access token\"}"));
        // VERDE: un 403 de recurso protegido (sin firma de borde) NO es muro de cliente.
        assert!(!es_muro_waf(403, "{\"message\":\"Full authentication is required\"}"));
        // VERDE: una respuesta 200 normal.
        assert!(!es_muro_waf(200, "<html><body>tienda</body></html>"));
    }

    #[test]
    fn parse_salida_separa_cuerpo_y_status() {
        let r = parse_salida("{\"ok\":true}\n200").unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, "{\"ok\":true}");
        // Cuerpo con saltos internos: el status sigue siendo la ÚLTIMA línea.
        let r2 = parse_salida("linea1\nlinea2\n404").unwrap();
        assert_eq!(r2.status, 404);
        assert_eq!(r2.body, "linea1\nlinea2");
        // Salida basura sin status numérico → None.
        assert!(parse_salida("sin status").is_none());
    }

    #[test]
    fn build_args_pone_status_al_final_y_cabeceras() {
        let a = build_args("https://x.com/", &[("Authorization".into(), "Bearer t".into())], 15);
        assert!(a.contains(&"https://x.com/".to_string()));
        assert!(a.windows(2).any(|w| w[0] == "-H" && w[1] == "Authorization: Bearer t"));
        assert!(a.windows(2).any(|w| w[0] == "-w" && w[1] == "\n%{http_code}"));
    }
}
