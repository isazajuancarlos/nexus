// SPDX-License-Identifier: LicenseRef-Propietario
//! Add-on "datos en tránsito": audita CABECERAS de seguridad, flags de COOKIES y
//! el forzado de HTTPS/HSTS. Todo con reqwest — SIN deps nuevas (el protocolo
//! solo-local exige mínimas dependencias). Cada hallazgo aterriza en la Ley 1581
//! (Art. 4 g seguridad / 4 h confidencialidad) y alimenta el dictamen (§4/§6).
//!
//! NO cubre (necesitaría dep nueva o `openssl s_client`, decisión aparte de Juan):
//! versiones de protocolo TLS, suites de cifrado y expiración/validez del
//! certificado. Lo que sí se comprueba sin deps es lo que más pesa en un dictamen
//! de protección de datos: que el canal sea HTTPS forzado y que la sesión no viaje
//! robable.

use std::collections::BTreeMap;

/// Un hallazgo de cabeceras/cookies/HTTPS, listo para persistir.
pub struct Hallazgo {
    pub vuln_name: &'static str,
    pub severity: &'static str,
    pub detalle: String,
}

fn tiene(headers: &BTreeMap<String, String>, nombre: &str) -> bool {
    headers.contains_key(nombre)
}

/// Evalúa las cabeceras de UNA respuesta. PURO. `headers`: nombres en MINÚSCULAS.
/// `es_https`: si la URL era https (HSTS solo aplica ahí).
pub fn evaluar_cabeceras(headers: &BTreeMap<String, String>, es_https: bool) -> Vec<Hallazgo> {
    let mut out = Vec::new();
    if es_https && !tiene(headers, "strict-transport-security") {
        out.push(Hallazgo {
            vuln_name: "tls-hsts-missing",
            severity: "medium",
            detalle: "respuesta HTTPS sin Strict-Transport-Security: permite downgrade a HTTP y ataques MITM sobre datos en tránsito".into(),
        });
    }
    if !tiene(headers, "content-security-policy") {
        out.push(Hallazgo {
            vuln_name: "header-csp-missing",
            severity: "low",
            detalle: "sin Content-Security-Policy: mayor superficie de XSS/inyección".into(),
        });
    }
    if headers.get("x-content-type-options").map(|v| v.to_ascii_lowercase()) != Some("nosniff".into()) {
        out.push(Hallazgo {
            vuln_name: "header-xcto-missing",
            severity: "low",
            detalle: "sin X-Content-Type-Options: nosniff: el navegador puede interpretar mal el tipo de contenido".into(),
        });
    }
    let sin_xfo = !tiene(headers, "x-frame-options");
    let csp_sin_frame = headers
        .get("content-security-policy")
        .map(|v| !v.to_ascii_lowercase().contains("frame-ancestors"))
        .unwrap_or(true);
    if sin_xfo && csp_sin_frame {
        out.push(Hallazgo {
            vuln_name: "header-clickjacking",
            severity: "low",
            detalle: "sin X-Frame-Options ni CSP frame-ancestors: riesgo de clickjacking".into(),
        });
    }
    if !tiene(headers, "referrer-policy") {
        out.push(Hallazgo {
            vuln_name: "header-referrer-missing",
            severity: "info",
            detalle: "sin Referrer-Policy: puede filtrar URLs con datos por el encabezado Referer".into(),
        });
    }
    // Divulgación de versión (Server / X-Powered-By con dígitos = versión).
    for h in ["server", "x-powered-by"] {
        if let Some(v) = headers.get(h) {
            if v.chars().any(|c| c.is_ascii_digit()) {
                out.push(Hallazgo {
                    vuln_name: "version-banner-expuesto",
                    severity: "info",
                    detalle: format!("cabecera '{h}: {v}' divulga versión del software: facilita el ataque dirigido"),
                });
                break; // una por respuesta basta
            }
        }
    }
    out
}

/// Evalúa los valores `Set-Cookie` de UNA respuesta. PURO. `es_https`: el canal.
/// Una cookie de sesión sin Secure/HttpOnly es la vía directa al robo de sesión =
/// acceso no autorizado a datos del titular (Art. 4 g/h + 17 d).
pub fn evaluar_cookies(set_cookies: &[String], es_https: bool) -> Vec<Hallazgo> {
    let mut out = Vec::new();
    let (mut sin_secure, mut sin_httponly, mut sin_samesite) = (false, false, false);
    for c in set_cookies {
        let l = c.to_ascii_lowercase();
        if es_https && !l.contains("secure") {
            sin_secure = true;
        }
        if !l.contains("httponly") {
            sin_httponly = true;
        }
        if !l.contains("samesite") {
            sin_samesite = true;
        }
    }
    if sin_secure {
        out.push(Hallazgo {
            vuln_name: "cookie-sin-secure",
            // low, no high (revisión 2026-08-23): la falta del flag Secure es
            // informativa en casi todo programa; marcarla HIGH tienta un envío que
            // vuelve como Informative y quema Signal.
            severity: "low",
            detalle: "cookie servida por HTTPS sin el flag Secure: puede viajar por HTTP en claro y ser interceptada".into(),
        });
    }
    if sin_httponly {
        out.push(Hallazgo {
            vuln_name: "cookie-sin-httponly",
            severity: "medium",
            detalle: "cookie sin HttpOnly: accesible a JavaScript, robable vía XSS (secuestro de sesión)".into(),
        });
    }
    if sin_samesite {
        out.push(Hallazgo {
            vuln_name: "cookie-sin-samesite",
            severity: "low",
            detalle: "cookie sin SameSite: expuesta a CSRF".into(),
        });
    }
    out
}

/// La fase: para cada HOST vivo del corpus (deduplicado, acotado), una petición
/// HTTPS para evaluar cabeceras/cookies, y una HTTP (sin seguir redirecciones)
/// para comprobar que se fuerza el upgrade a HTTPS. Persiste los hallazgos con
/// evidencia. Ligera: 2 GET por host, sin ofensiva.
pub async fn fase_cabeceras(
    pool: &sqlx::SqlitePool,
    program: &str,
    corpus: &[String],
    user_agent: &str,
    max: usize,
    deadline: Option<std::time::Instant>,
) -> crate::error::Result<u64> {
    let https = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(12))
        .user_agent(user_agent)
        .build()?;
    // Cliente que NO sigue redirecciones: para VER el 301/302 del upgrade.
    let sin_redir = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(12))
        .user_agent(user_agent)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let program_id = crate::db::upsert_program(pool, program).await?;
    let mut nuevas = 0u64;
    let mut hosts_vistos: Vec<String> = Vec::new();

    for url in corpus {
        if hosts_vistos.len() >= max {
            break;
        }
        if crate::autz::deadline_vencido(deadline) {
            tracing::info!("cabeceras: presupuesto del ciclo agotado — paro ({nuevas} nuevos)");
            break;
        }
        let host = crate::scope::host_of(url);
        if host.is_empty() || hosts_vistos.contains(&host) {
            continue;
        }
        hosts_vistos.push(host.clone());

        let objetivo = format!("https://{host}/");
        let Ok(resp) = https.get(&objetivo).send().await else {
            continue;
        };
        // Cabeceras en minúsculas + Set-Cookie por separado.
        let mut headers: BTreeMap<String, String> = BTreeMap::new();
        let mut cookies: Vec<String> = Vec::new();
        for (k, v) in resp.headers().iter() {
            let nombre = k.as_str().to_ascii_lowercase();
            let valor = v.to_str().unwrap_or("").to_string();
            if nombre == "set-cookie" {
                cookies.push(valor);
            } else {
                headers.insert(nombre, valor);
            }
        }

        let mut hallazgos = evaluar_cabeceras(&headers, true);
        hallazgos.extend(evaluar_cookies(&cookies, true));

        // Forzado de HTTPS: si http:// responde 2xx sin redirigir a https, los
        // datos pueden viajar en claro.
        if let Ok(r) = sin_redir.get(format!("http://{host}/")).send().await {
            let status = r.status().as_u16();
            let ubica = r
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let redirige_https = (300..400).contains(&status) && ubica.to_ascii_lowercase().starts_with("https://");
            if (200..300).contains(&status) || ((300..400).contains(&status) && !redirige_https) {
                hallazgos.push(Hallazgo {
                    vuln_name: "tls-no-https-redirect",
                    // low, no high (revisión 2026-08-23): mismo motivo que cookie-sin-secure.
                    severity: "low",
                    detalle: format!("http://{host}/ no fuerza HTTPS (status {status}): datos personales pueden viajar en claro"),
                });
            }
        }

        for h in hallazgos {
            let nf = crate::db::NewFinding {
                program_name: program.to_string(),
                vuln_name: h.vuln_name.to_string(),
                severity: h.severity.to_string(),
                url: objetivo.clone(),
                cwe: None,
                evidencia: Some(h.detalle),
            };
            if crate::db::insert_finding_dedup(pool, &nf, program_id).await? {
                nuevas += 1;
            }
        }
    }
    Ok(nuevas)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdrs(pares: &[(&str, &str)]) -> BTreeMap<String, String> {
        pares.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    // Caso ROJO (todo ausente) vs control (todo presente): la sonda discrimina.
    #[test]
    fn cabeceras_rojo_marca_control_calla() {
        // ROJO: HTTPS sin HSTS/CSP/XCTO/XFO/referrer + banner de versión
        let malo = hdrs(&[("server", "nginx/1.18.0")]);
        let r = evaluar_cabeceras(&malo, true);
        let nombres: Vec<&str> = r.iter().map(|h| h.vuln_name).collect();
        assert!(nombres.contains(&"tls-hsts-missing"));
        assert!(nombres.contains(&"header-csp-missing"));
        assert!(nombres.contains(&"header-xcto-missing"));
        assert!(nombres.contains(&"header-clickjacking"));
        assert!(nombres.contains(&"header-referrer-missing"));
        assert!(nombres.contains(&"version-banner-expuesto"));

        // CONTROL: todas presentes y bien → NADA
        let bueno = hdrs(&[
            ("strict-transport-security", "max-age=63072000"),
            ("content-security-policy", "default-src 'self'; frame-ancestors 'none'"),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "no-referrer"),
            ("server", "cloudflare"), // sin dígitos → no divulga versión
        ]);
        assert!(evaluar_cabeceras(&bueno, true).is_empty(), "cabeceras correctas no deben marcar");
    }

    // HSTS solo aplica en HTTPS (falso positivo evitado: en http no se exige HSTS).
    #[test]
    fn hsts_no_se_exige_en_http() {
        let vacio = hdrs(&[
            ("content-security-policy", "default-src 'self'; frame-ancestors 'none'"),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "no-referrer"),
        ]);
        let r = evaluar_cabeceras(&vacio, false);
        assert!(!r.iter().any(|h| h.vuln_name == "tls-hsts-missing"), "sin HTTPS no se exige HSTS");
    }

    #[test]
    fn cookies_rojo_marca_control_calla() {
        // ROJO: cookie de sesión sin flags, en HTTPS
        let malo = evaluar_cookies(&["sid=abc123; Path=/".to_string()], true);
        let n: Vec<&str> = malo.iter().map(|h| h.vuln_name).collect();
        assert!(n.contains(&"cookie-sin-secure"));
        assert!(n.contains(&"cookie-sin-httponly"));
        assert!(n.contains(&"cookie-sin-samesite"));

        // CONTROL: cookie endurecida → NADA
        let bueno = evaluar_cookies(
            &["sid=abc; Secure; HttpOnly; SameSite=Strict; Path=/".to_string()],
            true,
        );
        assert!(bueno.is_empty(), "cookie con todos los flags no debe marcar");
    }

    // Secure solo se exige en HTTPS (no en http, donde Secure no tiene sentido).
    #[test]
    fn secure_no_se_exige_en_http() {
        let r = evaluar_cookies(&["sid=abc; HttpOnly; SameSite=Lax".to_string()], false);
        assert!(!r.iter().any(|h| h.vuln_name == "cookie-sin-secure"));
    }
}
