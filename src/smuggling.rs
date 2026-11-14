// SPDX-License-Identifier: LicenseRef-Propietario
//! Detección de HTTP request smuggling / desync por DISCREPANCIA DE PARSING
//! (fase 3.3), técnica solo-TIMING (PortSwigger 2025): NO se deja una petición
//! parcial que envenene la conexión de OTRO usuario —eso sería el ataque, y viola
//! «sin daño»—; se envía una petición AMBIGUA AUTO-CONTENIDA y se mide si el
//! back-end se cuelga esperando cuerpo que no llega (desync CL↔TE).
//!
//! **Salvaguardas «sin daño»:**
//!   1. Solo-timing, auto-contenido: una petición ambigua por sonda, sin colgar
//!      nada en el buffer para el siguiente cliente.
//!   2. Timeout corto y sin reuso de conexión.
//!   3. **Gateado tras opt-in** (`NEXUS_SMUGGLING`): no corre por defecto — el
//!      smuggling es la clase más sensible, se activa a conciencia por objetivo.
//!
//! **Límite honesto (para no vender de más):** reqwest NORMALIZA `Content-Length`
//! y `Transfer-Encoding`, así que este probe es BEST-EFFORT —no craftea todos los
//! variantes de smuggling—. La versión fiable necesita sockets HTTP crudos
//! (`tokio-rustls`, una dependencia NUEVA = decisión de Juan). El NÚCLEO de
//! decisión por timing (`es_desync_por_tiempo`) sí es puro, exacto y ya está.

use sqlx::SqlitePool;

/// Umbral absoluto (ms): por debajo, cualquier diferencia es ruido de red.
const MIN_DESYNC_MS: u128 = 5_000;
/// Factor: la sonda ambigua tiene que tardar bastante MÁS que el baseline.
const FACTOR: u128 = 3;
/// Sondas por origen y confirmaciones mínimas para dar el desync por reproducible.
/// Una sola medición de tiempo es ruido (un GC, un pico de upstream, un paquete
/// perdido que dispara el timeout): el smuggling por timing SOLO se afirma si el
/// desync se REPITE. Espejo del patrón xss/sqli_confirm_tries/min.
const SONDAS: usize = 3;
const MIN_CONFIRMACIONES: usize = 2;

/// ¿La diferencia de tiempos delata un desync? PURO. Exige que la sonda ambigua
/// tarde >= `FACTOR`× el baseline Y supere un piso absoluto (para no marcar por
/// jitter de red). Un back-end que se cuelga esperando cuerpo es el positivo.
pub fn es_desync_por_tiempo(base_ms: u128, prueba_ms: u128) -> bool {
    prueba_ms >= MIN_DESYNC_MS && prueba_ms >= base_ms.saturating_mul(FACTOR).max(MIN_DESYNC_MS)
}

/// Decide sobre VARIAS sondas `(base_ms, prueba_ms)`. PURO. Un desync real se
/// REPITE; un pico transitorio no. Dos guardas:
///   1. **Reproducción N/M**: al menos `min_conf` de las sondas deben marcar
///      desync por tiempo. Un único pico (1 de 3) no basta.
///   2. **Control negativo**: si ALGÚN baseline ya supera el piso absoluto, el
///      canal es ruidoso/el sitio es lento de por sí y el retardo NO se puede
///      atribuir al desync → se abstiene (directiva 30: no se afirma sobre un
///      camino que no discrimina). Un sitio lento pero estable cae aquí, y está
///      bien: este probe es best-effort y no es donde se caza su smuggling.
pub fn es_desync_reproducible(muestras: &[(u128, u128)], min_conf: usize) -> bool {
    if muestras.is_empty() {
        return false;
    }
    if muestras.iter().any(|(base, _)| *base >= MIN_DESYNC_MS) {
        return false;
    }
    let confirmaciones = muestras
        .iter()
        .filter(|(base, prueba)| es_desync_por_tiempo(*base, *prueba))
        .count();
    confirmaciones >= min_conf
}

/// UNA sonda: mide el baseline (POST normal) y una petición con CL y TE en
/// conflicto. Devuelve `(base_ms, prueba_ms)`, o `None` si el baseline mismo
/// falló (sin baseline no hay con qué comparar).
async fn una_sonda(cliente: &reqwest::Client, url: &str) -> Option<(u128, u128)> {
    let t = |inicio: std::time::Instant| inicio.elapsed().as_millis();
    // Baseline: POST normal pequeño.
    let i0 = std::time::Instant::now();
    let base = match cliente.post(url).body("x=1").send().await {
        Ok(r) => {
            let _ = r.bytes().await;
            t(i0)
        }
        Err(_) => return None,
    };
    // Ambigua: CL y TE en conflicto (best-effort; reqwest puede normalizar).
    let i1 = std::time::Instant::now();
    let prueba = match cliente
        .post(url)
        .header("Transfer-Encoding", "chunked")
        .header("Content-Length", "4")
        .body("1\r\nA\r\n")
        .send()
        .await
    {
        Ok(r) => {
            let _ = r.bytes().await;
            t(i1)
        }
        // Un timeout AQUÍ (no en el baseline) es señal fuerte de que se colgó.
        Err(e) if e.is_timeout() => MIN_DESYNC_MS + 1,
        Err(_) => return Some((base, 0)), // sonda fallida ≠ desync: cuenta como no-confirmación
    };
    Some((base, prueba))
}

/// Sonda best-effort REPRODUCIDA: `SONDAS` mediciones y decisión por N/M con
/// control negativo (`es_desync_reproducible`). Devuelve el ratio de
/// confirmaciones si es reproducible, para el informe; `None` si no.
async fn sondear(cliente: &reqwest::Client, url: &str) -> Option<String> {
    let mut muestras: Vec<(u128, u128)> = Vec::with_capacity(SONDAS);
    for _ in 0..SONDAS {
        match una_sonda(cliente, url).await {
            Some(m) => muestras.push(m),
            None => return None, // sin baseline fiable: no se puede atribuir nada
        }
    }
    if es_desync_reproducible(&muestras, MIN_CONFIRMACIONES) {
        let confirmadas = muestras.iter().filter(|(b, p)| es_desync_por_tiempo(*b, *p)).count();
        Some(format!("{confirmadas}/{SONDAS}"))
    } else {
        None
    }
}

/// Fase gateada (opt-in). Revisa una muestra ACOTADA de orígenes; por cada posible
/// desync persiste un finding (high, MANUAL — smuggling siempre pide confirmación
/// humana) y avisa. No-op sin opt-in.
pub async fn fase_smuggling(
    pool: &SqlitePool,
    program: &str,
    origenes: &[String],
    opt_in: bool,
    max: usize,
    webhook: Option<&str>,
) -> anyhow::Result<usize> {
    if !opt_in {
        return Ok(0);
    }
    let cliente = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .pool_max_idle_per_host(0) // sin reuso de conexión (sin daño)
        .build()?;
    let program_id = crate::db::upsert_program(pool, program).await?;
    let mut n = 0usize;
    for origen in origenes.iter().take(max) {
        if let Some(ratio) = sondear(&cliente, origen).await {
            let nf = crate::db::NewFinding {
                program_name: program.to_string(),
                vuln_name: "http-request-smuggling-timing".to_string(),
                severity: "high".to_string(),
                url: origen.clone(),
                cwe: Some("CWE-444".to_string()),
                evidencia: Some(format!(
                    "posible desync HTTP en {origen}: una petición con cabeceras CL.TE ambiguas colgó la conexión muy por encima del baseline, REPRODUCIDO {ratio} veces con baseline estable (señal por tiempo, best-effort; NO enviar sin confirmar con socket HTTP crudo — reqwest normaliza CL/TE)."
                )),
            };
            if crate::db::insert_finding_dedup(pool, &nf, program_id).await? {
                n += 1;
                let _ = crate::notify::notificar(
                    webhook,
                    &crate::notify::Evento::Hallazgos(vec![crate::notify::HallazgoBreve {
                        severity: "high".into(),
                        vuln_type: "request-smuggling (timing)".into(),
                        url: origen.clone(),
                        program_name: program.to_string(),
                    }]),
                )
                .await;
            }
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desync_por_tiempo_discrimina() {
        // Se colgó: 8s frente a 200ms de baseline → desync.
        assert!(es_desync_por_tiempo(200, 8_000));
        // PAREJA: lento pero proporcional (no se colgó) → NO.
        assert!(!es_desync_por_tiempo(3_000, 6_000), "6s no es 3× de 3s ni pasa por poco");
        // Rápido → NO (por debajo del piso absoluto, es jitter).
        assert!(!es_desync_por_tiempo(50, 300));
        // Baseline ya lento pero la prueba similar → NO (no es discrepancia).
        assert!(!es_desync_por_tiempo(4_000, 4_500));
    }

    #[test]
    fn reproduccion_mata_el_pico_unico() {
        // UN pico (1 de 3) es ruido transitorio → NO se afirma. Este es EL falso
        // positivo que había que cerrar: antes una sola medición disparaba HIGH.
        let un_pico = [(200, 300), (200, 8_000), (200, 250)];
        assert!(!es_desync_reproducible(&un_pico, MIN_CONFIRMACIONES),
            "un solo pico de tiempo no es un desync");
        // Reproducido (2 de 3), con baseline estable → SÍ.
        let repetido = [(200, 8_000), (180, 250), (210, 9_000)];
        assert!(es_desync_reproducible(&repetido, MIN_CONFIRMACIONES),
            "el desync que se repite en mayoría sí se afirma");
        // CONTROL NEGATIVO: baseline ruidoso (una muestra ya sobre el piso) →
        // abstenerse aunque las pruebas se disparen (no se puede atribuir).
        let baseline_ruidoso = [(200, 8_000), (6_000, 18_000), (200, 9_000)];
        assert!(!es_desync_reproducible(&baseline_ruidoso, MIN_CONFIRMACIONES),
            "un baseline inestable hace inatribuible el retardo");
        // Todo limpio → NO.
        let limpio = [(200, 300), (180, 250), (210, 260)];
        assert!(!es_desync_reproducible(&limpio, MIN_CONFIRMACIONES));
        // Vacío → NO (sin datos no se afirma).
        assert!(!es_desync_reproducible(&[], MIN_CONFIRMACIONES));
    }
}
