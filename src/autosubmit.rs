//! Auto-envío a HackerOne (opt-in). Juan lo pidió por practicidad: un hallazgo
//! confirmado a cualquier hora debe reportarse YA — en bug bounty el primero que
//! reporta se lleva el bounty; esperar a la revisión manual sería perderlo.
//!
//! Salvaguardas (acordadas) para que la velocidad no queme la cuenta:
//!   - SOLO el tramo de máxima señal: VERIFIED + explotable + confianza ALTA.
//!     Todo lo demás sigue en manual (submit).
//!   - Dedup: no reenvía lo que ya tiene report_id (estado REPORTED).
//!   - Atribución obligatoria: si no se puede mapear el host a un programa H1,
//!     NO se envía (falla ruidoso, directiva 20) — queda para manual.
//!   - Rate-limit con jitter entre envíos (mismo espíritu anti-baneo).
//!   - `dry_run` por defecto: imprime lo que enviaría; el POST real exige el flag.

use crate::aprobacion::{self, Claim, Dispatch};
use crate::config::Config;
use crate::db::{self, VerifiedRow};
use crate::error::Result;
use crate::protection::{jitter, ProtectionConfig};
use crate::scope::{host_of, ScopeRule};
use crate::{h1, submitter};
use sqlx::SqlitePool;
use std::time::Duration;

#[derive(Debug, Default, Clone, Copy)]
pub struct SubmitStats {
    pub sent: u64,
    pub skipped_no_program: u64,
    pub skipped_duplicate: u64,
    /// La puerta de integridad (aprobacion) negó el despacho: texto reescrito, ya en
    /// vuelo, ya enviado, o envío previo en 'unknown'. Distinto de un duplicate de H1.
    pub skipped_gate: u64,
    pub skipped_not_payable: u64,
    pub skipped_cap: u64,
    pub dry_run: u64,
    pub failed: u64,
    /// El cortacircuitos por Signal pausó el auto-envío real.
    pub paused_signal: bool,
}

/// ¿Es una clase que se auto-envía sola? Payability: alto pago Y alta aceptación
/// en H1. Deja FUERA la XSS reflejada (P4/low o N-A en muchos programas, y lo que
/// más arriesga el Signal → riesgo de baneo) y el open-redirect. Regla por
/// enumeración (directiva 23): lo que no esté aquí va a revisión manual, no se
/// auto-envía. Puro y testable.
pub fn payable_auto(vuln_type: &str) -> bool {
    matches!(
        vuln_type.to_lowercase().as_str(),
        "sqli" | "rce" | "cmdi" | "ssrf" | "lfi" | "exposure"
    )
}

/// ¿Es clase auto-enviable, contando el opt-in de control de acceso? Las clases
/// base de `payable_auto` SIEMPRE; idor/bac (autz) SOLO con `cfg.autz_payable`
/// —auto-enviar control de acceso a H1 es una decisión de Signal aparte—.
pub fn es_pagable(cfg: &Config, vuln_type: &str) -> bool {
    payable_auto(vuln_type)
        || (cfg.autz_payable && matches!(vuln_type.to_lowercase().as_str(), "idor" | "bac"))
}

/// Regla de atribución: (handle, structured_scope_id, ScopeRule).
pub type AttrRule = (String, Option<String>, ScopeRule);

/// Atribuye un host a (handle, scope_id) del programa cuyo scope lo cubre.
/// Primera regla que casa gana. Puro.
pub fn attribute_host<'a>(host: &str, rules: &'a [AttrRule]) -> Option<(&'a str, Option<&'a str>)> {
    rules
        .iter()
        .find(|(_, _, r)| r.matches(host))
        .map(|(h, sid, _)| (h.as_str(), sid.as_deref()))
}

/// Ejecuta el auto-envío. Con `dry_run`, no toca H1: solo reporta qué enviaría.
pub async fn run(cfg: &Config, pool: &SqlitePool, dry_run: bool) -> Result<SubmitStats> {
    let mut stats = SubmitStats::default();

    // (A) CORTACIRCUITOS anti-baneo: si H1 ya cerró varios reportes propios como
    // duplicate/informative/not-applicable/spam, el Signal está cayendo — pausar
    // el envío REAL antes de que llegue el límite/baneo. En dry-run se avisa pero
    // se sigue mostrando qué se enviaría.
    let bad = db::count_bad_signal(pool).await?;
    if bad >= cfg.autosubmit_signal_floor {
        stats.paused_signal = true;
        tracing::error!(
            "auto-envío PAUSADO (anti-baneo): {bad} reporte(s) propios cerrados por H1 como \
             duplicate/informative/N-A (umbral {}). Revisar la calidad antes de reanudar.",
            cfg.autosubmit_signal_floor
        );
        if !dry_run {
            return Ok(stats);
        }
    }

    let candidates = db::fetch_autosubmit(pool).await?;
    if candidates.is_empty() {
        tracing::info!("auto-envío: sin candidatos (VERIFIED+execution_confirmed+explotable+alta, no reportados)");
        return Ok(stats);
    }

    // (B) TOPE DIARIO duro: no más de N envíos por 24 h aunque haya candidatos.
    let sent_today = db::count_submitted_since(pool, 24).await?;
    let mut budget = (cfg.autosubmit_max_per_day - sent_today).max(0);
    if budget == 0 && !dry_run {
        tracing::warn!(
            "auto-envío: tope diario alcanzado ({}/{} en 24 h); el resto espera al próximo día",
            sent_today, cfg.autosubmit_max_per_day
        );
    }

    // Reglas (handle, scope_id, ScopeRule) para atribuir hosts a programas.
    let rules: Vec<AttrRule> = db::scope_rules_full(pool)
        .await?
        .into_iter()
        .filter_map(|(h, sid, ident, wild)| ScopeRule::parse(&ident, wild).map(|r| (h, sid, r)))
        .collect();

    // S2: agrupa por (programa, vuln_name) → un reporte por grupo con TODAS las URLs.
    let mut groups: std::collections::BTreeMap<(String, String), Vec<VerifiedRow>> = Default::default();
    for row in candidates {
        let prog = row.program_name.clone().unwrap_or_else(|| "GLOBAL_FEED".into());
        groups.entry((prog, row.vuln_name.clone())).or_default().push(row);
    }

    let pcfg = ProtectionConfig::default();
    let client = if dry_run { None } else { Some(h1::H1Client::from_env(&pcfg.user_agent)?) };

    let mut i = 0u32;
    for ((program, vuln), rows) in groups {
        // (C) PAYABILITY: solo clases de alto pago/aceptación se auto-envían. La
        // XSS reflejada confirmada y el open-redirect quedan en manual (P4/N-A y
        // riesgo de Signal). Es lo que hace el auto-envío "efectivo y sin baneo".
        let vuln_type = rows.first().and_then(|r| r.vuln_type.clone()).unwrap_or_default();
        if cfg.autosubmit_payable_only && !es_pagable(cfg, &vuln_type) {
            tracing::info!("payability: '{vuln}' ({vuln_type}) no es clase de auto-envío; queda para revisión manual");
            stats.skipped_not_payable += 1;
            continue;
        }

        // Atribuye por el host del primer sibling (todos comparten programa).
        let host = host_of(&rows[0].url);
        let (handle, scope_id) = match attribute_host(&host, &rules) {
            Some((h, sid)) => (h.to_string(), sid.map(String::from)),
            None => {
                tracing::warn!("sin programa para {host}: '{vuln}' queda para envío manual");
                stats.skipped_no_program += 1;
                continue;
            }
        };

        // Dedup entre ciclos: si este (programa, vuln) ya se reportó, no reenviar
        // (H1 lo cerraría como duplicate → quema señal). Chequeo antes del POST.
        if db::already_reported(pool, &program, &vuln).await? {
            tracing::info!("dedup: '{vuln}' de '{program}' ya fue reportado; no se reenvía");
            stats.skipped_duplicate += 1;
            continue;
        }

        let (title, vuln_info, impact, severity, cwe) = build_report(&program, &vuln, &rows);

        if dry_run {
            tracing::info!("[DRY-RUN] enviaría a '{handle}': {title} ({severity}, {} endpoints)", rows.len());
            stats.dry_run += 1;
            continue;
        }

        // (B) TOPE DIARIO: si ya se agotó el presupuesto de 24 h, el resto espera.
        if budget <= 0 {
            tracing::warn!("tope diario: '{vuln}' de '{program}' espera al próximo día (max {}/24h)", cfg.autosubmit_max_per_day);
            stats.skipped_cap += 1;
            continue;
        }

        // Rate-limit con jitter entre envíos reales (respeta --safe-mode).
        if i > 0 {
            let wait = jitter(cfg.program_cooldown as f64, pcfg.jitter_percent, deterministic_r(i));
            tokio::time::sleep(Duration::from_secs_f64(wait)).await;
        }
        i += 1;

        // PUERTA DE INTEGRIDAD (aprobacion, port del operator-approval-loop de ECC):
        // congela el texto EXACTO que va a salir (destino incluido), reclama permiso —
        // rechaza si el texto se reescribió desde la aprobación, si ya hay uno en vuelo,
        // o si este report_key ya se envió/quedó 'unknown'— y solo entonces despacha.
        // Cierra la ventana POST-ok/crash del `mark_reported` y el reenvío de texto no
        // verificado (directiva 31: el veredicto se ancla al ARTEFACTO).
        let report_key = format!("{program}::{vuln}");
        let texto_envio = format!(
            "handle={handle}\nscope={}\nseverity={severity}\ncwe={}\ntitle={title}\n\n{vuln_info}\n\n== IMPACTO ==\n{impact}",
            scope_id.as_deref().unwrap_or("-"),
            cwe.as_deref().unwrap_or("-"),
        );
        let evidencia = format!(
            "auto-envío {vuln_type}, {} endpoint(s), VERIFIED+execution_confirmed",
            rows.len()
        );
        let sid = aprobacion::snapshot(pool, &report_key, &texto_envio, &evidencia, now_ts()).await?;
        let token = match aprobacion::claim(pool, &report_key, sid, &texto_envio, now_ts()).await? {
            Claim::Concedido(t) => t,
            Claim::Rechazado(motivo) => {
                tracing::warn!("aprobación: '{vuln}' de '{program}' NO se despacha: {motivo}");
                stats.skipped_gate += 1;
                continue;
            }
        };
        // El texto aprobado que devuelve el despacho es, byte a byte, el que compusimos
        // en esta misma iteración (mismo sha ya validado en `claim`); H1 lo recibe por
        // campos. begin_dispatch existe para que NADIE más pueda despachar este claim.
        match aprobacion::begin_dispatch(pool, &token, now_ts()).await? {
            Dispatch::Concedido(_) => {}
            Dispatch::Perdido(motivo) => {
                tracing::warn!("aprobación: despacho perdido para '{vuln}' de '{program}': {motivo}");
                stats.skipped_gate += 1;
                continue;
            }
        }

        let resultado = client.as_ref().unwrap()
            .submit_report(&crate::h1::ReporteNuevo {
                team_handle: &handle,
                title: &title,
                vulnerability_information: &vuln_info,
                impact: &impact,
                severity_rating: severity,
                structured_scope_id: scope_id.as_deref(),
                cwe: cwe.as_deref(),
            })
            .await;
        if finalizar_envio(pool, &token, resultado, &rows, &handle, &title).await? {
            stats.sent += 1;
            budget -= 1; // consume una plaza del tope diario
        } else {
            stats.failed += 1;
        }
    }
    Ok(stats)
}

/// Cierra el claim tras el INTENTO de envío, recibiendo el `resultado` ya obtenido (no toca
/// la red). En ÉXITO: `complete` ANTES de `mark_reported` —el receipt 'sent' es la barrera de
/// idempotencia aunque `mark_reported` falle luego—. En FALLO: marca 'unknown' —el POST pudo
/// salir, así que NO se reintenta solo, para no arriesgar el doble envío—. Devuelve `true` si
/// se envió. Extraído de `run` para ANCLAR por test esta invariante (antes vivía inline y
/// ningún test la reddenaba: sin-caso-rojo `autosubmit.rs:226/237`, 2026-09-24).
async fn finalizar_envio(
    pool: &sqlx::SqlitePool,
    token: &str,
    resultado: Result<String>,
    rows: &[VerifiedRow],
    handle: &str,
    title: &str,
) -> Result<bool> {
    match resultado {
        Ok(report_id) => {
            aprobacion::complete(pool, token, &report_id, now_ts()).await?;
            for r in rows {
                db::mark_reported(pool, r.id, &report_id).await?;
            }
            tracing::info!("ENVIADO a '{handle}' → reporte {report_id}: {title} ({} endpoints)", rows.len());
            Ok(true)
        }
        Err(e) => {
            if let Err(e2) = aprobacion::mark_unknown(pool, token, now_ts()).await {
                tracing::error!("aprobación: no se pudo marcar 'unknown' tras fallo de envío: {e2}");
            }
            tracing::error!("fallo enviando '{title}' a '{handle}': {e} (claim en 'unknown', requiere revisión)");
            Ok(false)
        }
    }
}

/// Segundos epoch UTC para los timestamps de la puerta de aprobación.
fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Construye (title, body, impact, severity, cwe) de un grupo de siblings (S2/S4).
fn build_report(program: &str, vuln_name: &str, rows: &[VerifiedRow]) -> (String, String, String, &'static str, Option<String>) {
    let vt = rows.first().and_then(|r| r.vuln_type.clone()).unwrap_or_else(|| "other".into());
    let severity = rows.first().map(|r| r.severity.clone()).unwrap_or_else(|| "unknown".into());
    let cwe = rows.iter().find_map(|r| r.cwe.clone());
    let endpoints: Vec<submitter::Endpoint> = rows.iter().map(|r| submitter::Endpoint {
        url: r.url.clone(),
        verified: r.verified != 0,
        tool: r.verification_tool.clone(),
        confidence: r.verification_confidence.clone(),
        exploitable: r.exploitable != 0,
        evidence: r.verification_evidence.clone(),
        raw: r.raw_evidence.clone(),
        execution_confirmed: r.execution_confirmed != 0,
        repro_ratio: r.repro_ratio.clone(),
    }).collect();
    let body = submitter::build_submission(program, vuln_name, &vt, &severity, &endpoints);
    let ti = submitter::tech_info(&vt);
    let title = format!("[{vuln_name}] confirmado en {} endpoint(s)", rows.len());
    (title, body, ti.impact.to_string(), submitter::h1_severity(&severity), cwe)
}

/// Aleatorio determinista por índice (evita Math.random; varía por i).
fn deterministic_r(i: u32) -> f64 {
    // Secuencia pseudo-aleatoria simple y estable.
    let x = (i.wrapping_mul(2654435761)) as f64;
    (x / u32::MAX as f64).fract()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool_migrado() -> sqlx::SqlitePool {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    /// Deja un claim en estado 'dispatching' (snapshot → claim → begin_dispatch), listo para
    /// que `finalizar_envio` lo cierre.
    async fn claim_en_dispatch(pool: &sqlx::SqlitePool, k: &str) -> String {
        let sid = aprobacion::snapshot(pool, k, "txt", "ev", 100).await.unwrap();
        let tok = match aprobacion::claim(pool, k, sid, "txt", 101).await.unwrap() {
            Claim::Concedido(t) => t,
            o => panic!("claim inicial debía conceder: {o:?}"),
        };
        match aprobacion::begin_dispatch(pool, &tok, 102).await.unwrap() {
            Dispatch::Concedido(_) => {}
            o => panic!("begin_dispatch debía conceder: {o:?}"),
        }
        tok
    }

    #[tokio::test]
    async fn finalizar_exito_cierra_el_claim_y_bloquea_reenvio() {
        // CASO ROJO de autosubmit.rs:226: en ÉXITO, `finalizar_envio` hace `complete` → el
        // report_key queda 'sent' y un re-claim se rechaza como YA ENVIADO. Si se saltara el
        // `complete`, el claim quedaría 'en vuelo' y este assert reddenaría.
        let pool = pool_migrado().await;
        let tok = claim_en_dispatch(&pool, "acme::sqli").await;
        let enviado = finalizar_envio(&pool, &tok, Ok("report-1".to_string()), &[], "acme", "t")
            .await
            .unwrap();
        assert!(enviado, "un envío Ok cuenta como enviado");
        let sid2 = aprobacion::snapshot(&pool, "acme::sqli", "txt", "ev", 200).await.unwrap();
        match aprobacion::claim(&pool, "acme::sqli", sid2, "txt", 201).await.unwrap() {
            Claim::Rechazado(m) => assert!(m.contains("enviado"), "esperaba 'ya enviado', fue: {m}"),
            Claim::Concedido(_) => panic!("CASO ROJO: reenvío tras un envío Ok (¿se saltó `complete`?)"),
        }
    }

    #[tokio::test]
    async fn finalizar_fallo_marca_unknown_y_no_reintenta_solo() {
        // CASO ROJO de autosubmit.rs:237: en FALLO, `finalizar_envio` marca 'unknown' (el POST
        // pudo salir) → un re-claim va a revisión, NO se reintenta solo. Sin `mark_unknown` el
        // claim quedaría 'en vuelo' y el motivo no diría 'unknown/revisión'.
        let pool = pool_migrado().await;
        let tok = claim_en_dispatch(&pool, "acme::xss").await;
        let enviado = finalizar_envio(
            &pool,
            &tok,
            Err(crate::error::NexusError::Other("500 del objetivo".into())),
            &[],
            "acme",
            "t",
        )
        .await
        .unwrap();
        assert!(!enviado, "un envío Err no cuenta como enviado");
        let sid2 = aprobacion::snapshot(&pool, "acme::xss", "txt", "ev", 200).await.unwrap();
        match aprobacion::claim(&pool, "acme::xss", sid2, "txt", 201).await.unwrap() {
            Claim::Rechazado(m) => {
                assert!(m.contains("unknown") || m.contains("revisión"), "esperaba 'unknown', fue: {m}")
            }
            Claim::Concedido(_) => panic!("CASO ROJO: reintento tras fallo (¿se saltó `mark_unknown`?)"),
        }
    }

    fn rules() -> Vec<AttrRule> {
        vec![
            ("acme".into(), Some("SC-1".into()), ScopeRule::parse("*.example.com", true).unwrap()),
            ("beta".into(), None, ScopeRule::parse("foo.com", false).unwrap()),
        ]
    }

    #[test]
    fn atribuye_host_al_programa() {
        let r = rules();
        assert_eq!(attribute_host("api.example.com", &r), Some(("acme", Some("SC-1"))));
        assert_eq!(attribute_host("foo.com", &r), Some(("beta", None)));
        assert_eq!(attribute_host("nada.org", &r), None); // sin programa → manual
    }

    #[test]
    fn severidad_a_h1() {
        assert_eq!(submitter::h1_severity("critical"), "critical");
        assert_eq!(submitter::h1_severity("info"), "none");
    }

    #[test]
    fn payability_deja_fuera_xss_y_redirect() {
        // Alto pago / alta aceptación → sí.
        for t in ["sqli", "rce", "cmdi", "ssrf", "lfi", "exposure", "SQLI"] {
            assert!(payable_auto(t), "{t} debe auto-enviarse");
        }
        // Riesgo de Signal / bajo pago → no (quedan en manual).
        for t in ["xss", "redirect", "other", ""] {
            assert!(!payable_auto(t), "{t} NO debe auto-enviarse");
        }
    }

    #[test]
    fn control_de_acceso_pagable_solo_con_el_opt_in() {
        use clap::Parser;
        let con = Config::parse_from(["nexus", "--autz-payable", "scan"]);
        let sin = Config::parse_from(["nexus", "scan"]);
        // idor/bac: SOLO pagables con el flag.
        for t in ["idor", "bac", "BAC"] {
            assert!(es_pagable(&con, t), "{t} pagable con autz_payable");
            assert!(!es_pagable(&sin, t), "{t} NO pagable sin el opt-in");
        }
        // Las clases base no dependen del flag; el ruido sigue fuera en ambos.
        assert!(es_pagable(&sin, "sqli") && es_pagable(&con, "sqli"));
        assert!(!es_pagable(&con, "xss") && !es_pagable(&sin, "xss"), "el flag NO abre otras clases");
    }
}
