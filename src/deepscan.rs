//! Orquestación de la verificación profunda (F3). Toma los hallazgos NEW o
//! RETRY_PENDING vencidos, los verifica en paralelo (acotado por deep_workers,
//! importante en el VPS sin swap) y aplica la máquina de estados:
//!   confirmado → VERIFIED · descartado → FALSE_POSITIVE
//!   bloqueo reintentable → RETRY_PENDING (con backoff) o VERIFICATION_FAILED si agotado
//!   sin herramienta → MANUAL_READY
//! Portado de bounty/scanner.py::verify_pending_findings + deep_scanner.verify_batch.

use crate::config::Config;
use crate::db;
use crate::error::Result;
use crate::verify::{self, Confidence, ErrorType, VerificationStrategy, VulnType};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub verified: u64,
    pub false_positive: u64,
    pub retry: u64,
    pub failed: u64,
    pub manual: u64,
    pub informational: u64,
}

/// Verifica hasta `limit` hallazgos pendientes. Devuelve estadísticas.
pub async fn run(cfg: &Config, pool: &SqlitePool, limit: i64) -> Result<Stats> {
    let items = db::fetch_verifiable(pool, limit).await?;
    if items.is_empty() {
        return Ok(Stats::default());
    }
    let sem = Arc::new(Semaphore::new(cfg.deep_workers.max(1)));
    // Evasión compartida entre los verificadores del lote (rate adaptativo).
    let evasion = Arc::new(crate::evasion::Evasion::new(
        cfg.rate_limit, cfg.user_agent.clone(), cfg.proxy.clone(), !cfg.no_rotate_ua, 0.2,
    ));
    let mut handles = Vec::with_capacity(items.len());

    for it in items {
        let permit = sem.clone().acquire_owned().await.expect("semáforo abierto");
        let cfg = cfg.clone();
        let pool = pool.clone();
        let evasion = evasion.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit; // se libera al terminar la tarea
            verify_and_persist(&cfg, &evasion, &pool, it).await
        }));
    }

    let mut stats = Stats::default();
    for h in handles {
        match h.await {
            Ok(Ok(kind)) => match kind {
                Kind::Verified => stats.verified += 1,
                Kind::FalsePositive => stats.false_positive += 1,
                Kind::Retry => stats.retry += 1,
                Kind::Failed => stats.failed += 1,
                Kind::Manual => stats.manual += 1,
                Kind::Informational => stats.informational += 1,
            },
            Ok(Err(e)) => tracing::warn!("verificación falló al persistir: {e}"),
            Err(e) => tracing::warn!("tarea de verificación abortó: {e}"),
        }
    }
    Ok(stats)
}

enum Kind {
    Verified,
    FalsePositive,
    Retry,
    Failed,
    Manual,
    Informational,
}

async fn verify_and_persist(cfg: &Config, evasion: &crate::evasion::Evasion, pool: &SqlitePool, it: db::PendingFinding) -> Result<Kind> {
    let vt = verify::classify(&it.vuln_name);

    // (P0) Poda de clases informativas ANTES de gastar herramientas: won't-fix de
    // H1 (cabeceras, versiones, SRI, debug/rpc en host no-productivo) no llenan la
    // cola manual ni pueden auto-enviarse. Queda visible en BD como INFORMATIONAL
    // (no se borra en silencio, directiva 20).
    if verify::is_informational_class(&it.vuln_name, &it.url) {
        db::apply_verification(pool, it.id, "INFORMATIONAL", false, "clasificador",
            "none", false, Some("clase informativa/won't-fix; no se promueve ni se auto-envía"),
            vt.as_str(), None, false, None).await?;
        return Ok(Kind::Informational);
    }

    let strategy = VerificationStrategy::default();
    let mut outcome = verify::verify_one(cfg, evasion, &it.vuln_name, &it.url, &strategy).await;
    let mut repro_ratio: Option<String> = None;

    // (P1) XSS: la herramienta (xsstrike) es solo PISTA. El gate de navegador
    // confirma por EJECUCIÓN, N veces (reproducibilidad incorporada). Solo si el
    // marcador computado ejecuta de forma reproducible se promueve a
    // explotable+confirmado; si no, se queda en manual sin explotable.
    if vt == VulnType::Xss {
        let hard_negative = outcome.confidence == Confidence::High && !outcome.verified;
        let blocked = outcome.error != ErrorType::None;
        if !hard_negative && !blocked {
            let nonce = (it.id as u64).wrapping_mul(2_654_435_761) % 100_000 + 1_000;
            // La REPRODUCIBILIDAD (N intentos de Chromium) solo la necesita lo que
            // puede AUTO-ENVIARSE, para no cerrarse "not reproducible" en H1. Si
            // payability excluye esta clase del auto-envío (la XSS reflejada hoy),
            // basta UNA confirmación de ejecución para la cola manual — 1/3 del
            // coste de Chromium en el VPS, sin perder el dato que hace accionable
            // la revisión (si ejecuta, merece reporte manual).
            let auto_ok = !cfg.autosubmit_payable_only || crate::autosubmit::payable_auto(vt.as_str());
            let (tries, min_ok) = if auto_ok { (cfg.xss_confirm_tries, cfg.xss_confirm_min) } else { (1, 1) };
            // Multipunto: prueba cada parámetro y el FRAGMENTO (DOM-XSS de location.hash), no
            // solo el último parámetro. Mismo discriminador (marcador computado) y misma
            // reproducibilidad; para en cuanto un punto confirma.
            let c = crate::browser::confirm_xss_multipunto(cfg, &it.url, tries, min_ok, nonce).await;
            repro_ratio = Some(c.ratio.clone());
            if c.confirmed {
                outcome.verified = true;
                outcome.exploitable = true;
                outcome.execution_confirmed = true;
                outcome.confidence = Confidence::High;
                outcome.tool = "browser".into();
                outcome.details = format!("XSS confirmada por ejecución en navegador ({})", c.ratio);
                outcome.evidence = Some(format!("ejecución reproducible {}", c.ratio));
            } else {
                // Reflejo no confirmado o intermitente: manual, nunca auto-envío.
                outcome.exploitable = false;
                outcome.execution_confirmed = false;
                if outcome.verified {
                    outcome.confidence = Confidence::Medium; // → MANUAL_READY
                    outcome.details = format!("XSS reflejada NO confirmada por ejecución ({})", c.ratio);
                }
            }
        }
    }

    // (P2) RETIRADO el 2026-08-23 (hallazgo H1 de la revisión). Era un gate FALSO
    // para exposición: re-corría `content_check` N veces y, si `exploitable`, ponía
    // `execution_confirmed=true` → auto-envío. Pero `content_check` sobre un cuerpo
    // estable es DETERMINISTA (clasificador puro), así que un substring FP
    // (`{"api_key":"REDACTED"}`) daba 3/3 y se auto-enviaba a la plataforma. La
    // reproducción por re-lectura NUNCA discrimina un FP estable (directiva 33: el
    // control no fallaba por la vía real). La confirmación REAL de un secreto la
    // hace `evaluar_secretos` (patrón + verificación viva del proveedor), que ya
    // pone `execution_confirmed` cuando corresponde; y `classify_exposure` quedó
    // acotado a Medium/no-explotable → MANUAL_READY. Quitar el mecanismo en vez de
    // contenerlo (directiva 1). SQLi/CMDi (P3) SÍ reproduce, porque re-lanza la
    // HERRAMIENTA real (no un clasificador puro).

    // (P3) SQLi/CMDi: sqlmap/commix EXPLOTAN de verdad (no string-match), pero una
    // sola corrida puede dar un falso "is vulnerable" (WAF que refleja el payload,
    // jitter en time-based). Cierra la asimetría con XSS/Exposure: reproducir antes
    // de auto-confirmar. El segundo pase (caro) SOLO se paga en lo AUTO-ENVIABLE; lo
    // que va a manual de todas formas se queda con una confirmación (directiva 30).
    if matches!(vt, VulnType::Sqli | VulnType::Cmdi) && outcome.execution_confirmed {
        let auto_ok = !cfg.autosubmit_payable_only || crate::autosubmit::payable_auto(vt.as_str());
        if auto_ok {
            let tries = cfg.sqli_confirm_tries.max(1);
            let mut oks = 1usize; // la primera corrida ya confirmó
            for _ in 1..tries {
                let o2 = verify::verify_one(cfg, evasion, &it.vuln_name, &it.url, &strategy).await;
                if o2.execution_confirmed {
                    oks += 1;
                }
            }
            repro_ratio = Some(format!("{oks}/{tries}"));
            if crate::browser::decide(oks, tries, cfg.sqli_confirm_min) {
                outcome.details = format!("{} reproducible ({oks}/{tries})", vt.as_str());
            } else {
                // No reproducible: NO auto-confirmar; a revisión manual.
                outcome.execution_confirmed = false;
                outcome.exploitable = false;
                outcome.confidence = Confidence::Medium;
                outcome.details = format!(
                    "{} NO reproducible ({oks}/{tries}) — no se auto-confirma, a revisión manual",
                    vt.as_str()
                );
            }
        }
    }

    let status = outcome.status();

    if status == "RETRY_PENDING" {
        // ¿Quedan reintentos? La decisión pasa por el tipo (solo errores
        // reintentables llegan aquí) y por el contador.
        match verify::plan_retry(outcome.error, it.retry_count as u32, it.max_retries as u32) {
            Some(wait) => {
                db::schedule_retry(pool, it.id, wait).await?;
                Ok(Kind::Retry)
            }
            None => {
                db::apply_verification(pool, it.id, "VERIFICATION_FAILED", false, &outcome.tool,
                    "none", false, None, vt.as_str(), None, false, repro_ratio.as_deref()).await?;
                Ok(Kind::Failed)
            }
        }
    } else {
        db::apply_verification(pool, it.id, status, outcome.verified, &outcome.tool,
            outcome.confidence.as_str(), outcome.exploitable, outcome.evidence.as_deref(),
            vt.as_str(), outcome.raw.as_deref(), outcome.execution_confirmed, repro_ratio.as_deref()).await?;
        Ok(match status {
            "VERIFIED" => Kind::Verified,
            "FALSE_POSITIVE" => Kind::FalsePositive,
            _ => Kind::Manual,
        })
    }
}
