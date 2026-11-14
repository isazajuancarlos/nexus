//! Motor de escaneo. Invoca nuclei por fases de prioridad (CRITICAL→HIGH),
//! parsea su JSONL, deduplica e inserta. Entre fases mete cooldown con jitter.
//! Unifica el "sniper" de hacker/main.py con el escaneo por fases de
//! bounty/scanner.py.

use crate::config::{Config, HIGH_PRIORITY_TAGS, MEDIUM_PRIORITY_TAGS};
use crate::db::{self, NewFinding};
use crate::error::Result;
use crate::protection::{self, Guard};
use serde::Deserialize;
use sqlx::SqlitePool;
use std::path::Path;
use std::time::Duration;

/// Una línea de la salida -jsonl de nuclei (solo los campos que usamos).
#[derive(Debug, Deserialize)]
struct NucleiLine {
    #[serde(rename = "template-id")]
    template_id: Option<String>,
    info: Option<NucleiInfo>,
    #[serde(rename = "matched-at")]
    matched_at: Option<String>,
    host: Option<String>,
    // Campos que SOLO trae el modo DAST (fuzzing): el parámetro inyectado y la
    // petición/respuesta que lo prueban. En la salida de `-tags` no vienen, así
    // que son Option y `parse_nuclei_line` los ignora — solo `parse_dast_line`
    // los usa para construir la evidencia (la petición de fuzzing ES la prueba:
    // no hay plantilla-CVE que re-correr, a diferencia de un hallazgo de -tags).
    request: Option<String>,
    response: Option<String>,
    #[serde(rename = "fuzzing_parameter")]
    fuzzing_parameter: Option<String>,
    #[serde(rename = "fuzzing_position")]
    fuzzing_position: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NucleiInfo {
    severity: Option<String>,
    classification: Option<NucleiClass>,
}

#[derive(Debug, Deserialize)]
struct NucleiClass {
    #[serde(rename = "cwe-id")]
    cwe_id: Option<Vec<String>>,
}

/// Parsea una línea JSONL de nuclei a un hallazgo. Devuelve None si la línea no
/// es JSON válido o le falta lo esencial (falla en silencio por línea, no
/// aborta la fase — pero el llamante cuenta las líneas malas).
pub fn parse_nuclei_line(line: &str, program: &str) -> Option<NewFinding> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let parsed: NucleiLine = serde_json::from_str(line).ok()?;
    let vuln_name = parsed.template_id.unwrap_or_else(|| "unknown".into());
    let info = parsed.info;
    let severity = info.as_ref().and_then(|i| i.severity.clone()).unwrap_or_else(|| "unknown".into());
    let cwe = info
        .as_ref()
        .and_then(|i| i.classification.as_ref())
        .and_then(|c| c.cwe_id.as_ref())
        .and_then(|v| v.first().cloned());
    let url = parsed.matched_at.or(parsed.host).unwrap_or_else(|| "unknown".into());
    Some(NewFinding { program_name: program.to_string(), vuln_name, severity, url, cwe, evidencia: None })
}

/// Tope de bytes de la petición/respuesta que se guardan como evidencia DAST. Una
/// respuesta puede ser enorme; con esto la cola sigue siendo auditable sin inflar
/// la BD. Se corta por el primer límite de char para no partir un UTF-8.
const DAST_EVIDENCIA_MAX: usize = 1500;

fn recorta(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let corte = s.char_indices().take_while(|(i, _)| *i < max).last().map(|(i, c)| i + c.len_utf8()).unwrap_or(0);
        format!("{}…[+{} bytes]", &s[..corte], s.len() - corte)
    }
}

/// Parsea una línea JSONL del modo DAST (fuzzing). A diferencia de
/// `parse_nuclei_line`, CONSERVA la evidencia: el parámetro inyectado y la
/// petición/respuesta que lo prueban, porque en DAST no hay plantilla-CVE que
/// deepscan pueda re-correr para confirmar — la petición de fuzzing es la prueba.
/// Sin evidencia el hallazgo no sería auditable (directiva 30).
pub fn parse_dast_line(line: &str, program: &str) -> Option<NewFinding> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let parsed: NucleiLine = serde_json::from_str(line).ok()?;
    let vuln_name = parsed.template_id.unwrap_or_else(|| "unknown".into());
    let info = parsed.info;
    let severity = info.as_ref().and_then(|i| i.severity.clone()).unwrap_or_else(|| "unknown".into());
    let cwe = info
        .as_ref()
        .and_then(|i| i.classification.as_ref())
        .and_then(|c| c.cwe_id.as_ref())
        .and_then(|v| v.first().cloned());
    let url = parsed.matched_at.clone().or_else(|| parsed.host.clone()).unwrap_or_else(|| "unknown".into());

    let mut ev = String::new();
    if let Some(p) = &parsed.fuzzing_parameter {
        let pos = parsed.fuzzing_position.as_deref().unwrap_or("?");
        ev.push_str(&format!("fuzzing: parámetro «{p}» en {pos}\n"));
    }
    if let Some(m) = &parsed.matched_at {
        ev.push_str(&format!("matched-at: {m}\n"));
    }
    if let Some(req) = &parsed.request {
        ev.push_str(&format!("--- petición ---\n{}\n", recorta(req, DAST_EVIDENCIA_MAX)));
    }
    if let Some(resp) = &parsed.response {
        ev.push_str(&format!("--- respuesta ---\n{}", recorta(resp, DAST_EVIDENCIA_MAX)));
    }
    let evidencia = (!ev.is_empty()).then_some(ev);
    Some(NewFinding { program_name: program.to_string(), vuln_name, severity, url, cwe, evidencia })
}

/// ¿Es una severidad que H1 puede pagar y por tanto vale la pena almacenar y
/// verificar? Falso para `info`/`unknown`/vacío: informativo o sin severidad, no
/// es una vulnerabilidad. Ante el dato ausente NO se trata como pagable
/// (directiva 20). Es la REGLA que sustituye al enumerado de plantillas: filtra
/// por lo que H1 paga, no por una lista de IDs que siempre va por detrás.
pub fn es_severidad_pagable(sev: &str) -> bool {
    !matches!(
        sev.trim().to_ascii_lowercase().as_str(),
        "info" | "informational" | "unknown" | ""
    )
}

/// Ejecuta UNA fase de nuclei con un set de tags sobre `targets_file`. Devuelve
/// (hallazgos_nuevos, líneas_ilegibles). El timeout crece con hosts y tags.
#[allow(clippy::too_many_arguments)] // motor: muchos parámetros por naturaleza
pub async fn run_phase(
    cfg: &Config,
    pool: &SqlitePool,
    program: &str,
    program_id: i64,
    phase_name: &str,
    tags: &str,
    targets_file: &Path,
    host_count: usize,
    // Techo de segundos para esta fase. Es `min(phase_timeout, presupuesto
    // restante)`, ya calculado por el llamante — aquí solo se aplica al
    // `-timeout` de nuclei, para que salga con lo reunido y no lo mate systemd.
    tope_secs: u64,
) -> Result<(u64, u64)> {
    let log_id = db::scan_log_start(pool, program, "nuclei", phase_name).await?;
    let tag_count = tags.split(',').count();
    let timeout = protection::phase_timeout(host_count, tag_count).min(tope_secs.max(1));

    let mut args: Vec<String> = vec![
        "-l".into(), targets_file.display().to_string(),
        "-tags".into(), tags.into(),
        "-rl".into(), cfg.rate_limit.to_string(),
        "-bs".into(), cfg.batch_size.to_string(),
        "-c".into(), cfg.nuclei_concurrency.to_string(),
        "-timeout".into(), cfg.nuclei_request_timeout.to_string(),
        "-jsonl".into(),
        "-silent".into(),
        "-disable-update-check".into(),
    ];
    // Evasión (P1): User-Agent (fijo o rotado) + proxy de salida.
    let ua = cfg.user_agent.clone().unwrap_or_else(|| {
        let idx = if cfg.no_rotate_ua { 0 } else { tag_count % crate::evasion::UA_POOL.len() };
        crate::evasion::UA_POOL[idx].to_string()
    });
    args.push("-H".into());
    args.push(format!("User-Agent: {ua}"));
    if let Some(p) = &cfg.proxy {
        args.push("-proxy".into());
        args.push(p.clone());
    }
    // Excluir plantillas info-flood (ruido no pagable en H1, medido en vivo).
    for id in crate::config::EXCLUDED_TEMPLATES {
        args.push("-eid".into());
        args.push((*id).to_string());
    }
    // Y excluir por SEVERIDAD: que nuclei ni ejecute las plantillas info. Es la
    // regla; el `-eid` de arriba es solo un complemento para casos concretos.
    args.push("-es".into());
    args.push(crate::config::EXCLUDED_SEVERITIES.into());

    let out = crate::tools::run(&cfg.nuclei_path, &args, Duration::from_secs(timeout)).await?;

    let mut new_findings = 0u64;
    let mut bad_lines = 0u64;
    let mut no_pagables = 0u64;
    for line in out.stdout.lines() {
        match parse_nuclei_line(line, program) {
            Some(f) => {
                // Filtro por severidad: no se almacena lo que H1 no paga aunque
                // nuclei lo emita (una plantilla con severidad mal etiquetada, o
                // `unknown` por metadata ausente). El `-es` de arriba ya evita
                // que la mayoría siquiera se ejecute; esto cierra el resto.
                if !es_severidad_pagable(&f.severity) {
                    no_pagables += 1;
                    continue;
                }
                if db::insert_finding_dedup(pool, &f, program_id).await? {
                    new_findings += 1;
                }
            }
            None if !line.trim().is_empty() => bad_lines += 1,
            None => {}
        }
    }
    if no_pagables > 0 {
        tracing::info!("fase {phase_name}: {no_pagables} hallazgos de severidad no pagable (info/unknown) descartados");
    }

    let status = if out.timed_out { "timeout" } else if out.code == Some(0) { "completed" } else { "failed" };
    db::scan_log_finish(pool, log_id, status, new_findings as i64, if bad_lines > 0 { Some("líneas JSON ilegibles") } else { None }).await?;
    Ok((new_findings, bad_lines))
}

/// Construye los argumentos de `nuclei -dast`. Extraído de `fase_dast` para poder
/// SONDEARLO (directiva 33): el único invariante de seguridad de la fase es
/// `-no-interactsh` —sin él, las clases OAST filtrarían callbacks al interactsh
/// PÚBLICO de un tercero, revelando qué objetivos probamos (justo lo que el OOB
/// auto-hospedado evita)—, y hasta ahora lo sostenía solo un literal que un
/// refactor podía borrar sin que nada se pusiera rojo (observación de la revisión
/// 2026-08-23). El test `dast_args_siempre_excluye_interactsh` lo fija.
fn dast_args(cfg: &Config, dast_file: &Path, ua: &str) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "-l".into(), dast_file.display().to_string(),
        "-dast".into(),
        "-no-interactsh".into(), // sin fuga OOB a terceros; clases in-band solo
        "-fuzz-aggression".into(), cfg.dast_aggression.clone(),
        "-rl".into(), cfg.rate_limit.to_string(),
        "-c".into(), cfg.nuclei_concurrency.to_string(),
        "-timeout".into(), cfg.nuclei_request_timeout.to_string(),
        "-es".into(), crate::config::EXCLUDED_SEVERITIES.into(),
        "-jsonl".into(),
        "-silent".into(),
        "-disable-update-check".into(),
    ];
    args.push("-H".into());
    args.push(format!("User-Agent: {ua}"));
    if let Some(p) = &cfg.proxy {
        args.push("-proxy".into());
        args.push(p.clone());
    }
    args
}

/// Fase DAST: fuzzing ACTIVO de parámetros con el motor `-dast` de nuclei sobre
/// las URLs parametrizadas (`param_urls`). Caza lo que las plantillas-CVE no ven
/// —SQLi/XSS/SSTI/cmdi en el código PROPIO del objetivo—, en banda (reflejado /
/// por tiempo / por error). SIEMPRE `-no-interactsh`: las clases ciegas OAST se
/// EXCLUYEN para no filtrar a un interactsh de terceros (la razón por la que el
/// OOB es auto-hospedado). Los hallazgos entran como NEW con su evidencia de
/// fuzzing y pasan por el mismo verify + gate que el resto: un candidato DAST NO
/// se auto-envía sin confirmación por ejecución (execution_confirmed sigue 0).
///
/// Devuelve el número de hallazgos nuevos. No-op ruidoso (log) si no hay URLs
/// parametrizadas o si el presupuesto no da para una vuelta.
pub async fn fase_dast(
    cfg: &Config,
    pool: &SqlitePool,
    program: &str,
    param_urls: &[String],
    deadline: Option<std::time::Instant>,
) -> Result<u64> {
    if param_urls.is_empty() {
        tracing::info!("dast: sin URLs parametrizadas en {program}, no hay dónde fuzzear");
        return Ok(0);
    }
    let cap = param_urls.len().min(cfg.dast_cap.max(1));
    // Presupuesto: el fuzzing es caro (payloads × parámetros). ~25 s/URL, acotado
    // entre 5 y 30 min, y recortado a lo que quede del ciclo (o saltado si no da).
    let natural = (cap as u64 * 25).clamp(300, 1800);
    let restante = deadline.map(|d| d.saturating_duration_since(std::time::Instant::now()).as_secs());
    let tope = match presupuesto_de_fase(restante, natural) {
        Presupuesto::Correr(t) => t,
        Presupuesto::Saltar => {
            tracing::info!("dast: quedan {}s, no arranco el fuzzing", restante.unwrap_or(0));
            return Ok(0);
        }
    };

    let program_id = db::upsert_program(pool, program).await?;
    let log_id = db::scan_log_start(pool, program, "dast", &cfg.dast_aggression).await?;

    let dast_file = cfg.scans_dir.join("dast_targets.txt");
    let capped: Vec<&str> = param_urls.iter().map(|s| s.as_str()).take(cap).collect();
    tokio::fs::write(&dast_file, capped.join("\n")).await?;

    let ua = cfg.user_agent.clone().unwrap_or_else(|| crate::evasion::UA_POOL[0].to_string());
    let args = dast_args(cfg, dast_file.as_path(), &ua);

    tracing::info!("dast: fuzzeando {cap} URL(s) parametrizada(s) de {program} (agresión {}, tope {tope}s)", cfg.dast_aggression);
    let out = crate::tools::run(&cfg.nuclei_path, &args, Duration::from_secs(tope)).await?;

    let mut new_findings = 0u64;
    let mut bad_lines = 0u64;
    let mut no_pagables = 0u64;
    for line in out.stdout.lines() {
        match parse_dast_line(line, program) {
            Some(f) => {
                if !es_severidad_pagable(&f.severity) {
                    no_pagables += 1;
                    continue;
                }
                if db::insert_finding_dedup(pool, &f, program_id).await? {
                    new_findings += 1;
                }
            }
            None if !line.trim().is_empty() => bad_lines += 1,
            None => {}
        }
    }

    let status = if out.timed_out { "timeout" } else if out.code == Some(0) { "completed" } else { "failed" };
    db::scan_log_finish(pool, log_id, status, new_findings as i64, if bad_lines > 0 { Some("líneas JSON ilegibles") } else { None }).await?;
    tracing::info!("dast: {new_findings} hallazgo(s) nuevo(s) de fuzzing en {program} ({no_pagables} no-pagables descartados, {status})");
    Ok(new_findings)
}

/// Lo que el presupuesto de tiempo decide para la siguiente fase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presupuesto {
    /// Córrela, con este techo de segundos para nuclei (`-timeout` acotado).
    Correr(u64),
    /// No queda tiempo útil: sáltala y ve a verify + envío con lo escaneado.
    Saltar,
}

/// Menos de esto no vale la pena arrancar otra fase: nuclei tarda en levantarse
/// y no daría ni para una vuelta. Se para y se pasa a verificar lo que haya.
const MIN_FASE_SECS: u64 = 60;

/// Decide, SIN reloj ni red, qué hacer con una fase cuyo timeout natural sería
/// `phase_timeout`, cuando quedan `restante` segundos de presupuesto.
///
/// - Sin presupuesto (`None`) → correr con su timeout natural: es el
///   comportamiento de siempre, intacto cuando `NEXUS_SCAN_DEADLINE_SECS=0`.
/// - Queda menos que el mínimo útil → saltar.
/// - Queda menos que el timeout natural → correr, pero **acotada al tiempo que
///   queda**: nuclei sale con lo que haya reunido en vez de que lo mate systemd.
/// - Queda de sobra → su timeout natural.
pub fn presupuesto_de_fase(restante: Option<u64>, phase_timeout: u64) -> Presupuesto {
    match restante {
        None => Presupuesto::Correr(phase_timeout),
        Some(r) if r < MIN_FASE_SECS => Presupuesto::Saltar,
        Some(r) => Presupuesto::Correr(phase_timeout.min(r)),
    }
}

/// Escanea un programa con escaneo por fases (o de una pasada si
/// --no-priority-scan). Aplica cooldown con jitter entre fases y actualiza el
/// Guard según el resultado (backoff/pausa anti-baneo).
///
/// `deadline`: instante en que el SCAN debe haber terminado, o `None` para no
/// acotarlo. Cuando está, cada fase se acota al tiempo que queda y las que no
/// caben se saltan — el ciclo para limpio y deja el resto del presupuesto para
/// verify + auto-envío, en vez de morir por SIGKILL a mitad de nuclei.
#[allow(clippy::too_many_arguments)]
pub async fn scan_program(
    cfg: &Config,
    pool: &SqlitePool,
    guard: &mut Guard,
    deadline: Option<std::time::Instant>,
    program: &str,
    targets_file: &Path,
    host_count: usize,
    rng: &mut impl FnMut() -> f64,
) -> Result<u64> {
    let program_id = db::upsert_program(pool, program).await?;

    // P3: budget cap — acota la entrada de nuclei a lo que una fase puede cubrir
    // a este ritmo, así no se dispara la duración ni la RAM (bajos recursos).
    const TPL_PER_PHASE: u64 = 200; // estimación de plantillas por fase
    let budget = (900u64 * cfg.rate_limit as u64 / TPL_PER_PHASE) as usize;
    let cap = budget.clamp(40, cfg.max_hosts);
    let (scan_file, host_count): (std::path::PathBuf, usize) = if host_count > cap {
        let content = tokio::fs::read_to_string(targets_file).await?;
        let capped: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).take(cap).collect();
        let cf = cfg.scans_dir.join("targets_capped.txt");
        tokio::fs::write(&cf, capped.join("\n")).await?;
        tracing::info!("budget: {host_count}→{cap} objetivos (cap @ {}/s)", cfg.rate_limit);
        (cf, cap)
    } else {
        (targets_file.to_path_buf(), host_count)
    };
    let targets_file = scan_file.as_path();

    let phases: Vec<(&str, &str)> = if cfg.no_priority_scan {
        vec![("ALL", "cve,rce,sqli,ssrf,lfi,cmdi,auth-bypass,takeover,xss,exposure,token,secret,config")]
    } else {
        vec![("CRITICAL", HIGH_PRIORITY_TAGS), ("HIGH", MEDIUM_PRIORITY_TAGS)]
    };

    let mut total = 0u64;
    for (i, (phase_name, tags)) in phases.iter().enumerate() {
        // ¿Cabe esta fase en lo que queda del presupuesto?
        let restante = deadline.map(|d| d.saturating_duration_since(std::time::Instant::now()).as_secs());
        let tope = match presupuesto_de_fase(restante, protection::phase_timeout(host_count, tags.split(',').count())) {
            Presupuesto::Correr(t) => t,
            Presupuesto::Saltar => {
                tracing::info!(
                    "presupuesto: quedan {}s, no arranco la fase {phase_name} ni las que falten; \
                     paso a verificar lo escaneado",
                    restante.unwrap_or(0)
                );
                break;
            }
        };
        match run_phase(cfg, pool, program, program_id, phase_name, tags, targets_file, host_count, tope).await {
            Ok((found, _bad)) => {
                total += found;
                guard.record_success();
            }
            Err(e) => {
                let wait = guard.record_failure();
                tracing::warn!("fase {phase_name} falló: {e}; backoff {wait}s");
                if guard.should_pause() {
                    tracing::error!("demasiados fallos seguidos: pausando (anti-baneo)");
                    let d = guard.cooldown(wait, rng());
                    tokio::time::sleep(d).await;
                }
            }
        }
        // cooldown entre fases (no tras la última), y solo si la próxima va a
        // correr: esperar un cooldown para luego saltar la fase es tiempo tirado.
        let próxima_cabe = deadline
            .map(|d| d.saturating_duration_since(std::time::Instant::now()).as_secs() >= MIN_FASE_SECS + cfg.phase_cooldown)
            .unwrap_or(true);
        if i + 1 < phases.len() && próxima_cabe {
            let d = guard.cooldown(cfg.phase_cooldown, rng());
            tracing::info!("cooldown de fase: {:.0}s", d.as_secs_f64());
            tokio::time::sleep(d).await;
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **El presupuesto decide bien las cuatro situaciones, y su pareja.**
    ///
    /// Es la lógica que hace que el ciclo quepa en su tiempo: sin ella, o corre a
    /// ciegas (y systemd lo mata), o se cierra de más. Se prueba pura —sin reloj,
    /// sin red— porque la decisión no depende de ninguno de los dos.
    #[test]
    fn el_presupuesto_acota_y_salta_pero_no_estrangula() {
        // Sin presupuesto: el timeout natural, intacto (NEXUS_SCAN_DEADLINE_SECS=0).
        assert_eq!(presupuesto_de_fase(None, 1384), Presupuesto::Correr(1384));

        // De sobra: su timeout natural, no lo infla.
        assert_eq!(presupuesto_de_fase(Some(3000), 1384), Presupuesto::Correr(1384));

        // Justo: queda menos que el natural -> se ACOTA al tiempo restante, que
        // es lo que impide el SIGKILL. nuclei sale con lo reunido.
        assert_eq!(presupuesto_de_fase(Some(900), 1384), Presupuesto::Correr(900));

        // Nada útil: se SALTA y se va a verificar lo escaneado.
        assert_eq!(presupuesto_de_fase(Some(30), 1384), Presupuesto::Saltar);

        // El borde exacto del mínimo: 60 corre (acotado), 59 salta. Un `<` mal
        // puesto se caza aquí.
        assert_eq!(presupuesto_de_fase(Some(MIN_FASE_SECS), 1384), Presupuesto::Correr(MIN_FASE_SECS));
        assert_eq!(presupuesto_de_fase(Some(MIN_FASE_SECS - 1), 1384), Presupuesto::Saltar);
    }

    /// La priorización se conserva: con presupuesto para UNA fase, es la CRÍTICA
    /// la que corre —va primera en la lista— y la HIGH la que se salta. La razón
    /// de las dos fases (crítico primero) sobrevive al recorte.
    #[test]
    fn con_una_sola_fase_de_presupuesto_corre_la_critica() {
        let fases = [("CRITICAL", HIGH_PRIORITY_TAGS), ("HIGH", MEDIUM_PRIORITY_TAGS)];
        // Presupuesto que da para la primera fase (techo 1384s) y deja menos que
        // el mínimo útil para la segunda: 1400 - 1384 = 16 < 60.
        let mut restante = 1400u64;
        let mut corridas = Vec::new();
        for (nombre, tags) in fases {
            let pt = protection::phase_timeout(38, tags.split(',').count());
            match presupuesto_de_fase(Some(restante), pt) {
                Presupuesto::Correr(t) => {
                    corridas.push(nombre);
                    restante = restante.saturating_sub(t); // como si consumiera su techo
                }
                Presupuesto::Saltar => break,
            }
        }
        assert_eq!(corridas, ["CRITICAL"], "corrió la crítica y paró antes de la HIGH");
    }

    #[test]
    fn parsea_jsonl_de_nuclei() {
        let line = r#"{"template-id":"CVE-2021-1234","info":{"severity":"critical"},"matched-at":"https://x.example.com/a"}"#;
        let f = parse_nuclei_line(line, "acme").unwrap();
        assert_eq!(f.vuln_name, "CVE-2021-1234");
        assert_eq!(f.severity, "critical");
        assert_eq!(f.url, "https://x.example.com/a");
        assert_eq!(f.program_name, "acme");
    }

    /// `parse_dast_line` CONSERVA la evidencia del fuzzing, y su pareja
    /// (directiva 33): `parse_nuclei_line` sobre la MISMA línea la DESCARTA. Si
    /// los dos hicieran lo mismo, la fase DAST persistiría hallazgos sin prueba
    /// (directiva 30). La línea es la salida REAL del positivo de control del
    /// 2026-08-23 (nuclei -dast contra el servidor vulnerable), recortada.
    #[test]
    fn dast_conserva_la_evidencia_de_fuzzing() {
        let line = r#"{"template-id":"reflected-xss","info":{"severity":"medium"},"matched-at":"http://t/search?q=x'\"><69093>","request":"GET /search?q=x HTTP/1.1","response":"HTTP/1.0 200 OK\r\n\r\n<html>x'\"><69093></html>","fuzzing_parameter":"q","fuzzing_position":"query","is_fuzzing_result":true}"#;
        let f = parse_dast_line(line, "acme").unwrap();
        assert_eq!(f.vuln_name, "reflected-xss");
        assert_eq!(f.severity, "medium");
        let ev = f.evidencia.expect("DAST DEBE traer evidencia");
        assert!(ev.contains("parámetro «q»"), "captura el parámetro fuzzeado: {ev}");
        assert!(ev.contains("petición") && ev.contains("respuesta"), "captura req/resp: {ev}");
        // La PAREJA: el parser de -tags sobre la misma línea NO guarda evidencia.
        assert!(parse_nuclei_line(line, "acme").unwrap().evidencia.is_none());
    }

    /// El invariante de seguridad de la fase DAST: `-no-interactsh` va SIEMPRE en
    /// los args, para no filtrar callbacks OAST a un interactsh de terceros. Su
    /// pareja (directiva 33): sin él, un refactor pasaría este assert solo si de
    /// verdad se emite. Comprueba además que se piden -dast y la exclusión de info.
    #[test]
    fn dast_args_siempre_excluye_interactsh() {
        use clap::Parser as _;
        let cfg = crate::config::Config::parse_from(["nexus", "scan"]);
        let args = dast_args(&cfg, std::path::Path::new("/tmp/t.txt"), "UA/1.0");
        assert!(args.iter().any(|a| a == "-no-interactsh"), "DEBE excluir interactsh (sin fuga OOB a terceros): {args:?}");
        assert!(args.iter().any(|a| a == "-dast"), "DEBE pedir el motor dast");
        // La agresión por defecto (low) llega al flag de nuclei.
        let i = args.iter().position(|a| a == "-fuzz-aggression").expect("pasa la agresión");
        assert_eq!(args[i + 1], "low");
    }

    /// El recorte no parte un char multibyte ni pierde el aviso de truncado.
    #[test]
    fn recorta_respeta_utf8_y_avisa() {
        let s = "áéíóú".repeat(1000); // multibyte, > DAST_EVIDENCIA_MAX
        let r = recorta(&s, DAST_EVIDENCIA_MAX);
        assert!(r.len() <= DAST_EVIDENCIA_MAX + 40, "recortado cerca del tope");
        assert!(r.contains("[+"), "avisa de lo truncado");
        assert!(std::str::from_utf8(r.as_bytes()).is_ok(), "sigue siendo UTF-8 válido");
        assert_eq!(recorta("corto", DAST_EVIDENCIA_MAX), "corto", "lo corto pasa intacto");
    }

    #[test]
    fn cae_a_host_si_no_hay_matched_at() {
        let line = r#"{"template-id":"exposure","info":{"severity":"low"},"host":"h.example.com"}"#;
        assert_eq!(parse_nuclei_line(line, "p").unwrap().url, "h.example.com");
    }

    #[test]
    fn rechaza_lineas_no_json() {
        assert!(parse_nuclei_line("no soy json", "p").is_none());
        assert!(parse_nuclei_line("", "p").is_none());
    }

    /// La regla de severidad y su pareja: lo pagable pasa, el ruido no. Sin el
    /// caso rojo (info→false) un filtro que dijera «sí» a todo pasaría igual.
    #[test]
    fn la_severidad_pagable_discrimina() {
        for s in ["critical", "high", "medium", "low", "CRITICAL", " High "] {
            assert!(es_severidad_pagable(s), "{s} es pagable en H1");
        }
        for s in ["info", "informational", "unknown", "", "  ", "INFO"] {
            assert!(!es_severidad_pagable(s), "{s:?} NO es pagable (no se almacena)");
        }
    }
}
