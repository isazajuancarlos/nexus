//! Capa de datos: pool SQLite + operaciones. Queries en runtime (no macros) para
//! no exigir una BD en tiempo de compilación — el binario se compila en cualquier
//! sitio y crea su propia base al arrancar.

use crate::error::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{FromRow, SqlitePool};
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Clone, FromRow)]
pub struct Finding {
    pub id: i64,
    pub program_name: Option<String>,
    pub vuln_name: String,
    pub vuln_type: Option<String>,
    pub severity: String,
    pub url: String,
    pub status: String,
    pub verified: i64,
    pub found_at: DateTime<Utc>,
}

/// Un hallazgo recién parseado de nuclei, aún sin persistir.
#[derive(Debug, Clone, Default)]
pub struct NewFinding {
    pub program_name: String,
    pub vuln_name: String,
    pub severity: String,
    pub url: String,
    pub cwe: Option<String>,
    /// Evidencia del hallazgo (CNAME→servicio del takeover, esquema GraphQL,
    /// metadata SSRF exfiltrada…). Sin esto la cola no es auditable (directiva 30):
    /// el ciclo del 2026-08-21 persistió el takeover de `try.cloudways.com` con
    /// `verification_evidence` NULL. nuclei no la trae (None).
    pub evidencia: Option<String>,
}

/// Abre (o crea) la base y aplica migraciones embebidas. `max_conns` acota la
/// concurrencia contra SQLite: en el VPS sin swap, pocas conexiones bastan.
pub async fn open(db_path: &Path, max_conns: u32) -> Result<SqlitePool> {
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .busy_timeout(std::time::Duration::from_secs(10));

    let pool = SqlitePoolOptions::new()
        .max_connections(max_conns)
        .connect_with(opts)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// Abre la BD AISLADA del colector OOB. Autocontenida: crea su tabla in situ (no
/// pasa por las migraciones de la BD principal), para que el colector público NO
/// abra jamás la BD de findings/clínica. WAL: el colector escribe y la sonda lee
/// concurrentemente. `max_conns` bajo: el colector solo hace INSERTs pequeños.
pub async fn open_oob(db_path: &Path, max_conns: u32) -> Result<SqlitePool> {
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .busy_timeout(std::time::Duration::from_secs(10));
    let pool = SqlitePoolOptions::new()
        .max_connections(max_conns)
        .connect_with(opts)
        .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS oob_hits (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            token       TEXT NOT NULL,
            source_ip   TEXT,
            method      TEXT,
            path        TEXT,
            user_agent  TEXT,
            created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS ix_oob_hits_token ON oob_hits(token)")
        .execute(&pool)
        .await?;
    Ok(pool)
}

/// Garantiza que un programa existe y devuelve su id. `GLOBAL_FEED` es el
/// programa por defecto al que cuelgan los hallazgos sin programa (modo sniper
/// de hacker/).
pub async fn upsert_program(pool: &SqlitePool, name: &str) -> Result<i64> {
    sqlx::query("INSERT INTO programs (name) VALUES (?1) ON CONFLICT(name) DO NOTHING")
        .bind(name)
        .execute(pool)
        .await?;
    let id: i64 = sqlx::query_scalar("SELECT id FROM programs WHERE name = ?1")
        .bind(name)
        .fetch_one(pool)
        .await?;
    Ok(id)
}

/// Inserta un hallazgo si es nuevo. Devuelve `true` si se insertó, `false` si ya
/// existía (dedup por índice único (url, vuln_name)). Esta es la operación que
/// más se ejecuta y la que debe DISCRIMINAR bien (directiva 8).
pub async fn insert_finding_dedup(pool: &SqlitePool, f: &NewFinding, program_id: i64) -> Result<bool> {
    let res = sqlx::query(
        // notified=0: nace PENDIENTE de notificar; el módulo `notify` lo envía al
        // cierre del ciclo si llega a VERIFIED/MANUAL_READY (antes era 1 fijo y
        // nadie lo consumía).
        "INSERT INTO findings (program_id, program_name, vuln_name, severity, url, cwe, verification_evidence, notified)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)
         ON CONFLICT(url, vuln_name) DO NOTHING",
    )
    .bind(program_id)
    .bind(&f.program_name)
    .bind(&f.vuln_name)
    .bind(&f.severity)
    .bind(&f.url)
    .bind(&f.cwe)
    .bind(&f.evidencia)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Carga las URLs SEMILLA de un programa: recursos PROPIOS del dueño que el recon
/// pasivo no descubre (privados). El motor autz las diffea junto con el corpus.
pub async fn cargar_semillas(pool: &SqlitePool, program: &str) -> Result<Vec<String>> {
    let filas: Vec<(String,)> = sqlx::query_as("SELECT url FROM autz_semillas WHERE program_name = ?1")
        .bind(program)
        .fetch_all(pool)
        .await?;
    Ok(filas.into_iter().map(|(u,)| u).collect())
}

/// Persiste una costura de control de acceso (motor `autz`) con su `vuln_type`.
/// NO marca `execution_confirmed`: una clase de detección NUEVA no se auto-envía
/// a H1 —va a revisión manual— hasta que la validación por reproducción la
/// respalde (el auto-envío se gatea sobre prueba de ejecución, y esta clase aún
/// no la tiene). Dedup por (url, vuln_name).
#[allow(clippy::too_many_arguments)]
pub async fn insert_costura(
    pool: &SqlitePool,
    program_id: i64,
    program: &str,
    url: &str,
    vuln_name: &str,
    vuln_type: &str,
    severity: &str,
    cwe: &str,
    // `true` = veredicto de confianza ALTA de autz (firma exacta: la otra
    // identidad vio EL MISMO recurso 2xx del dueño). Es un bypass PROBADO por
    // diferencial — tan fuerte como una XSS confirmada en navegador.
    confirmado: bool,
    // Evidencia a persistir: la técnica/diferencial que produjo el hallazgo. Sin
    // esto un MANUAL_READY es indistinguible del ruido y la cola no se puede
    // auditar (directiva 30) — el fallo medido el 2026-08-21 (12 findings, 0 con
    // evidencia). Para un ALTA confirmado se usa esta si viene, y si no el texto
    // por defecto.
    evidencia: Option<&str>,
) -> Result<bool> {
    // Un ALTA se inserta ya VERIFIED + execution_confirmed, para que el deepscan
    // genérico (que NO hace análisis diferencial) no lo degrade a MANUAL_READY
    // perdiendo la prueba que autz ya calculó. NO se auto-envía: control de acceso
    // no es clase pagable y estas van a severidad media — el auto-envío es una
    // decisión aparte. Confianza MEDIA → NEW (sigue al verificador, como antes).
    let (status, ev): (&str, Option<&str>) = if confirmado {
        (
            "VERIFIED",
            evidencia.or(Some("bypass de control de acceso confirmado por diferencial de identidad (firma exacta: otra identidad vio el mismo recurso 2xx del dueño)")),
        )
    } else {
        ("NEW", evidencia)
    };
    // Una costura CONFIRMADA (Alta) escribe su evidencia también en `raw_evidence`:
    // esa es la columna de PRUEBA CAPTURADA que exige la puerta de auto-envío
    // (`fetch_autosubmit`), y una costura vertical/fuga confirmada es severidad
    // ALTA → sí puede llegar al auto-envío. La evidencia de autz ES el diferencial
    // real (dueño/no-dueño/anónimo), no la palabra de una herramienta. Una MEDIA no
    // la puebla: no está confirmada (execution_confirmed=0 la frena igual).
    let raw_ev: Option<&str> = if confirmado { ev } else { None };
    let res = sqlx::query(
        "INSERT INTO findings (program_id, program_name, vuln_name, vuln_type, severity, url, cwe, notified,
                               status, verified, execution_confirmed, exploitable, verification_tool, verification_evidence, raw_evidence)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9, ?9, ?9, ?10, ?11, ?12)
         ON CONFLICT(url, vuln_name) DO NOTHING",
    )
    .bind(program_id)
    .bind(program)
    .bind(vuln_name)
    .bind(vuln_type)
    .bind(severity)
    .bind(url)
    .bind(cwe)
    .bind(status)
    .bind(confirmado as i64) // verified / execution_confirmed / exploitable (?9)
    .bind(if confirmado { Some("autz") } else { None })
    .bind(ev)
    .bind(raw_ev)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Hallazgos VERIFIED/MANUAL_READY que aún no se notificaron (para el webhook).
/// Solo esos dos estados: un NEW crudo de nuclei (sin verificar) o un
/// FALSE_POSITIVE no se anuncian. `notify` les da forma de mensaje.
pub async fn hallazgos_sin_notificar(
    pool: &SqlitePool,
) -> Result<Vec<crate::notify::HallazgoBreve>> {
    let filas: Vec<(String, Option<String>, String, String)> = sqlx::query_as(
        "SELECT severity, vuln_type, url, program_name FROM findings
         WHERE notified = 0 AND status IN ('VERIFIED', 'MANUAL_READY')
         ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    Ok(filas
        .into_iter()
        .map(
            |(severity, vuln_type, url, program_name)| crate::notify::HallazgoBreve {
                severity,
                vuln_type: vuln_type.unwrap_or_default(),
                url,
                program_name,
            },
        )
        .collect())
}

/// Marca como notificados los VERIFIED/MANUAL_READY pendientes. Se llama SOLO
/// tras un envío exitoso, con el mismo WHERE que `hallazgos_sin_notificar` (la
/// caza es proceso único: sin carrera entre leer y marcar). Devuelve cuántos.
pub async fn marcar_notificados(pool: &SqlitePool) -> Result<u64> {
    let res = sqlx::query(
        "UPDATE findings SET notified = 1
         WHERE notified = 0 AND status IN ('VERIFIED', 'MANUAL_READY')",
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Registra los assets vistos de un programa (ASM, 2.2) y devuelve
/// `(nuevos, era_primera_vez)`: los assets vistos por PRIMERA vez, y si el programa
/// no tenía histórico (para NO avisar de toda la superficie en la corrida inicial
/// — solo lo que APAREZCA después es superficie nueva). Actualiza `ultima_vez` de
/// los ya conocidos (dato que 2.3 usa para «dejó de aparecer»).
pub async fn registrar_assets(
    pool: &SqlitePool,
    program: &str,
    assets: &[String],
) -> Result<(Vec<String>, bool)> {
    let previos: Vec<String> =
        sqlx::query_scalar("SELECT asset FROM assets_historicos WHERE program_name = ?1")
            .bind(program)
            .fetch_all(pool)
            .await?;
    let era_primera = previos.is_empty();
    let conocidos: std::collections::HashSet<&str> = previos.iter().map(|s| s.as_str()).collect();
    let mut nuevos: Vec<String> = Vec::new();
    let mut vistos: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for a in assets {
        if a.is_empty() || !vistos.insert(a.as_str()) {
            continue; // dedup de la entrada
        }
        if !conocidos.contains(a.as_str()) {
            nuevos.push(a.clone());
        }
        sqlx::query(
            "INSERT INTO assets_historicos (program_name, asset) VALUES (?1, ?2)
             ON CONFLICT(program_name, asset) DO UPDATE SET ultima_vez = CURRENT_TIMESTAMP",
        )
        .bind(program)
        .bind(a)
        .execute(pool)
        .await?;
    }
    Ok((nuevos, era_primera))
}

/// Registra el inicio de un escaneo; devuelve el id del log para cerrarlo luego.
pub async fn scan_log_start(pool: &SqlitePool, program: &str, scan_type: &str, phase: &str) -> Result<i64> {
    let res = sqlx::query(
        "INSERT INTO scan_logs (program_name, scan_type, phase, status) VALUES (?1, ?2, ?3, 'running')",
    )
    .bind(program)
    .bind(scan_type)
    .bind(phase)
    .execute(pool)
    .await?;
    Ok(res.last_insert_rowid())
}

pub async fn scan_log_finish(pool: &SqlitePool, log_id: i64, status: &str, findings: i64, err: Option<&str>) -> Result<()> {
    sqlx::query(
        "UPDATE scan_logs SET status = ?2, findings_count = ?3, error_message = ?4, completed_at = CURRENT_TIMESTAMP WHERE id = ?1",
    )
    .bind(log_id)
    .bind(status)
    .bind(findings)
    .bind(err)
    .execute(pool)
    .await?;
    Ok(())
}

/// Reconcilia escaneos huérfanos: filas que quedaron en `'running'` porque el
/// proceso murió (SIGKILL de systemd al vencer `TimeoutStartSec`, OOM, crash)
/// ANTES de `scan_log_finish`. Sin esto, cada corrida abortada deja una fila en
/// `'running'` para siempre — contamina las estadísticas y el panel, y "sano y
/// quieto" (un escaneo vivo) pasa a verse igual que "muerto" (directiva 30). El
/// deadline blando (`NEXUS_SCAN_DEADLINE_SECS`) evita GENERARLos; esto limpia
/// los que ya hay y cubre lo que el deadline no puede (OOM, crash duro).
///
/// **Acotado a lo DEFINITIVAMENTE muerto** (directiva 22): solo toca filas cuyo
/// `started_at` es más viejo que `stale_secs`. Un escaneo vivo no puede durar
/// más de lo que su supervisor le permite (`TimeoutStartSec`), así que con
/// `stale_secs >= TimeoutStartSec` jamás se marca una fila EN CURSO — que es el
/// caso verde que la prueba exige preservar. Devuelve cuántas reconcilió.
pub async fn reconcile_orphaned_scans(pool: &SqlitePool, stale_secs: i64) -> Result<u64> {
    let res = sqlx::query(
        "UPDATE scan_logs
         SET status = 'interrupted',
             completed_at = CURRENT_TIMESTAMP,
             error_message = COALESCE(error_message, 'proceso terminado sin cerrar el escaneo; reconciliado al arranque')
         WHERE status = 'running'
           AND started_at < datetime(CURRENT_TIMESTAMP, '-' || ?1 || ' seconds')",
    )
    .bind(stale_secs)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Todos los hallazgos, ordenados para el informe.
pub async fn all_findings(pool: &SqlitePool) -> Result<Vec<Finding>> {
    let rows = sqlx::query_as::<_, Finding>(
        "SELECT id, program_name, vuln_name, vuln_type, severity, url, status, verified, found_at FROM findings",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn count_findings(pool: &SqlitePool) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM findings").fetch_one(pool).await?)
}

/// Un hallazgo pendiente de verificación profunda.
#[derive(Debug, Clone, FromRow)]
pub struct PendingFinding {
    pub id: i64,
    pub vuln_name: String,
    pub url: String,
    pub retry_count: i64,
    pub max_retries: i64,
}

/// Hallazgos por verificar: nuevos, o pendientes de reintento cuya hora ya venció.
pub async fn fetch_verifiable(pool: &SqlitePool, limit: i64) -> Result<Vec<PendingFinding>> {
    let rows = sqlx::query_as::<_, PendingFinding>(
        "SELECT id, vuln_name, url, retry_count, max_retries FROM findings
         WHERE status = 'NEW'
            OR (status = 'RETRY_PENDING' AND (next_retry_at IS NULL OR next_retry_at <= CURRENT_TIMESTAMP))
         ORDER BY id LIMIT ?1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Un hallazgo en MANUAL_READY, con lo que el gate de elegibilidad necesita.
#[derive(Debug, Clone, FromRow)]
pub struct HallazgoManual {
    pub id: i64,
    pub program_name: String,
    pub vuln_name: String,
    pub url: String,
    pub cwe: Option<String>,
    pub severity: String,
}

/// Los hallazgos que esperan veredicto humano (MANUAL_READY). Solo lectura.
pub async fn fetch_manual_ready(pool: &SqlitePool) -> Result<Vec<HallazgoManual>> {
    let rows = sqlx::query_as::<_, HallazgoManual>(
        "SELECT id, COALESCE(program_name, '') AS program_name, vuln_name, url, cwe, severity
         FROM findings WHERE status = 'MANUAL_READY' ORDER BY program_name, id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Hallazgos que llevan en MANUAL_READY más de `max_dias` sin resolverse (por
/// `found_at`). El reloj terminal los cierra: en 24/7 nadie los revisa. Devuelve
/// (id, vuln_name) para poder registrar qué se cerró (directiva 20).
pub async fn fetch_manual_ready_vencidos(pool: &SqlitePool, max_dias: u64) -> Result<Vec<(i64, String)>> {
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, vuln_name FROM findings
         WHERE status = 'MANUAL_READY'
           AND found_at < datetime('now', printf('-%d days', ?1))
         ORDER BY found_at",
    )
    .bind(max_dias as i64)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Resuelve un hallazgo a INFORMATIONAL por decisión autónoma del ciclo (gate de
/// elegibilidad H1, clase informativa, o reloj terminal). NO borra —reclasifica— y guarda el
/// motivo en `verification_evidence` (directiva 20: no se pierde en silencio,
/// queda auditable y reversible). Solo actúa sobre filas que siguen en
/// MANUAL_READY (idempotente entre ciclos).
pub async fn descartar_por_elegibilidad(pool: &SqlitePool, id: i64, motivo: &str) -> Result<()> {
    sqlx::query(
        "UPDATE findings
         SET status = 'INFORMATIONAL', verification_evidence = ?2
         WHERE id = ?1 AND status = 'MANUAL_READY'",
    )
    .bind(id)
    .bind(format!("resolución autónoma: {motivo}"))
    .execute(pool)
    .await?;
    Ok(())
}

/// Persiste el resultado de una verificación. `execution_confirmed` (ejecución/
/// reproducción probada) y `repro_ratio` ("aciertos/intentos") son lo que habilita
/// el auto-envío — se escriben siempre, incluido el 0, para que un hallazgo viejo
/// no herede un `execution_confirmed` de una corrida anterior (directiva 32).
#[allow(clippy::too_many_arguments)]
pub async fn apply_verification(
    pool: &SqlitePool,
    id: i64,
    status: &str,
    verified: bool,
    tool: &str,
    confidence: &str,
    exploitable: bool,
    evidence: Option<&str>,
    vuln_type: &str,
    raw_evidence: Option<&str>,
    execution_confirmed: bool,
    repro_ratio: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "UPDATE findings SET status = ?2, verified = ?3, verification_tool = ?4,
             verification_confidence = ?5, exploitable = ?6, verification_evidence = ?7,
             vuln_type = ?8, raw_evidence = COALESCE(?9, raw_evidence),
             execution_confirmed = ?10, repro_ratio = COALESCE(?11, repro_ratio),
             verified_at = CURRENT_TIMESTAMP
         WHERE id = ?1",
    )
    .bind(id)
    .bind(status)
    .bind(verified as i64)
    .bind(tool)
    .bind(confidence)
    .bind(exploitable as i64)
    .bind(evidence)
    .bind(vuln_type)
    .bind(raw_evidence)
    .bind(execution_confirmed as i64)
    .bind(repro_ratio)
    .execute(pool)
    .await?;
    Ok(())
}

/// Fila para generar informes de envío (F6) y evidencia (F5).
#[derive(Debug, Clone, FromRow)]
pub struct VerifiedRow {
    pub id: i64,
    pub program_name: Option<String>,
    pub vuln_name: String,
    pub vuln_type: Option<String>,
    pub severity: String,
    pub url: String,
    pub verified: i64,
    pub verification_tool: Option<String>,
    pub verification_confidence: Option<String>,
    pub exploitable: i64,
    pub verification_evidence: Option<String>,
    pub raw_evidence: Option<String>,
    pub cwe: Option<String>,
    /// NEXUS lo vio ejecutar/reproducir (no la palabra de la herramienta). Alimenta
    /// el certificado anti-slop de `submitter::build_submission` (2026-09-05).
    pub execution_confirmed: i64,
    /// Control diferencial reproducible ("aciertos/intentos", p. ej. "3/3").
    pub repro_ratio: Option<String>,
}

/// Hallazgos verificados (para submitter y evidencia), ordenados por grupo.
pub async fn verified_findings(pool: &SqlitePool) -> Result<Vec<VerifiedRow>> {
    let rows = sqlx::query_as::<_, VerifiedRow>(
        "SELECT id, program_name, vuln_name, vuln_type, severity, url, verified,
                verification_tool, verification_confidence, exploitable, verification_evidence, raw_evidence, cwe,
                execution_confirmed, repro_ratio
         FROM findings
         WHERE status = 'VERIFIED' OR verified = 1
         ORDER BY program_name, vuln_name, id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// ---- Atribución a programa H1 y auto-envío ----

/// Programa con su handle de H1 (name = handle para la fuente H1).
pub async fn upsert_program_handle(pool: &SqlitePool, name: &str, handle: &str) -> Result<i64> {
    sqlx::query(
        "INSERT INTO programs (name, h1_handle) VALUES (?1, ?2)
         ON CONFLICT(name) DO UPDATE SET h1_handle = ?2",
    )
    .bind(name)
    .bind(handle)
    .execute(pool)
    .await?;
    let id: i64 = sqlx::query_scalar("SELECT id FROM programs WHERE name = ?1")
        .bind(name)
        .fetch_one(pool)
        .await?;
    Ok(id)
}

/// Siembra programas PÚBLICOS de Intigriti (del feed de arkadiyt) como
/// ciudadanos de 1ª en la cola de caza. `name = "intigriti:{handle}"` evita
/// colisión con un handle homónimo de H1; `platform='intigriti'` y `external_id`
/// = GUID nativo. El scope viene del FEED (Intigriti no tiene API sin token), así
/// que se guarda ya en `program_scopes` y el recon lo lee de ahí (Source::
/// Almacenado) en vez de llamar a ninguna API. Idempotente: refresca plataforma,
/// GUID y scope; devuelve cuántos programas eran NUEVOS.
pub async fn seed_intigriti_programs(
    pool: &SqlitePool,
    programas: &[crate::sources::ProgramaIntigriti],
) -> Result<usize> {
    let mut nuevos = 0usize;
    for p in programas {
        let name = format!("intigriti:{}", p.handle);
        let r = sqlx::query(
            "INSERT INTO programs (name, platform, external_id, status)
             VALUES (?1, 'intigriti', ?2, 'Pending')
             ON CONFLICT(name) DO NOTHING",
        )
        .bind(&name)
        .bind(&p.guid)
        .execute(pool)
        .await?;
        nuevos += r.rows_affected() as usize;
        // Mantener plataforma/GUID al día aunque el programa ya existiera.
        sqlx::query("UPDATE programs SET platform = 'intigriti', external_id = ?2 WHERE name = ?1")
            .bind(&name)
            .bind(&p.guid)
            .execute(pool)
            .await?;
        let pid: i64 = sqlx::query_scalar("SELECT id FROM programs WHERE name = ?1")
            .bind(&name)
            .fetch_one(pool)
            .await?;
        // Refrescar el scope ENTERO de este programa (directiva 22: acotado a él).
        clear_scopes_for_program(pool, pid).await?;
        for d in &p.scope {
            insert_scope(pool, pid, &d.identifier, d.is_wildcard, None).await?;
        }
    }
    Ok(nuevos)
}

/// Dominios raíz del scope guardado de UN programa (por nombre). Es la fuente de
/// recon para los programas cuyo scope NO viene de una API sino del feed
/// (Intigriti): ya está en `program_scopes`, se lee y se enumera.
pub async fn scope_roots_for_program(pool: &SqlitePool, name: &str) -> Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT ps.asset_identifier FROM program_scopes ps
         JOIN programs p ON p.id = ps.program_id
         WHERE p.name = ?1",
    )
    .bind(name)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(s,)| s).collect())
}

// ---- Scheduling por BD del cazador (Sc1) ----

pub async fn count_programs(pool: &SqlitePool) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM programs WHERE h1_handle IS NOT NULL").fetch_one(pool).await?)
}

/// Siembra handles como programas Pending (idempotente).
/// Carga el juego de identidades de un programa para el motor `autz`. Un papel
/// desconocido o unas cabeceras mal formadas son error RUIDOSO (directiva 20):
/// esta tabla la llena Juan a mano, y un juego a medias que "corre" sería peor
/// que uno que falla. Devuelve vacío si el programa no tiene identidades (el
/// motor lo salta), que es distinto de un error.
pub async fn cargar_identidades(
    pool: &SqlitePool,
    program: &str,
) -> Result<Vec<crate::autz::Identidad>> {
    let filas: Vec<(String, String)> = sqlx::query_as(
        "SELECT papel, cabeceras FROM identidades WHERE program_name = ?1 ORDER BY papel",
    )
    .bind(program)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(filas.len());
    for (papel_s, cab_s) in filas {
        let papel = crate::autz::Papel::desde_str(&papel_s).ok_or_else(|| {
            crate::error::NexusError::Other(format!(
                "identidad con papel desconocido '{papel_s}' en programa '{program}' (usa dueno|par|menor|anonimo)"
            ))
        })?;
        let cabeceras: Vec<(String, String)> = serde_json::from_str(&cab_s)?;
        out.push(crate::autz::Identidad { papel, cabeceras });
    }
    Ok(out)
}

/// Monta (o REEMPLAZA) una identidad del juego autz de un programa. Las cabeceras
/// se guardan como JSON `[[clave,valor],…]` — el MISMO formato que `cargar_identidades`
/// lee, así que lo que entra por aquí sale por allá sin traducción. `UPSERT` por
/// (program_name, papel): volver a montar el mismo papel ROTA la credencial vieja
/// en vez de duplicarla (un token caduca; montar otra vez es lo natural). Devuelve
/// `true` si actualizó una fila existente, `false` si insertó una nueva.
pub async fn guardar_identidad(
    pool: &SqlitePool,
    program: &str,
    papel: crate::autz::Papel,
    cabeceras: &[(String, String)],
) -> Result<bool> {
    let cab_json = serde_json::to_string(cabeceras)?;
    // ¿ya existía? (para informar ROTACIÓN vs alta, no para decidir el escritura).
    let previa: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM identidades WHERE program_name = ?1 AND papel = ?2")
            .bind(program)
            .bind(papel.a_str())
            .fetch_optional(pool)
            .await?;
    sqlx::query(
        "INSERT INTO identidades (program_name, papel, cabeceras) VALUES (?1, ?2, ?3)
         ON CONFLICT(program_name, papel) DO UPDATE SET cabeceras = excluded.cabeceras",
    )
    .bind(program)
    .bind(papel.a_str())
    .bind(&cab_json)
    .execute(pool)
    .await?;
    Ok(previa.is_some())
}

/// Borra una identidad (por papel) del juego de un programa. Devuelve `true` si
/// borró algo. Reversible en el sentido operativo: se vuelve a montar con
/// `guardar_identidad`.
pub async fn borrar_identidad(
    pool: &SqlitePool,
    program: &str,
    papel: crate::autz::Papel,
) -> Result<bool> {
    let res = sqlx::query("DELETE FROM identidades WHERE program_name = ?1 AND papel = ?2")
        .bind(program)
        .bind(papel.a_str())
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Lista los papeles montados de un programa (sin volcar las cabeceras: son
/// secretos, y listar no es exportar). Orden estable por papel.
pub async fn listar_identidades(pool: &SqlitePool, program: &str) -> Result<Vec<String>> {
    let filas: Vec<(String,)> =
        sqlx::query_as("SELECT papel FROM identidades WHERE program_name = ?1 ORDER BY papel")
            .bind(program)
            .fetch_all(pool)
            .await?;
    Ok(filas.into_iter().map(|(p,)| p).collect())
}

/// Añade una URL semilla al juego autz de un programa. Dedup por (program, url):
/// añadir la misma dos veces es no-op. Devuelve `true` si insertó una nueva.
pub async fn guardar_semilla(pool: &SqlitePool, program: &str, url: &str) -> Result<bool> {
    let res = sqlx::query(
        "INSERT INTO autz_semillas (program_name, url) VALUES (?1, ?2)
         ON CONFLICT(program_name, url) DO NOTHING",
    )
    .bind(program)
    .bind(url)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn seed_programs_pending(pool: &SqlitePool, handles: &[String]) -> Result<usize> {
    let mut n = 0;
    for h in handles {
        // DO NOTHING (no DO UPDATE): un `ON CONFLICT DO UPDATE` cuenta como fila
        // afectada aunque la fila ya existiera, así que `rows_affected` diría 592
        // "nuevos" cuando solo 368 lo eran —y un sync que grita eso cada día
        // entierra la señal de que UNO nuevo llegó de verdad (directiva 20/23).
        // El `SET h1_handle = ?1` era además un no-op: name == h1_handle siempre.
        let r = sqlx::query(
            "INSERT INTO programs (name, h1_handle, status) VALUES (?1, ?1, 'Pending')
             ON CONFLICT(name) DO NOTHING",
        )
        .bind(h)
        .execute(pool)
        .await?;
        n += r.rows_affected() as usize;
    }
    Ok(n)
}

/// Elige el programa menos-reciente para cazar (nunca-escaneados primero;
/// salta los ScopeBlocked), pero DEPRIORITIZA los "estériles": los que acumulan
/// `quarantine_timeouts` o más escaneos no-completados (timeout/interrupted/
/// failed/no_live) SIN un solo `completed`. Ése es el patrón de coupang_tw —59
/// escaneos, 0 completados— que quemaba presupuesto reintentándose por delante de
/// programas frescos.
///
/// Es deprioritización, no exclusión: el estéril sigue en la cola y se reintenta
/// cuando todos los sanos están más recientes que él. Y es **auto-sanable**
/// (directiva 22, no cerrar de más): en cuanto ese programa completa UN escaneo,
/// `SUM(completed)=0` deja de cumplirse y vuelve a la prioridad normal — no hace
/// falta levantar la cuarentena a mano ni un barrido aparte. Se deriva de
/// `scan_logs`, así que no necesita columna ni migración (directiva 32: el valor
/// se calcula de su fuente, no se almacena duplicado).
///
/// Devuelve `(name, platform)`: el `name` es la identidad UNIVERSAL del programa
/// (H1 lo pone = handle; Intigriti = `intigriti:{slug}`), y `platform` le dice al
/// cazador CÓMO obtener el scope (API de H1 vs scope ya almacenado del feed).
pub async fn next_program_to_hunt(
    pool: &SqlitePool,
    quarantine_timeouts: i64,
    fresh_window_days: i64,
) -> Result<Option<(String, String)>> {
    // El orden tiene CUATRO niveles, y cada uno gana al siguiente:
    //   1. estéril al fondo — cuarentena, ya existente;
    //   2. BLANDO al frente — paga (eligible_for_bounty) Y tiene superficie amplia
    //      (un scope wildcard). Es el SESGO A OBJETIVOS BLANDOS (2026-08-25): de 651
    //      huntables solo ~145 pagan y tienen wildcard, y ahí es donde una clase
    //      commodity (nuclei/XSS/SSRF) tiene chance de un rincón sin endurecer —
    //      medido que sobre objetivos maduros grandes da 0 aun con superficie. El
    //      round-robin de abajo rota DENTRO del tier, así no se re-caza el mismo;
    //   3. FRESCO al frente — dentro de `fresh_window_days` desde `created_at`;
    //   4. menos-reciente — round-robin por `last_scanned` (NULL primero).
    // El sesgo es SUAVE (un tier del ORDER BY, no un filtro): cuando los blandos ya
    // se cazaron hace poco, cae a los demás. Con `fresh_window_days = 0` el nivel 3
    // es constante.
    //
    // Huntable = tiene identidad escaneable: un handle de H1, O una plataforma
    // que no es hackerone (Intigriti, cuyo scope vive en program_scopes). La
    // cuarentena se une a scan_logs por `p.name` (universal), no por h1_handle,
    // que es NULL para Intigriti.
    let fila: Option<(String, String)> = sqlx::query_as(
        "SELECT name, platform FROM programs p
         WHERE status != 'ScopeBlocked'
           AND (h1_handle IS NOT NULL OR platform != 'hackerone')
         ORDER BY
           COALESCE((
             SELECT SUM(CASE WHEN status IN ('timeout','interrupted','failed','no_live') THEN 1 ELSE 0 END) >= ?1
                    AND SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) = 0
             FROM scan_logs s WHERE s.program_name = p.name
           ), 0) ASC,
           CASE WHEN EXISTS(
             SELECT 1 FROM program_scopes ps
             WHERE ps.program_id = p.id AND ps.eligible_for_bounty = 1 AND ps.is_wildcard = 1
           ) THEN 0 ELSE 1 END ASC,
           CASE WHEN ?2 > 0 AND created_at >= datetime('now', printf('-%d days', ?2))
                THEN 0 ELSE 1 END ASC,
           last_scanned ASC
         LIMIT 1",
    )
    .bind(quarantine_timeouts)
    .bind(fresh_window_days)
    .fetch_optional(pool)
    .await?;
    Ok(fila)
}

/// Marca un programa como escaneado (last_scanned=ahora) con su estado final.
/// Clavea por `name` (universal): h1_handle es NULL para los de Intigriti.
pub async fn mark_program_scanned(pool: &SqlitePool, name: &str, status: &str) -> Result<()> {
    sqlx::query("UPDATE programs SET last_scanned = CURRENT_TIMESTAMP, status = ?2 WHERE name = ?1")
        .bind(name)
        .bind(status)
        .execute(pool)
        .await?;
    Ok(())
}

/// Borra todos los scopes (recon completo los regenera enteros — directiva 22).
pub async fn clear_scopes(pool: &SqlitePool) -> Result<()> {
    sqlx::query("DELETE FROM program_scopes").execute(pool).await?;
    Ok(())
}

/// Borra el scope de UN programa (recon acotado con --only refresca solo ese,
/// sin tocar el de los demás — clave para el cazador que rota programa a programa).
pub async fn clear_scopes_for_program(pool: &SqlitePool, program_id: i64) -> Result<()> {
    sqlx::query("DELETE FROM program_scopes WHERE program_id = ?1")
        .bind(program_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Guarda una regla de scope de un programa, con su id de regla de H1.
pub async fn insert_scope(pool: &SqlitePool, program_id: i64, asset_identifier: &str, is_wildcard: bool, h1_scope_id: Option<&str>) -> Result<()> {
    sqlx::query(
        "INSERT INTO program_scopes (program_id, asset_identifier, asset_type, eligible_for_bounty, is_wildcard, base_domain, h1_scope_id)
         VALUES (?1, ?2, 'DOMAIN', 1, ?3, ?2, ?4)",
    )
    .bind(program_id)
    .bind(asset_identifier)
    .bind(is_wildcard as i64)
    .bind(h1_scope_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Inserta un scope ESTRUCTURADO de H1 con su `asset_type` REAL (URL, WILDCARD,
/// DOMAIN, CIDR, **SOURCE_CODE**…), a diferencia de `insert_scope` que asume DOMAIN.
/// Persistir el `asset_type` es lo que permite clasificar un programa por si su
/// CÓDIGO FUENTE está en scope (la señal del método whitebox) y si paga por él.
pub async fn insert_structured_scope(
    pool: &SqlitePool,
    program_id: i64,
    asset_identifier: &str,
    asset_type: &str,
    eligible_for_bounty: bool,
    is_wildcard: bool,
    h1_scope_id: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO program_scopes (program_id, asset_identifier, asset_type, eligible_for_bounty, is_wildcard, base_domain, h1_scope_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?2, ?6)",
    )
    .bind(program_id)
    .bind(asset_identifier)
    .bind(asset_type)
    .bind(eligible_for_bounty as i64)
    .bind(is_wildcard as i64)
    .bind(h1_scope_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Todos los programas de HackerOne (id, name, h1_handle). Para barridos por programa
/// —p. ej. bajar las structured scopes de cada uno—.
pub async fn all_h1_programs(pool: &SqlitePool) -> Result<Vec<(i64, String, Option<String>)>> {
    Ok(sqlx::query_as(
        "SELECT id, name, h1_handle FROM programs WHERE platform = 'hackerone' ORDER BY id",
    )
    .fetch_all(pool)
    .await?)
}

/// Marca el estado del scope de un programa y sella `scope_fetched_at`.
/// (`pending|fetched|error|no_credentials`). Primer escritor real de estas columnas.
pub async fn set_scope_status(pool: &SqlitePool, program_id: i64, status: &str) -> Result<()> {
    sqlx::query("UPDATE programs SET scope_status = ?1, scope_fetched_at = CURRENT_TIMESTAMP WHERE id = ?2")
        .bind(status)
        .bind(program_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// (h1_scope_id, asset_identifier, is_wildcard) de TODO el scope guardado.
/// Para filtrar targets a in-scope y resolver el structured_scope_id de un host.
pub async fn scope_rules_with_id(pool: &SqlitePool) -> Result<Vec<(Option<String>, String, bool)>> {
    let rows: Vec<(Option<String>, String, i64)> = sqlx::query_as(
        "SELECT h1_scope_id, asset_identifier, is_wildcard FROM program_scopes",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(id, a, w)| (id, a, w != 0)).collect())
}

/// Reglas de scope SOLO de los programas dados. Es la versión acotada de
/// `scope_rules_with_id`: el filtro de recon del ciclo debe usar el scope del
/// programa que se está cazando, NO el catálogo global — o un host de OTRO programa
/// (p. ej. linkedin durante el ciclo de intigriti) pasa el filtro y se atribuye al
/// programa equivocado, arriesgando un reporte FUERA DE SCOPE (bug medido 2026-08-27).
///
/// CLAVE = `programs.name` (la MISMA que `cmd_hunt` fija en `cfg.only` y que usa la
/// atribución del finding). NO filtrar por `h1_handle`: es NULL para Intigriti y
/// rompería el fail-closed de su caza (0 reglas → 0 objetivos). Todo el fix se apoya
/// en que `c.only`, `scope_roots_for_program` y esta función clavan sobre `name`.
pub async fn scope_rules_for_programs(
    pool: &SqlitePool,
    programas: &[String],
) -> Result<Vec<(Option<String>, String, bool)>> {
    let rows: Vec<(String, Option<String>, String, i64)> = sqlx::query_as(
        "SELECT p.name, s.h1_scope_id, s.asset_identifier, s.is_wildcard
         FROM program_scopes s JOIN programs p ON s.program_id = p.id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter(|(name, ..)| programas.iter().any(|p| p == name))
        .map(|(_, id, a, w)| (id, a, w != 0))
        .collect())
}

/// (handle, h1_scope_id, asset_identifier, is_wildcard) — para atribuir un host a
/// su programa Y a su regla de scope (structured_scope_id) en el envío.
pub async fn scope_rules_full(pool: &SqlitePool) -> Result<Vec<(String, Option<String>, String, bool)>> {
    let rows: Vec<(String, Option<String>, String, i64)> = sqlx::query_as(
        "SELECT p.h1_handle, s.h1_scope_id, s.asset_identifier, s.is_wildcard
         FROM program_scopes s JOIN programs p ON s.program_id = p.id
         WHERE p.h1_handle IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(h, sid, a, w)| (h, sid, a, w != 0)).collect())
}

/// Carga (handle, asset_identifier, is_wildcard) para atribuir hosts a programas.
pub async fn load_scope_rules(pool: &SqlitePool) -> Result<Vec<(String, String, bool)>> {
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT p.h1_handle, s.asset_identifier, s.is_wildcard
         FROM program_scopes s JOIN programs p ON s.program_id = p.id
         WHERE p.h1_handle IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(h, a, w)| (h, a, w != 0)).collect())
}

/// Candidatos a auto-envío. Gate estricto: ningún humano revisa antes del POST a
/// H1, así que el listón es EJECUCIÓN PROBADA, no la palabra de la herramienta.
///   - `execution_confirmed = 1`: lo vimos ejecutar/reproducir (navegador real para
///     XSS; sqlmap/commix que explotan; re-fetch reproducible). Es el gate que
///     cierra el hueco del FP #11 (reflexión inerte marcada "verified" por xsstrike).
///   - `status = 'VERIFIED'`: solo el veredicto definitivo (antes se colaba
///     MANUAL_READY, más laxo de lo que decía el comentario).
///   - explotable, verificador real (no manual/nuclei), severidad crítica/alta, no reportado.
pub async fn fetch_autosubmit(pool: &SqlitePool) -> Result<Vec<VerifiedRow>> {
    let rows = sqlx::query_as::<_, VerifiedRow>(
        "SELECT id, program_name, vuln_name, vuln_type, severity, url, verified,
                verification_tool, verification_confidence, exploitable, verification_evidence, raw_evidence, cwe,
                execution_confirmed, repro_ratio
         FROM findings
         WHERE status = 'VERIFIED'
               AND execution_confirmed = 1
               AND report_id IS NULL
               AND exploitable = 1
               AND verification_tool IS NOT NULL
               AND LOWER(verification_tool) NOT IN ('none', '', 'batch', 'manual')
               AND LOWER(severity) IN ('critical', 'high')
               -- PUERTA DE EVIDENCIA (transversal, 2026-08-24): ningún humano
               -- revisa antes del POST a H1, así que sin evidencia CAPTURADA no se
               -- envía. Cierra el hueco del FP medido (46 'IDOR' con evidencia
               -- vacía). Aplica a TODAS las clases, no solo a autz.
               AND raw_evidence IS NOT NULL
               -- TRIM con set explicito de blancos: el TRIM de SQLite sin segundo
               -- argumento recorta SOLO el espacio U+0020, asi que un relleno de
               -- tabs/newlines/CR pasaria. Recortamos los cuatro (obs. de la revision).
               AND LENGTH(TRIM(raw_evidence, ' ' || char(9) || char(10) || char(13))) > 0
         ORDER BY exploitable DESC, id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// ¿Ya se envió a H1 un hallazgo de este (programa, vuln_name)? Evita duplicados
/// ENTRE CICLOS: el dedup interno por (url, vuln_name) no cubre el mismo problema
/// en una URL nueva; H1 cierra los duplicados como "duplicate" y eso quema señal
/// en el programa — lo contrario de "aceptado". La atribución del auto-envío
/// consulta esto antes de cada POST.
pub async fn already_reported(pool: &SqlitePool, program_name: &str, vuln_name: &str) -> Result<bool> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM findings
         WHERE report_id IS NOT NULL
           AND COALESCE(program_name, '') = ?1
           AND vuln_name = ?2",
    )
    .bind(program_name)
    .bind(vuln_name)
    .fetch_one(pool)
    .await?;
    Ok(n > 0)
}

/// Cuántos reportes se auto-enviaron en las últimas `hours` horas. Para el tope
/// diario anti-baneo (no inundar H1 aunque haya muchos candidatos).
pub async fn count_submitted_since(pool: &SqlitePool, hours: i64) -> Result<i64> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM findings
         WHERE report_id IS NOT NULL
           AND h1_submitted_at >= datetime(CURRENT_TIMESTAMP, '-' || ?1 || ' hours')",
    )
    .bind(hours)
    .fetch_one(pool)
    .await?;
    Ok(n)
}

/// Cuántos reportes PROPIOS ya enviados están en un estado que H1 penaliza en el
/// Signal (duplicate/informative/not-applicable/spam). El cortacircuitos del
/// auto-envío pausa si esto cruza el umbral: reacciona a la señal del propio H1,
/// que es la defensa anti-baneo más fuerte. `h1_state` lo actualiza `sync`.
pub async fn count_bad_signal(pool: &SqlitePool) -> Result<i64> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM findings
         WHERE report_id IS NOT NULL
           AND LOWER(COALESCE(h1_state, '')) IN
               ('duplicate', 'informative', 'not-applicable', 'not_applicable', 'n/a', 'spam')",
    )
    .fetch_one(pool)
    .await?;
    Ok(n)
}

/// Marca un hallazgo como reportado con el id devuelto por H1.
pub async fn mark_reported(pool: &SqlitePool, id: i64, report_id: &str) -> Result<()> {
    sqlx::query(
        "UPDATE findings SET status = 'REPORTED', report_id = ?2, h1_state = 'new',
             h1_submitted_at = CURRENT_TIMESTAMP WHERE id = ?1",
    )
    .bind(id)
    .bind(report_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// (id, report_id) de los hallazgos ya enviados a H1 (para `sync`).
pub async fn submitted_findings(pool: &SqlitePool) -> Result<Vec<(i64, String)>> {
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, report_id FROM findings WHERE report_id IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Actualiza el estado en H1 y el bounty cobrado de un hallazgo enviado.
pub async fn update_h1_state(pool: &SqlitePool, id: i64, state: &str, bounty: Option<&str>) -> Result<()> {
    sqlx::query("UPDATE findings SET h1_state = ?2, bounty_amount = COALESCE(?3, bounty_amount) WHERE id = ?1")
        .bind(id)
        .bind(state)
        .bind(bounty)
        .execute(pool)
        .await?;
    Ok(())
}

/// Estadísticas del panel (F7).
#[derive(Debug, Default, Serialize, FromRow)]
pub struct DashStats {
    pub total: i64,
    pub verified: i64,
    pub exploitable: i64,
    pub false_positive: i64,
    pub manual: i64,
    pub retry: i64,
}

pub async fn dashboard_stats(pool: &SqlitePool) -> Result<DashStats> {
    let s = sqlx::query_as::<_, DashStats>(
        "SELECT
            COUNT(*) AS total,
            COALESCE(SUM(verified), 0) AS verified,
            COALESCE(SUM(exploitable), 0) AS exploitable,
            COALESCE(SUM(status = 'FALSE_POSITIVE'), 0) AS false_positive,
            COALESCE(SUM(status = 'MANUAL_READY'), 0) AS manual,
            COALESCE(SUM(status = 'RETRY_PENDING'), 0) AS retry
         FROM findings",
    )
    .fetch_one(pool)
    .await?;
    Ok(s)
}

/// Hallazgo serializable para la API del panel.
#[derive(Debug, Serialize, FromRow)]
pub struct FindingApi {
    pub vuln_name: String,
    pub severity: String,
    pub url: String,
    pub status: String,
    pub verified: i64,
    pub verification_tool: Option<String>,
}

pub async fn findings_for_api(pool: &SqlitePool, limit: i64) -> Result<Vec<FindingApi>> {
    let rows = sqlx::query_as::<_, FindingApi>(
        "SELECT vuln_name, severity, url, status, verified, verification_tool
         FROM findings ORDER BY id DESC LIMIT ?1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Fija la ruta del archivo de evidencia (screenshot) de un hallazgo.
pub async fn set_evidence(pool: &SqlitePool, id: i64, path: &str) -> Result<()> {
    sqlx::query("UPDATE findings SET verification_evidence = ?2 WHERE id = ?1")
        .bind(id)
        .bind(path)
        .execute(pool)
        .await?;
    Ok(())
}

/// Marca un reintento: incrementa el contador y fija la próxima hora (segundos
/// desde ahora) usando la aritmética de SQLite.
pub async fn schedule_retry(pool: &SqlitePool, id: i64, wait_secs: u64) -> Result<()> {
    sqlx::query(
        "UPDATE findings SET status = 'RETRY_PENDING', retry_count = retry_count + 1,
             next_retry_at = datetime(CURRENT_TIMESTAMP, '+' || ?2 || ' seconds')
         WHERE id = ?1",
    )
    .bind(id)
    .bind(wait_secs as i64)
    .execute(pool)
    .await?;
    Ok(())
}

/// Registra un CALLBACK recibido por el colector out-of-band (`nexus oob-server`).
/// El colector escribe; la sonda SSRF (otro proceso) consulta con `oob_hit_exists`.
/// Comparten la BD en WAL. No falla ruidoso: un hit no registrado se pierde, pero
/// no debe tumbar el colector público (se traga el error de escritura y sigue).
pub async fn record_oob_hit(
    pool: &SqlitePool,
    token: &str,
    source_ip: &str,
    method: &str,
    path: &str,
    user_agent: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO oob_hits (token, source_ip, method, path, user_agent)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(token)
    .bind(source_ip)
    .bind(method)
    .bind(path)
    .bind(user_agent)
    .execute(pool)
    .await?;
    Ok(())
}

/// Mayor `id` actual de `oob_hits` (0 si está vacía). La sonda lo lee ANTES de
/// inyectar para acotar la confirmación a los callbacks que llegan DESPUÉS.
pub async fn max_oob_id(pool: &SqlitePool) -> Result<i64> {
    let (m,): (i64,) = sqlx::query_as("SELECT COALESCE(MAX(id), 0) FROM oob_hits")
        .fetch_one(pool)
        .await?;
    Ok(m)
}

/// Borra callbacks OOB más viejos que `horas`. Housekeeping del colector público:
/// la tabla la puede engordar cualquiera en internet (una fila por request con
/// forma de token), y aunque la ventana `since_id` ya garantiza la CORRECCIÓN, sin
/// purga el disco crece sin cota. Los callbacks reales llegan en segundos tras
/// inyectar (oob_wait ~12s), así que una retención de 24h es holgada. Devuelve
/// cuántas filas borró.
pub async fn purge_oob_hits_older_than(pool: &SqlitePool, horas: u64) -> Result<u64> {
    let modificador = format!("-{horas} hours");
    let res = sqlx::query("DELETE FROM oob_hits WHERE created_at < datetime('now', ?1)")
        .bind(modificador)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

/// ¿Llegó un callback para este token DESPUÉS de `since_id`? Dos guardas contra un
/// falso positivo: (1) el token aleatorio de 16 chars solo lo pega algo que
/// recibió nuestro payload exacto (impredecibilidad, 36^16); (2) la VENTANA por
/// `id > since_id` acota a los hits de ESTA sonda, robusto por construcción y no
/// solo por la entropía (revisión 2026-08-23, obs 1) — un hit viejo con un token
/// reusado (imposible hoy, pero ya no dependemos de eso) no cuenta.
pub async fn oob_hit_exists(pool: &SqlitePool, token: &str, since_id: i64) -> Result<bool> {
    let fila: Option<(i64,)> =
        sqlx::query_as("SELECT 1 FROM oob_hits WHERE token = ?1 AND id > ?2 LIMIT 1")
            .bind(token)
            .bind(since_id)
            .fetch_optional(pool)
            .await?;
    Ok(fila.is_some())
}
