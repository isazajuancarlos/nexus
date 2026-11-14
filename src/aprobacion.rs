//! PUERTA DE INTEGRIDAD DEL AUTO-ENVÍO H1 — port del `operator-approval-loop` de ECC
//! (estudio de fuente 2026-09-19), adaptado al auto-envío YA autorizado de nexus
//! (memoria `h1-envio-autonomo-autorizado`). NO decide payabilidad ni envía: concede
//! o niega el PERMISO de despachar UN texto que ya pasó la puerta de evidencia.
//!
//! Dos huecos que cierra, medidos en `autosubmit::run`:
//!   1. **Doble envío.** Hoy el POST va y LUEGO `mark_reported` (autosubmit.rs:187-189);
//!      si el proceso muere en medio, la próxima corrida reenvía. La máquina
//!      claim→dispatching→sent + el índice único parcial `uniq_envio_claim_en_vuelo`
//!      dan idempotencia: a lo sumo un envío en vuelo por `report_key`, y un `sent`
//!      previo bloquea el re-claim.
//!   2. **Texto no atado a la evidencia.** El snapshot congela el texto EXACTO aprobado
//!      con su sha256 (directiva 31: al ARTEFACTO, no a la rama). Si el reporte se
//!      regenera distinto entre la decisión y el POST, `claim` lo RECHAZA (los sha
//!      difieren) y `begin_dispatch` entrega el texto del snapshot, no una variable que
//!      pudo mutar.
//!
//! Fail-loud (directivas 20/30): un snapshot inexistente es Err ruidoso, nunca un
//! permiso silencioso; un claim en `unknown` (worker reiniciado tras posible POST) NO
//! se reintenta solo — se nombra y espera revisión.

use crate::error::{NexusError, Result};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

/// SHA-256 hex del texto exacto del reporte. Es la huella que ata la aprobación al
/// artefacto: si el cuerpo cambia en un byte, el hash cambia y el claim se cae.
pub fn sha256_hex(texto: &str) -> String {
    let d = Sha256::digest(texto.as_bytes());
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn token_aleatorio() -> String {
    use rand::Rng;
    let mut b = [0u8; 16];
    rand::rng().fill(&mut b);
    let mut s = String::with_capacity(32);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Resultado de pedir permiso de despacho. `Rechazado` es una negativa LEGÍTIMA
/// (texto reescrito, ya en vuelo, ya enviado, en revisión) → el llamante SALTA ese
/// envío y sigue; NO es un fallo de sistema (eso es `Err`). Directiva 32: el rechazo
/// de permiso y el error de infraestructura son dos caminos distintos.
#[derive(Debug, Clone)]
pub enum Claim {
    Concedido(String),
    Rechazado(String),
}

/// Resultado de abrir el despacho: `Concedido(texto_aprobado)` una sola vez, o
/// `Perdido` si el claim ya no está en `claimed` (otro worker lo tomó, o se repitió).
#[derive(Debug, Clone)]
pub enum Dispatch {
    Concedido(String),
    Perdido(String),
}

/// Congela el texto aprobado como instantánea INMUTABLE. Regenerar el reporte crea
/// OTRA fila (epoch nuevo): una aprobación vieja queda atada a su epoch/sha. Devuelve
/// el `snapshot_id`.
pub async fn snapshot(
    pool: &SqlitePool,
    report_key: &str,
    texto: &str,
    evidencia: &str,
    now_ts: i64,
) -> Result<i64> {
    let sha = sha256_hex(texto);
    let id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO envio_snapshot (report_key, texto, texto_sha256, evidencia, epoch, created_ts)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5) RETURNING id",
    )
    .bind(report_key)
    .bind(texto)
    .bind(&sha)
    .bind(evidencia)
    .bind(now_ts)
    .fetch_one(pool)
    .await?;
    Ok(id)
}

/// Reserva UN envío ya aprobado. Valida por la VÍA REAL que lo que hay ahora es lo
/// aprobado (sha), que no hay uno en vuelo/enviado/en-revisión, y crea el claim.
/// - snapshot inexistente → Err (fail-loud: sin aprobación no hay permiso).
/// - `texto_actual` con sha distinto al del snapshot → Rechazado (texto reescrito).
/// - ya hay claim `sent`/`unknown` para el report_key → Rechazado.
/// - ya hay claim en vuelo → Rechazado (lo hace cumplir el índice único parcial).
pub async fn claim(
    pool: &SqlitePool,
    report_key: &str,
    snapshot_id: i64,
    texto_actual: &str,
    now_ts: i64,
) -> Result<Claim> {
    let fila = sqlx::query_as::<_, (String, String)>(
        "SELECT report_key, texto_sha256 FROM envio_snapshot WHERE id = ?1",
    )
    .bind(snapshot_id)
    .fetch_optional(pool)
    .await?;
    let (snap_key, snap_sha) = match fila {
        Some(f) => f,
        // Fail-loud: sin snapshot no hay permiso; NUNCA un permiso por defecto (D20).
        None => {
            return Err(NexusError::Other(format!(
                "aprobación: snapshot {snapshot_id} inexistente; no se despacha sin aprobación"
            )))
        }
    };
    if snap_key != report_key {
        return Err(NexusError::Other(format!(
            "aprobación: snapshot {snapshot_id} es de '{snap_key}', no de '{report_key}'"
        )));
    }

    // La VÍA REAL de discriminación: el sha del texto que se enviaría AHORA debe
    // coincidir con el aprobado. Si el reporte se regeneró distinto, difiere → no sale.
    let sha_actual = sha256_hex(texto_actual);
    if sha_actual != snap_sha {
        return Ok(Claim::Rechazado(format!(
            "texto reescrito desde la aprobación (sha actual {}… ≠ aprobado {}…): a revisión, sin envío",
            &sha_actual[..8.min(sha_actual.len())],
            &snap_sha[..8.min(snap_sha.len())]
        )));
    }

    // Un envío ya terminado o en revisión bloquea el re-claim (idempotencia + no
    // reenviar tras un POST que pudo salir). El índice en-vuelo cubre claimed/dispatching;
    // sent/unknown se comprueban aquí.
    if let Some(estado) = sqlx::query_scalar::<_, String>(
        "SELECT state FROM envio_claim WHERE report_key = ?1 AND state IN ('sent','unknown')
         ORDER BY id DESC LIMIT 1",
    )
    .bind(report_key)
    .fetch_optional(pool)
    .await?
    {
        return Ok(Claim::Rechazado(match estado.as_str() {
            "sent" => "ya enviado (report_key con receipt); no se reenvía".to_string(),
            _ => "envío previo en estado 'unknown' (worker reiniciado tras posible POST); \
                  requiere revisión manual, no se reintenta solo"
                .to_string(),
        }));
    }

    let token = token_aleatorio();
    let res = sqlx::query(
        "INSERT INTO envio_claim (report_key, snapshot_id, token, state, created_ts, updated_ts)
         VALUES (?1, ?2, ?3, 'claimed', ?4, ?4)",
    )
    .bind(report_key)
    .bind(snapshot_id)
    .bind(&token)
    .bind(now_ts)
    .execute(pool)
    .await;

    match res {
        Ok(_) => Ok(Claim::Concedido(token)),
        Err(e) => {
            // La colisión del índice único parcial = ya hay uno en vuelo. Es rechazo
            // legítimo, no fallo de sistema.
            if e.as_database_error().map(|d| d.is_unique_violation()).unwrap_or(false) {
                Ok(Claim::Rechazado(
                    "ya hay un envío en vuelo para este report_key".into(),
                ))
            } else {
                Err(NexusError::from(e))
            }
        }
    }
}

/// Abre el despacho: transición `claimed`→`dispatching` y entrega el texto APROBADO
/// (del snapshot, inmutable) UNA sola vez. Tras esto el llamante hace el POST.
pub async fn begin_dispatch(pool: &SqlitePool, token: &str, now_ts: i64) -> Result<Dispatch> {
    let fila = sqlx::query_as::<_, (i64, String)>(
        "SELECT snapshot_id, state FROM envio_claim WHERE token = ?1",
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;
    let (snapshot_id, state) = match fila {
        Some(f) => f,
        None => return Err(NexusError::Other(format!("aprobación: token de claim desconocido {token}"))),
    };
    if state != "claimed" {
        return Ok(Dispatch::Perdido(format!(
            "el claim no está en 'claimed' (state={state}); no concede otro despacho"
        )));
    }
    // La transición condicionada es la que evita el doble despacho: solo pasa si
    // seguía en 'claimed'.
    let cambiadas = sqlx::query(
        "UPDATE envio_claim SET state='dispatching', updated_ts=?2 WHERE token=?1 AND state='claimed'",
    )
    .bind(token)
    .bind(now_ts)
    .execute(pool)
    .await?
    .rows_affected();
    if cambiadas != 1 {
        return Ok(Dispatch::Perdido("la transición a 'dispatching' se perdió (carrera)".into()));
    }
    let texto = sqlx::query_scalar::<_, String>("SELECT texto FROM envio_snapshot WHERE id = ?1")
        .bind(snapshot_id)
        .fetch_one(pool)
        .await?;
    Ok(Dispatch::Concedido(texto))
}

/// Cierra el despacho con éxito: `dispatching`→`sent`, guardando la coordenada
/// (el report_id de H1). Es el receipt que impide el reenvío.
pub async fn complete(pool: &SqlitePool, token: &str, coordinate: &str, now_ts: i64) -> Result<()> {
    let n = sqlx::query(
        "UPDATE envio_claim SET state='sent', coordinate=?2, updated_ts=?3
         WHERE token=?1 AND state='dispatching'",
    )
    .bind(token)
    .bind(coordinate)
    .bind(now_ts)
    .execute(pool)
    .await?
    .rows_affected();
    if n != 1 {
        return Err(NexusError::Other(format!(
            "aprobación: complete sobre token {token} que no estaba en 'dispatching'"
        )));
    }
    Ok(())
}

/// Cancela un claim aún NO despachado (`claimed`→`cancelled`). No reabre nada.
pub async fn cancel(pool: &SqlitePool, token: &str, now_ts: i64) -> Result<()> {
    sqlx::query("UPDATE envio_claim SET state='cancelled', updated_ts=?2 WHERE token=?1 AND state='claimed'")
        .bind(token)
        .bind(now_ts)
        .execute(pool)
        .await?;
    Ok(())
}

/// Marca la incertidumbre de un worker reiniciado en `dispatching` (el POST pudo haber
/// salido): `dispatching`→`unknown`. Un `unknown` bloquea el re-claim (ver `claim`):
/// nunca se reintenta solo, para no arriesgar el doble envío.
pub async fn mark_unknown(pool: &SqlitePool, token: &str, now_ts: i64) -> Result<()> {
    sqlx::query("UPDATE envio_claim SET state='unknown', updated_ts=?2 WHERE token=?1 AND state='dispatching'")
        .bind(token)
        .bind(now_ts)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    async fn pool_migrado() -> SqlitePool {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    const K: &str = "acme::sqli";
    const TXT: &str = "## Description\nSQLi en /buscar?id=\n## PoC\nid=1' AND '1'='1";

    // POSITIVO: el camino feliz completo — snapshot → claim → dispatch entrega el
    // texto APROBADO → complete deja receipt.
    #[tokio::test]
    async fn camino_feliz_entrega_texto_aprobado_y_cierra() {
        let pool = pool_migrado().await;
        let sid = snapshot(&pool, K, TXT, "execution_confirmed 3/3", 100).await.unwrap();
        let tok = match claim(&pool, K, sid, TXT, 101).await.unwrap() {
            Claim::Concedido(t) => t,
            otro => panic!("esperaba Concedido, fue {otro:?}"),
        };
        match begin_dispatch(&pool, &tok, 102).await.unwrap() {
            Dispatch::Concedido(texto) => assert_eq!(texto, TXT, "debe entregar el texto APROBADO, byte a byte"),
            otro => panic!("esperaba Concedido, fue {otro:?}"),
        }
        complete(&pool, &tok, "report-999", 103).await.unwrap();
    }

    // CASO ROJO (D33), por la VÍA REAL: el texto se regeneró distinto tras la
    // aprobación → los sha difieren → RECHAZADO. Si esto concediera, saldría texto no
    // verificado: es el fallo que el módulo existe para impedir.
    #[tokio::test]
    async fn texto_reescrito_no_se_despacha() {
        let pool = pool_migrado().await;
        let sid = snapshot(&pool, K, TXT, "ev", 100).await.unwrap();
        let reescrito = format!("{TXT}\n(línea añadida que cambia el cuerpo)");
        match claim(&pool, K, sid, &reescrito, 101).await.unwrap() {
            Claim::Rechazado(m) => assert!(m.contains("reescrito"), "motivo: {m}"),
            Claim::Concedido(_) => panic!("CASO ROJO: aprobó texto reescrito — fuga de integridad"),
        }
    }

    // CASO ROJO idempotencia: un segundo claim con el mismo report_key en vuelo se
    // rechaza (lo hace cumplir el índice único parcial). Cierra el doble envío.
    #[tokio::test]
    async fn segundo_claim_en_vuelo_rechazado() {
        let pool = pool_migrado().await;
        let sid = snapshot(&pool, K, TXT, "ev", 100).await.unwrap();
        let _t1 = match claim(&pool, K, sid, TXT, 101).await.unwrap() {
            Claim::Concedido(t) => t,
            otro => panic!("primer claim debía conceder, fue {otro:?}"),
        };
        match claim(&pool, K, sid, TXT, 102).await.unwrap() {
            Claim::Rechazado(m) => assert!(m.contains("en vuelo"), "motivo: {m}"),
            Claim::Concedido(_) => panic!("CASO ROJO: dos claims en vuelo → doble envío"),
        }
    }

    // Ventana POST-ok/crash: un report_key ya 'sent' no se vuelve a reclamar.
    #[tokio::test]
    async fn ya_enviado_no_se_reclama() {
        let pool = pool_migrado().await;
        let sid = snapshot(&pool, K, TXT, "ev", 100).await.unwrap();
        let t1 = match claim(&pool, K, sid, TXT, 101).await.unwrap() {
            Claim::Concedido(t) => t,
            o => panic!("{o:?}"),
        };
        let _ = begin_dispatch(&pool, &t1, 102).await.unwrap();
        complete(&pool, &t1, "report-1", 103).await.unwrap();
        // Nuevo intento (otro snapshot del mismo report_key) → rechazado por 'sent'.
        let sid2 = snapshot(&pool, K, TXT, "ev", 200).await.unwrap();
        match claim(&pool, K, sid2, TXT, 201).await.unwrap() {
            Claim::Rechazado(m) => assert!(m.contains("ya enviado"), "motivo: {m}"),
            Claim::Concedido(_) => panic!("CASO ROJO: reenvío de un report_key ya enviado"),
        }
    }

    // Worker reiniciado en 'dispatching' → 'unknown' → bloquea el reintento solo (D30:
    // "no se puede saber si el POST salió" no es "no salió"; no se reenvía a ciegas).
    #[tokio::test]
    async fn unknown_bloquea_reintento() {
        let pool = pool_migrado().await;
        let sid = snapshot(&pool, K, TXT, "ev", 100).await.unwrap();
        let t1 = match claim(&pool, K, sid, TXT, 101).await.unwrap() {
            Claim::Concedido(t) => t,
            o => panic!("{o:?}"),
        };
        let _ = begin_dispatch(&pool, &t1, 102).await.unwrap();
        mark_unknown(&pool, &t1, 103).await.unwrap();
        let sid2 = snapshot(&pool, K, TXT, "ev", 200).await.unwrap();
        match claim(&pool, K, sid2, TXT, 201).await.unwrap() {
            Claim::Rechazado(m) => assert!(m.contains("unknown") || m.contains("revisión"), "motivo: {m}"),
            Claim::Concedido(_) => panic!("CASO ROJO: reintento tras 'unknown' arriesga doble envío"),
        }
    }

    // Fail-loud (D20): un snapshot inexistente es Err, no un permiso silencioso.
    #[tokio::test]
    async fn snapshot_inexistente_falla_ruidoso() {
        let pool = pool_migrado().await;
        let r = claim(&pool, K, 4242, TXT, 101).await;
        assert!(r.is_err(), "un snapshot inexistente debe ser Err ruidoso, fue {r:?}");
    }

    // No dos payloads del mismo claim: el segundo begin_dispatch se pierde.
    #[tokio::test]
    async fn dispatch_dos_veces_pierde() {
        let pool = pool_migrado().await;
        let sid = snapshot(&pool, K, TXT, "ev", 100).await.unwrap();
        let t1 = match claim(&pool, K, sid, TXT, 101).await.unwrap() {
            Claim::Concedido(t) => t,
            o => panic!("{o:?}"),
        };
        assert!(matches!(begin_dispatch(&pool, &t1, 102).await.unwrap(), Dispatch::Concedido(_)));
        assert!(
            matches!(begin_dispatch(&pool, &t1, 103).await.unwrap(), Dispatch::Perdido(_)),
            "el segundo dispatch del mismo token debe perderse"
        );
    }

    // Tras cancelar un claim, el report_key vuelve a estar libre para reclamar.
    #[tokio::test]
    async fn cancelar_libera_el_report_key() {
        let pool = pool_migrado().await;
        let sid = snapshot(&pool, K, TXT, "ev", 100).await.unwrap();
        let t1 = match claim(&pool, K, sid, TXT, 101).await.unwrap() {
            Claim::Concedido(t) => t,
            o => panic!("{o:?}"),
        };
        cancel(&pool, &t1, 102).await.unwrap();
        assert!(
            matches!(claim(&pool, K, sid, TXT, 103).await.unwrap(), Claim::Concedido(_)),
            "tras cancelar, el report_key debe poder reclamarse de nuevo"
        );
    }
}
