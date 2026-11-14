//! El ENFORCE del gate de elegibilidad, en su punto de riesgo real: el UPDATE de
//! la BD. `descartar_por_elegibilidad` debe (1) reclasificar a INFORMATIONAL solo
//! los MANUAL_READY, (2) guardar el motivo (directiva 20: reversible y visible), y
//! (3) NO tocar lo que está en otra cola. Pareja verde/rojo (directiva 33), y
//! cruza la frontera a la BD real (directiva 28), no de estructura a estructura.
//!
//! La DECISIÓN (qué es descartable) ya está probada pura en el módulo; aquí se
//! prueba el efecto en disco, que es lo que un veredicto sin ejecutar no cubre.

use nexus::db::{self, NewFinding};

/// El RELOJ TERMINAL cierra a INFORMATIONAL lo que lleva demasiado en MANUAL_READY
/// (nada espera para siempre), pero NO lo reciente. Pareja (directiva 33) y cruza a
/// la BD real (directiva 28). `max_dias=0` = apagado.
#[tokio::test]
async fn reloj_terminal_cierra_lo_viejo_no_lo_reciente() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("t.db"), 4).await.unwrap();
    let pid = db::upsert_program(&pool, "acme").await.unwrap();

    let nf = |v: &str| NewFinding {
        program_name: "acme".into(),
        vuln_name: v.into(),
        severity: "low".into(),
        url: "https://a.com".into(),
        cwe: None,
        evidencia: None,
    };
    db::insert_finding_dedup(&pool, &nf("viejo"), pid).await.unwrap();
    db::insert_finding_dedup(&pool, &nf("reciente"), pid).await.unwrap();
    let id_v: i64 = sqlx::query_scalar("SELECT id FROM findings WHERE vuln_name='viejo'").fetch_one(&pool).await.unwrap();
    let id_r: i64 = sqlx::query_scalar("SELECT id FROM findings WHERE vuln_name='reciente'").fetch_one(&pool).await.unwrap();
    for id in [id_v, id_r] {
        db::apply_verification(&pool, id, "MANUAL_READY", false, "manual", "medium", false, None, "other", None, false, None).await.unwrap();
    }
    // Envejecer solo el 'viejo' 40 días.
    sqlx::query("UPDATE findings SET found_at = datetime('now','-40 days') WHERE id = ?1")
        .bind(id_v).execute(&pool).await.unwrap();

    // Apagado (0) no toca nada, ni al viejo.
    assert_eq!(nexus::elegibilidad::reloj_terminal(&pool, 0).await.unwrap(), 0, "ventana 0 = apagado");

    // Ventana 21 días: cierra el viejo, deja el reciente.
    assert_eq!(nexus::elegibilidad::reloj_terminal(&pool, 21).await.unwrap(), 1, "solo el viejo vence");
    let (st_v, ev_v): (String, Option<String>) =
        sqlx::query_as("SELECT status, verification_evidence FROM findings WHERE id = ?1")
            .bind(id_v).fetch_one(&pool).await.unwrap();
    assert_eq!(st_v, "INFORMATIONAL");
    assert!(ev_v.unwrap().contains("reloj terminal"), "guarda el motivo (directiva 20)");
    // ROJO/pareja: el reciente NO vence. Sin este caso, un reloj sin la condición
    // de fecha cerraría todo por igual.
    let st_r: String = sqlx::query_scalar("SELECT status FROM findings WHERE id = ?1")
        .bind(id_r).fetch_one(&pool).await.unwrap();
    assert_eq!(st_r, "MANUAL_READY", "el reciente aún tiene su ventana");
}

#[tokio::test]
async fn descarta_solo_manual_ready_y_guarda_el_motivo() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("t.db"), 4).await.unwrap();
    let pid = db::upsert_program(&pool, "acme").await.unwrap();

    let nf = |vuln: &str| NewFinding {
        program_name: "acme".into(),
        vuln_name: vuln.into(),
        severity: "high".into(),
        url: "https://a.example.com".into(),
        cwe: None,
        evidencia: None,
    };
    db::insert_finding_dedup(&pool, &nf("hallazgo-manual"), pid).await.unwrap();
    db::insert_finding_dedup(&pool, &nf("hallazgo-otra-cola"), pid).await.unwrap();

    let id_manual: i64 = sqlx::query_scalar("SELECT id FROM findings WHERE vuln_name = 'hallazgo-manual'")
        .fetch_one(&pool).await.unwrap();
    let id_otro: i64 = sqlx::query_scalar("SELECT id FROM findings WHERE vuln_name = 'hallazgo-otra-cola'")
        .fetch_one(&pool).await.unwrap();

    // Uno pasa a MANUAL_READY; el otro se deja en su estado inicial (no-manual).
    db::apply_verification(&pool, id_manual, "MANUAL_READY", false, "manual", "medium", false, None, "other", None, false, None)
        .await.unwrap();
    let st_otro_antes: String = sqlx::query_scalar("SELECT status FROM findings WHERE id = ?1")
        .bind(id_otro).fetch_one(&pool).await.unwrap();
    assert_ne!(st_otro_antes, "MANUAL_READY", "el control NO debe estar en MANUAL_READY");

    // Se descarta sobre AMBOS con el mismo motivo. Solo el MANUAL_READY cambia.
    let motivo = "fuera de scope submittable";
    db::descartar_por_elegibilidad(&pool, id_manual, motivo).await.unwrap();
    db::descartar_por_elegibilidad(&pool, id_otro, motivo).await.unwrap();

    // VERDE: el MANUAL_READY se reclasifica y guarda el motivo (no se pierde).
    let (st_m, ev_m): (String, Option<String>) =
        sqlx::query_as("SELECT status, verification_evidence FROM findings WHERE id = ?1")
            .bind(id_manual).fetch_one(&pool).await.unwrap();
    assert_eq!(st_m, "INFORMATIONAL", "el MANUAL_READY se reclasifica a INFORMATIONAL");
    assert_eq!(
        ev_m.as_deref(),
        Some("resolución autónoma: fuera de scope submittable"),
        "guarda el motivo, auditable y reversible (directiva 20)"
    );

    // ROJO/pareja: el hallazgo fuera de MANUAL_READY NO lo toca el gate. Sin este
    // caso, un UPDATE sin el `AND status='MANUAL_READY'` pasaría igual y arrasaría
    // hallazgos ya verificados.
    let st_o: String = sqlx::query_scalar("SELECT status FROM findings WHERE id = ?1")
        .bind(id_otro).fetch_one(&pool).await.unwrap();
    assert_eq!(st_o, st_otro_antes, "un hallazgo fuera de MANUAL_READY queda intacto");
    assert_ne!(st_o, "INFORMATIONAL");
}
