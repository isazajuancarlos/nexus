//! Un veredicto de confianza ALTA de autz (firma exacta, mismo recurso: las 4
//! reglas de `clasificar`) es un bypass PROBADO por diferencial y debe insertarse
//! ya CONFIRMADO —sin que el deepscan genérico lo degrade a MANUAL_READY perdiendo
//! la prueba—. La MEDIA sigue al verificador. Pareja (directiva 33) y cruza a la BD
//! real (directiva 28). No toca el auto-envío: control de acceso no es clase
//! pagable, así que un confirmado NO se envía —solo deja de esperar a un humano—.

use nexus::db;

#[tokio::test]
async fn alta_se_confirma_media_sigue_al_verificador() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("t.db"), 4).await.unwrap();
    let pid = db::upsert_program(&pool, "acme").await.unwrap();

    // ALTA (confirmado = true): bypass probado → VERIFIED + execution_confirmed.
    // Evidencia None → usa el texto por defecto ("…diferencial…").
    db::insert_costura(&pool, pid, "acme", "https://a.com/api/x", "fuga-sin-auth", "bac", "high", "CWE-862", true, None)
        .await.unwrap();
    // MEDIA (confirmado = false): NEW, aún por verificar — pero YA con evidencia
    // persistida (directiva 30: la cola MANUAL_READY tiene que ser auditable).
    db::insert_costura(&pool, pid, "acme", "https://a.com/api/y", "fuga-sin-auth", "bac", "high", "CWE-862", false, Some("evasion sin login en /api/y: tecnica Sufijo, 401->200"))
        .await.unwrap();

    let (st_a, ec_a, ex_a, ev_a, raw_a, tool_a): (String, i64, i64, Option<String>, Option<String>, Option<String>) =
        sqlx::query_as(
            "SELECT status, execution_confirmed, exploitable, verification_evidence, raw_evidence, verification_tool
             FROM findings WHERE url = 'https://a.com/api/x'",
        )
        .fetch_one(&pool).await.unwrap();
    assert_eq!(st_a, "VERIFIED", "una ALTA salta el re-verify que la degradaría");
    assert_eq!(ec_a, 1, "el bypass diferencial ES la prueba de ejecución");
    assert_eq!(ex_a, 1, "explotable");
    assert!(ev_a.unwrap().contains("diferencial"), "guarda la prueba (directiva 20)");
    // Una ALTA confirmada (fuga/privesc = severidad HIGH) puede llegar al
    // auto-envío, que exige raw_evidence: se persiste la MISMA prueba también en
    // raw_evidence, no solo en verification_evidence (fix 2026-08-24, la puerta
    // de evidencia). Sin este assert, revertir el `.bind(raw_ev)` no protesta.
    assert!(raw_a.as_deref().unwrap_or("").contains("diferencial"),
        "una ALTA confirmada persiste su prueba en raw_evidence (la puerta de auto-envío la exige)");
    assert_eq!(tool_a.as_deref(), Some("autz"));

    // ROJO/pareja: la MEDIA no se auto-confirma — sin este caso, un `confirmado`
    // pegado a `true` pasaría igual y auto-confirmaría señales débiles.
    let (st_m, ec_m, ev_m, raw_m): (String, i64, Option<String>, Option<String>) =
        sqlx::query_as("SELECT status, execution_confirmed, verification_evidence, raw_evidence FROM findings WHERE url = 'https://a.com/api/y'")
            .fetch_one(&pool).await.unwrap();
    assert_eq!(st_m, "NEW", "la MEDIA sigue al verificador, no se auto-confirma");
    assert_eq!(ec_m, 0);
    // Fix 2026-08-21: una MEDIA/NEW ya NO va sin evidencia — la cola es auditable.
    assert!(
        ev_m.as_deref().unwrap_or("").contains("evasion sin login"),
        "un NEW también persiste su evidencia (directiva 30), no NULL como antes"
    );
    // Pero una MEDIA no confirmada NO puebla raw_evidence: raw_evidence es la
    // PRUEBA de ejecución, y una MEDIA no está probada (execution_confirmed=0 la
    // frena igual, pero la columna de prueba no debe mentir).
    assert!(raw_m.is_none(), "una MEDIA no confirmada no puebla raw_evidence (no es prueba de ejecución)");
}
