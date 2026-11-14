// SPDX-License-Identifier: LicenseRef-Propietario
//! El ciclo de notificación: solo VERIFIED/MANUAL_READY se anuncian, se marcan
//! tras enviar y no se re-notifican. El envío por red no se prueba aquí (I/O);
//! sí la selección + el marcado + el armado del mensaje (la lógica).

use nexus::db;

#[tokio::test]
async fn notifica_solo_verificados_y_no_repite() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("t.db"), 4).await.unwrap();
    let pid = db::upsert_program(&pool, "acme").await.unwrap();

    // VERIFIED (confirmado = true) → notified=0, DEBE salir en la cola.
    db::insert_costura(&pool, pid, "acme", "https://a.com/v", "fuga-sin-auth", "bac", "high", "CWE-862", true, None)
        .await.unwrap();
    // NEW (confirmado = false) → notified=0 pero status NEW → NO debe salir
    // (pareja del caso: sin este control, cualquier hit crudo se anunciaría).
    db::insert_costura(&pool, pid, "acme", "https://a.com/n", "fuga-sin-auth", "bac", "medium", "CWE-862", false, Some("ev"))
        .await.unwrap();

    let pend = db::hallazgos_sin_notificar(&pool).await.unwrap();
    assert_eq!(pend.len(), 1, "solo el VERIFIED, no el NEW crudo");
    assert_eq!(pend[0].url, "https://a.com/v");
    assert!(nexus::notify::construir_mensaje(&pend).is_some(), "hay algo que enviar");

    // Marca (como tras un envío exitoso) y confirma que la cola queda vacía.
    let marcados = db::marcar_notificados(&pool).await.unwrap();
    assert_eq!(marcados, 1);
    assert!(
        db::hallazgos_sin_notificar(&pool).await.unwrap().is_empty(),
        "no re-notifica lo ya avisado"
    );

    // Sin webhook configurado: no-op silencioso, cero enviados.
    let n = nexus::notify::notificar_pendientes(&pool, None).await.unwrap();
    assert_eq!(n, 0);
}
