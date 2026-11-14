// SPDX-License-Identifier: LicenseRef-Propietario
//! ASM (2.2): el diff de superficie. La primera corrida es LÍNEA BASE (no avisa
//! aunque todo sea nuevo); las siguientes avisan solo de lo que aparece.

use nexus::db;

#[tokio::test]
async fn asm_primera_corrida_es_base_luego_solo_lo_nuevo() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("t.db"), 4).await.unwrap();

    // Primera corrida: todo es nuevo, pero era_primera=true → NO avisar (base).
    let (nuevos, primera) = db::registrar_assets(
        &pool,
        "acme",
        &["a.acme.com".into(), "b.acme.com".into(), "a.acme.com".into()], // dup se ignora
    )
    .await
    .unwrap();
    assert!(primera, "sin histórico previo = primera corrida");
    assert_eq!(nuevos.len(), 2, "dedup de la entrada");

    // Segunda corrida: un asset nuevo → se reporta; era_primera=false.
    let (nuevos2, primera2) = db::registrar_assets(
        &pool,
        "acme",
        &["a.acme.com".into(), "c.acme.com".into()],
    )
    .await
    .unwrap();
    assert!(!primera2);
    assert_eq!(nuevos2, vec!["c.acme.com".to_string()], "solo lo que apareció");

    // Tercera: sin novedades → vacío (no re-avisa lo ya visto).
    let (nuevos3, _) = db::registrar_assets(&pool, "acme", &["a.acme.com".into()]).await.unwrap();
    assert!(nuevos3.is_empty());
}
