//! Montaje del juego de identidades autz por CLI, cruzando a la BD real
//! (directiva 28) y con su pareja (directiva 33): lo que `guardar_identidad`
//! escribe es EXACTAMENTE lo que `cargar_identidades` devuelve, y `juego_listo`
//! pasa de NO a SÍ en el momento correcto. Es el paso que abre la ruta que paga
//! (IDOR/BAC): si el round-trip se rompe, el motor se salta el programa en
//! silencio (juego a medias = no corre), que es el modo de fallo mudo.

use nexus::autz::{juego_listo, Papel};
use nexus::db;

#[tokio::test]
async fn montaje_carga_y_juego_listo_de_no_a_si() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("t.db"), 4).await.unwrap();

    // Sin identidades: el juego NO está listo (control negativo, directiva 33).
    let ids0 = db::cargar_identidades(&pool, "acme").await.unwrap();
    assert!(!juego_listo(&ids0), "sin identidades no puede estar listo");

    // Solo el dueño: SIGUE sin estar listo — falta contra quién comparar.
    let rot = db::guardar_identidad(
        &pool, "acme", Papel::Dueno,
        &[("Authorization".into(), "Bearer AAA".into())],
    ).await.unwrap();
    assert!(!rot, "primera vez inserta, no rota");
    let ids1 = db::cargar_identidades(&pool, "acme").await.unwrap();
    assert_eq!(ids1.len(), 1);
    assert!(!juego_listo(&ids1), "solo el dueño no basta");

    // Dueño + par: AHORA sí — el borde exacto donde el motor arranca.
    db::guardar_identidad(
        &pool, "acme", Papel::Par,
        &[("Cookie".into(), "sid=BBB".into())],
    ).await.unwrap();
    let ids2 = db::cargar_identidades(&pool, "acme").await.unwrap();
    assert_eq!(ids2.len(), 2);
    assert!(juego_listo(&ids2), "dueño + par debe estar listo");

    // Round-trip EXACTO: las cabeceras del dueño salen tal cual entraron.
    let dueno = ids2.iter().find(|i| i.papel == Papel::Dueno).unwrap();
    assert_eq!(dueno.cabeceras, vec![("Authorization".to_string(), "Bearer AAA".to_string())]);
}

#[tokio::test]
async fn rotar_el_mismo_papel_reemplaza_no_duplica() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("t.db"), 4).await.unwrap();

    db::guardar_identidad(&pool, "acme", Papel::Dueno, &[("Authorization".into(), "Bearer VIEJO".into())])
        .await.unwrap();
    // Montar OTRA vez el dueño (token nuevo) debe ROTAR, no añadir una segunda fila.
    let rot = db::guardar_identidad(&pool, "acme", Papel::Dueno, &[("Authorization".into(), "Bearer NUEVO".into())])
        .await.unwrap();
    assert!(rot, "el segundo montaje del mismo papel es una rotación");

    let ids = db::cargar_identidades(&pool, "acme").await.unwrap();
    assert_eq!(ids.len(), 1, "sigue habiendo UNA identidad dueño, no dos");
    assert_eq!(ids[0].cabeceras[0].1, "Bearer NUEVO", "vale la credencial nueva");
}

#[tokio::test]
async fn borrar_identidad_y_semillas_dedup() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("t.db"), 4).await.unwrap();

    db::guardar_identidad(&pool, "acme", Papel::Dueno, &[("Authorization".into(), "Bearer X".into())])
        .await.unwrap();
    assert!(db::borrar_identidad(&pool, "acme", Papel::Dueno).await.unwrap(), "borra la existente");
    assert!(!db::borrar_identidad(&pool, "acme", Papel::Dueno).await.unwrap(), "borrar dos veces es no-op");
    assert!(db::listar_identidades(&pool, "acme").await.unwrap().is_empty());

    // Semillas: dedup por (programa, url).
    assert!(db::guardar_semilla(&pool, "acme", "https://a.com/o/1").await.unwrap(), "primera es nueva");
    assert!(!db::guardar_semilla(&pool, "acme", "https://a.com/o/1").await.unwrap(), "repetida es no-op");
    assert!(db::guardar_semilla(&pool, "acme", "https://a.com/o/2").await.unwrap());
    let s = db::cargar_semillas(&pool, "acme").await.unwrap();
    assert_eq!(s.len(), 2, "dos semillas distintas, la repetida no cuenta");
}
