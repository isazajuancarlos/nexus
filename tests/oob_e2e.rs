// SPDX-License-Identifier: LicenseRef-Propietario
//! E2E del verificador SSRF out-of-band (directiva 28: cruzar la frontera del
//! programa). Levanta el COLECTOR real (socket) y dos objetivos:
//!   - VULNERABLE: su handler trae la URL del parámetro `url` (SSRF) → dispara el
//!     callback al colector → `fase_ssrf_oob` lo confirma.
//!   - SEGURO (pareja, directiva 33): ignora el parámetro, no hace fetch → sin
//!     callback → sin hallazgo. Discrimina de verdad, no por construcción.

use axum::{http::Uri, routing::get, Router};
use nexus::{db, oob};
use std::net::SocketAddr;

/// Extrae el valor DECODIFICADO del parámetro `url` de la URI (el payload va
/// percent-encoded al inyectarse).
fn param_url(uri: &Uri) -> Option<String> {
    let full = format!("http://x{uri}");
    let u = reqwest::Url::parse(&full).ok()?;
    u.query_pairs()
        .find(|(k, _)| k == "url")
        .map(|(_, v)| v.into_owned())
}

/// Objetivo VULNERABLE: trae ciegamente la URL que le pasan en `?url=` (el SSRF).
async fn objetivo_vulnerable(uri: Uri) -> &'static str {
    if let Some(u) = param_url(&uri) {
        // El servidor hace la petición saliente a la URL controlada por el atacante.
        let _ = reqwest::get(&u).await;
    }
    "ok"
}

/// Objetivo SEGURO: recibe el mismo parámetro pero NUNCA lo trae.
async fn objetivo_seguro(_uri: Uri) -> &'static str {
    "ok"
}

async fn levantar(app: Router) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    addr
}

#[tokio::test]
async fn ssrf_oob_confirma_el_ciego_y_no_el_seguro() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("t.db"), 4).await.unwrap();
    // BD AISLADA del colector (como en producción): el escritor público solo toca esta.
    let oob_pool = db::open_oob(&dir.path().join("oob.db"), 4).await.unwrap();

    // Colector real, servido con ConnectInfo (como en producción).
    let col = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let col_addr = col.local_addr().unwrap();
    let app = oob::router(oob_pool.clone());
    tokio::spawn(async move {
        axum::serve(col, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap()
    });
    let base = format!("http://{col_addr}");

    // Objetivo VULNERABLE → debe confirmarse por callback.
    let vuln = levantar(Router::new().route("/api", get(objetivo_vulnerable))).await;
    let url_vuln = format!("http://{vuln}/api?url=original");
    let n = oob::fase_ssrf_oob(&pool, &oob_pool, "prog", std::slice::from_ref(&url_vuln), 10, &base, 3, None)
        .await
        .unwrap();
    assert_eq!(n, 1, "el SSRF ciego real debe confirmarse por el callback");

    // Persistió como hallazgo real (cruzó a la BD).
    let program_id = db::upsert_program(&pool, "prog").await.unwrap();
    let hay: Option<(String,)> = sqlx::query_as(
        "SELECT vuln_name FROM findings WHERE program_id = ?1 AND vuln_name = 'ssrf-oob-callback'",
    )
    .bind(program_id)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(hay.is_some(), "el hallazgo OOB debe quedar en la BD");

    // PAREJA: objetivo SEGURO (no hace fetch) → ningún callback → cero hallazgos.
    let seguro = levantar(Router::new().route("/api", get(objetivo_seguro))).await;
    let url_seguro = format!("http://{seguro}/api?url=original");
    let m = oob::fase_ssrf_oob(&pool, &oob_pool, "prog2", std::slice::from_ref(&url_seguro), 10, &base, 3, None)
        .await
        .unwrap();
    assert_eq!(m, 0, "sin petición saliente NO hay confirmación (no se inventa)");
}

#[tokio::test]
async fn purga_borra_los_viejos_y_conserva_los_recientes() {
    let dir = tempfile::tempdir().unwrap();
    let oob = db::open_oob(&dir.path().join("oob.db"), 4).await.unwrap();
    // Reciente (created_at = ahora por defecto).
    db::record_oob_hit(&oob, "recientetoken001", "1.1.1.1", "GET", "/x", "")
        .await
        .unwrap();
    // Viejo: se fuerza created_at a hace 48h.
    sqlx::query(
        "INSERT INTO oob_hits (token, created_at) VALUES ('viejotoken000001', datetime('now','-48 hours'))",
    )
    .execute(&oob)
    .await
    .unwrap();

    let borrados = db::purge_oob_hits_older_than(&oob, 24).await.unwrap();
    assert_eq!(borrados, 1, "solo el callback de 48h supera el TTL de 24h");
    // PAREJA (directiva 33): el reciente NO se toca, el viejo YA no está.
    assert!(
        db::oob_hit_exists(&oob, "recientetoken001", 0).await.unwrap(),
        "el callback reciente se conserva"
    );
    assert!(
        !db::oob_hit_exists(&oob, "viejotoken000001", 0).await.unwrap(),
        "el callback viejo se purgó"
    );
}
