//! La fase bespoke contra servidores REALES (directiva 28: cruza la frontera
//! HTTP, no de estructura a estructura). Un stub emula un storefront Hybris (con
//! cookies de acelerador + la API OCC que lista baseSites); otro emula un sitio
//! NO-Hybris. La fase debe fingerprintear el primero y emitir su superficie OCC,
//! y NO tocar el segundo (directiva 33: discrimina de verdad).

use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;

use nexus::bespoke;

// ── Stub Hybris: raíz con cookies de acelerador; /occ/v2/basesites con la API OCC.
//    Se construye la respuesta a mano para APPEND dos `Set-Cookie` (un array de
//    axum con la misma clave conserva solo una — el detalle que rompía el test).
async fn hybris_raiz() -> impl IntoResponse {
    let mut resp = axum::response::Response::new(axum::body::Body::from(
        "<html><body>Storefront</body></html>",
    ));
    let h = resp.headers_mut();
    h.append(header::SET_COOKIE, "JSESSIONID=ABC123; Path=/".parse().unwrap());
    h.append(header::SET_COOKIE, "ROUTE=.node1; Path=/".parse().unwrap());
    resp
}
async fn hybris_basesites() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"baseSites":[{"uid":"electronics","channel":"B2C"},{"uid":"apparel-uk"}]}"#,
    )
}

// ── Stub NO-Hybris: una app Java cualquiera (JSESSIONID SOLO) sin acelerador ni OCC.
async fn otro_raiz() -> impl IntoResponse {
    (
        [(header::SET_COOKIE, "JSESSIONID=XYZ; Path=/")],
        "<html><body>Otra app</body></html>",
    )
}
async fn otro_404() -> impl IntoResponse {
    (axum::http::StatusCode::NOT_FOUND, "<html>404</html>")
}

async fn arranca(app: axum::Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("127.0.0.1:{}", addr.port())
}

#[tokio::test]
async fn procesar_host_hybris_e2e_superficie_y_hallazgo_admin() {
    // E2E REAL de toda la cadena (dir. 28): un stub Hybris con cookies de
    // acelerador + API OCC + HAC EXPUESTA. `procesar_host_hybris` (público, toma
    // base con esquema, por eso ES testeable contra el stub http) debe: confirmar
    // Hybris, DEVOLVER la superficie OCC, y PERSISTIR el hallazgo de la HAC. Esta
    // prueba habría cazado el bug del `https://https://` (fase no-op).
    let dir = tempfile::tempdir().unwrap();
    let pool = nexus::db::open(&dir.path().join("e2e.db"), 2).await.unwrap();
    let pid = nexus::db::upsert_program(&pool, "prog").await.unwrap();
    let mut g = nexus::protection::Guard::new(nexus::protection::ProtectionConfig::default());
    // Cliente como en producción: sin seguir redirects.
    let cliente = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // ── HYBRIS con HAC expuesta.
    let hybris = arranca(
        axum::Router::new()
            .route("/", get(hybris_raiz))
            .route("/occ/v2/basesites", get(hybris_basesites))
            .route("/hac", get(hac_expuesta)),
    )
    .await;
    let superficie = bespoke::procesar_host_hybris(&cliente, &format!("http://{hybris}"), &pool, "prog", pid, None, &mut g)
        .await
        .unwrap();
    assert!(superficie.iter().any(|u| u.contains("/occ/v2/electronics/users/1/carts")),
        "confirma Hybris y emite la superficie OCC IDOR-prone");
    // La HAC expuesta se persistió como hallazgo high.
    let hac: Vec<(String, String)> = sqlx::query_as("SELECT vuln_name, severity FROM findings WHERE vuln_name='hybris-hac-expuesta'")
        .fetch_all(&pool).await.unwrap();
    assert_eq!(hac.len(), 1, "la HAC expuesta se persiste como hallazgo");
    assert_eq!(hac[0].1, "high");

    // ── CONTROL NO-Hybris: JSESSIONID solo → no confirma → sin superficie ni
    //    hallazgos (no fabrica nada).
    let otro = arranca(
        axum::Router::new()
            .route("/", get(otro_raiz))
            .route("/occ/v2/basesites", get(otro_404))
            .route("/rest/v2/basesites", get(otro_404)),
    )
    .await;
    let mut g2 = nexus::protection::Guard::new(nexus::protection::ProtectionConfig::default());
    let nada = bespoke::procesar_host_hybris(&cliente, &format!("http://{otro}"), &pool, "prog", pid, None, &mut g2)
        .await
        .unwrap();
    assert!(nada.is_empty(), "una app Java genérica NO es Hybris — sin superficie");
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM findings").fetch_one(&pool).await.unwrap();
    assert_eq!(total, 1, "el control no-Hybris no persistió ningún hallazgo");
}

// ── Capa 2 E2E: un Hybris con la HAC EXPUESTA (200 con UI) vs PROTEGIDA (302).
async fn hac_expuesta() -> impl IntoResponse {
    (axum::http::StatusCode::OK, "<title>hybris administration console</title><form>login</form>")
}
async fn hac_protegida() -> impl IntoResponse {
    // El control CORRECTO: la HAC redirige a login/SSO (no alcanzable sin auth).
    (axum::http::StatusCode::FOUND, [(header::LOCATION, "/sso/login")])
}

#[tokio::test]
async fn capa2_detecta_hac_expuesta_y_no_la_protegida() {
    use nexus::protection::{Guard, ProtectionConfig};
    let cliente = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none()) // un 302→login NO se sigue
        .build()
        .unwrap();

    // ── EXPUESTA: la HAC responde 200 con su UI OPERATIVA → detectada high.
    let vuln = arranca(axum::Router::new().route("/hac", get(hac_expuesta))).await;
    let mut g = Guard::new(ProtectionConfig::default());
    let expuestas = bespoke::detectar_admin_urls(&cliente, &format!("http://{vuln}"), &mut g).await;
    assert!(expuestas.iter().any(|(_, _, h)| h.vuln_name == "hybris-hac-expuesta" && h.severidad == "high"),
        "la HAC operativa alcanzable se detecta como expuesta (high)");

    // ── CONTROL PROTEGIDA: la HAC redirige a login (302) → NO se marca (el control
    //    funcionando no es exposición; y redirect::none NO sigue el 302).
    let prot = arranca(axum::Router::new().route("/hac", get(hac_protegida))).await;
    let mut g2 = Guard::new(ProtectionConfig::default());
    let nada = bespoke::detectar_admin_urls(&cliente, &format!("http://{prot}"), &mut g2).await;
    assert!(nada.is_empty(), "una HAC que redirige a login NO es exposición (control funcionando)");
}

#[tokio::test]
async fn fase_bespoke_no_toca_hosts_inalcanzables() {
    // La fase sobre un host que no resuelve: no revienta, devuelve superficie vacía
    // (falla ABIERTO — un host caído no es trabajo de esta fase, dir. 20).
    let dir = tempfile::tempdir().unwrap();
    let pool = nexus::db::open(&dir.path().join("b.db"), 2).await.unwrap();
    let urls = bespoke::fase_bespoke(
        &pool,
        "prog",
        &["host-que-no-existe.invalid".to_string()],
        10,
        "nexus-bespoke-test",
        None,
        None,
    )
    .await
    .unwrap();
    assert!(urls.is_empty(), "un host inalcanzable no produce superficie ni pánico");
}
