// SPDX-License-Identifier: LicenseRef-Propietario
//! E2E del escáner de secretos en JS servido (D28): contra un servidor axum REAL,
//! `escanear_objetivo` —con reqwest de verdad— baja el HTML raíz, sigue el `<script src>`,
//! baja el bundle `.js` y detecta el secreto plantado. Cruza la frontera del programa (HTTP
//! real), no de estructura a estructura.
//!
//! PAREJA (D33): un host VULNERABLE sirve un bundle con un token real → debe marcar; un host
//! CONTROL sirve solo un placeholder benigno y una `pk_live_` publicable → NO debe producir
//! una fuga (a lo sumo la publicable, que su clase marca como no-fuga).

use axum::{
    response::{Html, Redirect},
    routing::get,
    Router,
};

use nexus::protection::{Guard, ProtectionConfig};
use nexus::secretos::ClaseSecreto;
use nexus::secretos_js;

async fn arranca(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://127.0.0.1:{}", addr.port())
}

fn cli() -> reqwest::Client {
    nexus::autz::cliente("nexus-test").unwrap()
}

#[tokio::test]
async fn detecta_secreto_en_bundle_js_servido() {
    // VULNERABLE: el index referencia /app.js, que lleva un token de GitHub real.
    let ghp = format!("ghp_{}", "a".repeat(36));
    let app_js = format!("window.__CFG={{token:'{ghp}'}};");
    let app = Router::new()
        .route("/", get(|| async { Html(r#"<html><body><script src="/app.js"></script></body></html>"#) }))
        .route("/app.js", get(move || { let j = app_js.clone(); async move { j } }));
    let base = arranca(app).await;

    let mut guard = Guard::new(ProtectionConfig::default());
    let mut rng = || 0.0_f64;
    let (h, diag) = secretos_js::escanear_objetivo(&cli(), &base, "", 10, 8, &mut guard, &mut rng, false).await;

    // Positivo de control (D30): se bajó y escaneó de verdad — raíz 200 + 2 recursos.
    assert_eq!(diag.root_status, 200, "la raíz respondió; got {diag:?}");
    assert_eq!(diag.recursos, 2, "HTML raíz + /app.js escaneados; got {diag:?}");
    assert!(diag.bytes > 0, "se escanearon bytes; got {diag:?}");

    let github: Vec<_> = h.iter().filter(|x| x.clase == ClaseSecreto::GithubToken).collect();
    assert_eq!(github.len(), 1, "debe hallar el token en el bundle servido; got {h:?}");
    assert!(github[0].url.ends_with("/app.js"), "atribuido al bundle correcto");
    assert!(!github[0].valor_enmascarado.contains(&"a".repeat(36)), "el valor va enmascarado");
}

#[tokio::test]
async fn host_control_sin_fuga_real() {
    // CONTROL: bundle con solo texto benigno y una pk_live publicable (NO es fuga).
    let pk = format!("pk_live_{}", "c".repeat(30));
    let vendor_js = format!("const api_key = cfg.get('apikey'); const stripe='{pk}';");
    let app = Router::new()
        .route("/", get(|| async { Html(r#"<html><script src="/vendor.js"></script></html>"#) }))
        .route("/vendor.js", get(move || { let j = vendor_js.clone(); async move { j } }));
    let base = arranca(app).await;

    let mut guard = Guard::new(ProtectionConfig::default());
    let mut rng = || 0.0_f64;
    let (h, diag) = secretos_js::escanear_objetivo(&cli(), &base, "", 10, 8, &mut guard, &mut rng, false).await;

    assert_eq!(diag.recursos, 2, "control: también se escaneó de verdad; got {diag:?}");
    // No hay NINGUNA clase verificable/secreta; a lo sumo la publicable, que no es fuga.
    assert!(
        h.iter().all(|x| x.clase.publicable()),
        "el control no debe producir una fuga real; got {h:?}"
    );
}

#[tokio::test]
async fn sigue_redirect_del_apex_hasta_el_js() {
    // DEFECTO (b) corregido: el apex 302-redirige a /app (la SPA real), que sirve
    // /real.js con un token. Con un cliente que NO sigue redirects (el viejo
    // `autz::cliente`, Policy::none) esto daría 0 recursos y "limpio" falso — el
    // caso rojo falla por la MISMA vía real (el status 3xx del apex), no por el arnés.
    let ghp = format!("ghp_{}", "a".repeat(36));
    let real_js = format!("window.T='{ghp}';");
    let app = Router::new()
        .route("/", get(|| async { Redirect::temporary("/app") }))
        .route("/app", get(|| async { Html(r#"<html><script src="/real.js"></script></html>"#) }))
        .route("/real.js", get(move || { let j = real_js.clone(); async move { j } }));
    let base = arranca(app).await;

    let mut guard = Guard::new(ProtectionConfig::default());
    let mut rng = || 0.0_f64;
    // El MISMO cliente que usa el handler real: sigue redirects.
    let c = nexus::autz::cliente_redirigible("nexus-test").unwrap();
    let (h, diag) = secretos_js::escanear_objetivo(&c, &base, "", 10, 8, &mut guard, &mut rng, false).await;

    assert_eq!(diag.root_status, 200, "tras seguir el 302, la raíz efectiva es 200; got {diag:?}");
    assert!(diag.recursos >= 2, "raíz(/app) + /real.js escaneados; got {diag:?}");
    assert_eq!(
        h.iter().filter(|x| x.clase == ClaseSecreto::GithubToken).count(),
        1,
        "halla el token tras seguir el redirect; got {h:?}"
    );
}
