// SPDX-License-Identifier: LicenseRef-Propietario
//! E2E de la fase JWT out-of-band (directiva 28: cruzar la frontera del programa).
//! Levanta el COLECTOR real (que ADEMÁS sirve el JWKS del atacante) y dos objetivos:
//!   - VULNERABLE: su verificador JWT TRAE el `jku` del header del token (el fallo de
//!     CVE-2026-27962/48522) → dispara el callback → `fase_jwt_oob` lo confirma.
//!   - SEGURO (pareja, directiva 33): ignora el `jku`, no hace fetch → sin callback → sin
//!     hallazgo. Discrimina de verdad, no por construcción.

use axum::{http::HeaderMap, routing::get, Router};
use nexus::{autenticacion, db, oob};
use std::net::SocketAddr;

/// JWT de muestra (header.payload.sig) — como el que el recon observa en el objetivo.
fn jwt_muestra() -> String {
    let h = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImsxIn0"; // {"alg":"HS256","typ":"JWT","kid":"k1"}
    let p = "eyJzdWIiOiJ1c2VyIiwicm9sZSI6InVzZXIifQ"; // {"sub":"user","role":"user"}
    format!("{h}.{p}.ZmFrZXNpZw")
}

/// Objetivo VULNERABLE: lee el Bearer, saca el `jku` del header del JWT y lo TRAE ciegamente
/// (el fallo: confiar en una URL de clave controlada por el atacante).
async fn objetivo_vulnerable(headers: HeaderMap) -> &'static str {
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(jwt) = autenticacion::parse_jwt(auth) {
            if let Some(jku) = jwt.jku {
                let _ = reqwest::get(&jku).await; // petición saliente a la URL del atacante
            }
        }
    }
    "ok"
}

/// Objetivo SEGURO: recibe el mismo token pero NUNCA trae el `jku`.
async fn objetivo_seguro(_headers: HeaderMap) -> &'static str {
    "ok"
}

async fn levantar(app: Router) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    addr
}

#[tokio::test]
async fn jwt_oob_confirma_el_jku_vulnerable_y_no_el_seguro() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("t.db"), 4).await.unwrap();
    let oob_pool = db::open_oob(&dir.path().join("oob.db"), 4).await.unwrap();

    // Colector real, servido con ConnectInfo (como en producción). Sirve ADEMÁS el JWKS.
    let col = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let col_addr = col.local_addr().unwrap();
    let app = oob::router(oob_pool.clone());
    tokio::spawn(async move {
        axum::serve(col, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap()
    });
    let base = format!("http://{col_addr}");

    // El colector HOSPEDA el JWKS del atacante: una ruta con `jwks` devuelve nuestra pubkey.
    let tok = oob::token();
    let jwks_url = format!("{base}/{tok}/.well-known/jwks.json");
    let cuerpo = reqwest::get(&jwks_url).await.unwrap().text().await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&cuerpo).unwrap();
    assert_eq!(v["keys"][0]["kty"], "RSA", "el colector sirve el JWKS del atacante");

    // Objetivo VULNERABLE → debe confirmarse por callback (ssrf y atacante traen el jku).
    let muestra = vec![jwt_muestra()];
    let vuln = levantar(Router::new().route("/api", get(objetivo_vulnerable))).await;
    let url_vuln = format!("http://{vuln}/api");
    let n = oob::fase_jwt_oob(&pool, &oob_pool, "prog", std::slice::from_ref(&url_vuln), &muestra, 10, &base, 3, None)
        .await
        .unwrap();
    assert!(n >= 1, "el jku vulnerable real debe confirmarse por callback (n={n})");

    // Persistió como hallazgo real (cruzó a la BD) con uno de los dos vuln_name esperados.
    let program_id = db::upsert_program(&pool, "prog").await.unwrap();
    let hay: Option<(String,)> = sqlx::query_as(
        "SELECT vuln_name FROM findings WHERE program_id = ?1 AND vuln_name IN ('jwt-jku-ssrf','jwt-jku-key-injection')",
    )
    .bind(program_id)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(hay.is_some(), "el hallazgo jku debe quedar en la BD");

    // PAREJA (directiva 33): objetivo SEGURO (no trae el jku) → ningún callback → cero hallazgos.
    let seguro = levantar(Router::new().route("/api", get(objetivo_seguro))).await;
    let url_seguro = format!("http://{seguro}/api");
    let m = oob::fase_jwt_oob(&pool, &oob_pool, "prog2", std::slice::from_ref(&url_seguro), &muestra, 10, &base, 3, None)
        .await
        .unwrap();
    assert_eq!(m, 0, "sin fetch del jku NO hay confirmación (no se inventa)");
}
