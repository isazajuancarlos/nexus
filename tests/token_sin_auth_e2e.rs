// SPDX-License-Identifier: LicenseRef-Propietario
//! E2E del molde token-sin-auth (D28): contra un servidor axum REAL, `sondear` pide el
//! endpoint de emisión SIN credencial y, con el token obtenido, el oráculo diferencial abre
//! un endpoint protegido que SIN token da 401. Cruza la frontera del programa (HTTP real).
//!
//! PAREJA (D33): host VULNERABLE emite token sin auth y el oráculo DISCRIMINA
//! (`ConfirmadoUsable`); host CONTROL exige auth en /token y NO entrega token → no marca.

use axum::{extract::Request, http::StatusCode, response::IntoResponse, routing::get, Router};

use nexus::protection::{Guard, ProtectionConfig};
use nexus::token_sin_auth::{self, VeredictoToken};

const JWT: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.ZmFrZXNpZ25hdHVyZV9fXw";

async fn arranca(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://127.0.0.1:{}", addr.port())
}

fn cli() -> reqwest::Client {
    nexus::autz::cliente("nexus-test").unwrap()
}

// VULNERABLE: /token emite un token SIN pedir credencial.
async fn emite_sin_auth() -> impl IntoResponse {
    ([("content-type", "application/json")], format!(r#"{{"access_token":"{JWT}"}}"#))
}

// Protegido: 401 sin Bearer, 200 con el Bearer correcto.
async fn protegido(req: Request) -> impl IntoResponse {
    let ok = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == format!("Bearer {JWT}"))
        .unwrap_or(false);
    if ok {
        (StatusCode::OK, "datos privados").into_response()
    } else {
        (StatusCode::UNAUTHORIZED, "no").into_response()
    }
}

// CONTROL: /token EXIGE auth → sin credencial, 401 y sin token.
async fn exige_auth() -> impl IntoResponse {
    (StatusCode::UNAUTHORIZED, r#"{"error":"invalid_token"}"#)
}

#[tokio::test]
async fn confirma_emision_sin_auth_por_oraculo() {
    let app = Router::new()
        .route("/token", get(emite_sin_auth).post(emite_sin_auth))
        .route("/privado", get(protegido));
    let base = arranca(app).await;

    let mut guard = Guard::new(ProtectionConfig::default());
    let rng = || 0.0_f64;
    let protegido_url = format!("{base}/privado");
    let h = token_sin_auth::sondear(
        &cli(),
        &base,
        &["/token"],
        Some(&protegido_url),
        8,
        &mut guard,
        rng,
    )
    .await;

    assert!(!h.is_empty(), "debe hallar la emisión sin auth");
    assert!(
        h.iter().any(|x| x.veredicto == VeredictoToken::ConfirmadoUsable),
        "el oráculo debe confirmar que el token abre el protegido; got {h:?}"
    );
    assert!(h[0].token_enmascarado.contains('…'), "token enmascarado");
}

#[tokio::test]
async fn control_que_exige_auth_no_marca() {
    let app = Router::new().route("/token", get(exige_auth).post(exige_auth));
    let base = arranca(app).await;

    let mut guard = Guard::new(ProtectionConfig::default());
    let rng = || 0.0_f64;
    let h =
        token_sin_auth::sondear(&cli(), &base, &["/token"], None, 8, &mut guard, rng).await;

    assert!(h.is_empty(), "un /token que exige auth NO debe producir hallazgo; got {h:?}");
}
