// SPDX-License-Identifier: LicenseRef-Propietario
//! E2E del laboratorio de auth (dir. 28): contra un servidor JWT SINTÉTICO vulnerable,
//! el ataque `alg:none` debe lograr acceso de admin, y el oráculo confirmarlo — mientras
//! un control (token inválido) es rechazado. Prueba la CADENA entera: forjar → enviar →
//! oráculo, no solo la lógica unitaria. No destructivo: forjamos nuestro propio token.

use axum::{routing::get, Router};
use axum::http::HeaderMap;
use nexus::autenticacion as auth;

/// Endpoint /perfil VULNERABLE: decodifica el JWT y, si `alg=none`, CONFÍA en el payload
/// sin verificar firma (el fallo clásico). Devuelve el rol. Sin token o inválido → 401.
async fn perfil(headers: HeaderMap) -> (axum::http::StatusCode, String) {
    use axum::http::StatusCode;
    let Some(authz) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return (StatusCode::UNAUTHORIZED, "{\"error\":\"missing token\"}".into());
    };
    let Some(jwt) = auth::parse_jwt(authz) else {
        return (StatusCode::UNAUTHORIZED, "{\"error\":\"invalid_token\"}".into());
    };
    // LA VULNERABILIDAD: si alg=none, acepta el payload sin verificar (no debería).
    if jwt.alg.eq_ignore_ascii_case("none") {
        let rol = jwt.payload.get("role").and_then(|v| v.as_str()).unwrap_or("user");
        return (StatusCode::OK, format!("{{\"role\":\"{rol}\",\"data\":\"secreto\"}}"));
    }
    // Para otros alg exigiría verificar la firma (aquí, simplificado: rechaza sin verificar).
    (StatusCode::UNAUTHORIZED, "{\"error\":\"invalid_token\"}".into())
}

async fn arranca(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("127.0.0.1:{}", addr.port())
}

async fn get_con_token(cliente: &reqwest::Client, url: &str, token: &str) -> (u16, String) {
    let r = cliente.get(url).header("Authorization", token).send().await.unwrap();
    let s = r.status().as_u16();
    (s, r.text().await.unwrap_or_default())
}

#[tokio::test]
async fn alg_none_logra_bypass_y_el_oraculo_lo_confirma() {
    let host = arranca(Router::new().route("/perfil", get(perfil))).await;
    let url = format!("http://{host}/perfil");
    let cliente = reqwest::Client::new();

    // CONTROL (dir. 33): un token basura debe ser RECHAZADO (401).
    let (s_control, _) = get_con_token(&cliente, &url, "Bearer basura.no.jwt").await;
    assert_eq!(s_control, 401, "el control inválido debe ser rechazado");

    // ATAQUE: forjar alg:none con role=admin (partiendo de un token de usuario normal).
    let payload = serde_json::json!({"sub": "victima", "role": "user"});
    let mutado = auth::mutar_payload(&payload, &[("role", serde_json::json!("admin"))]);
    let variantes = auth::forjar_alg_none(&mutado);

    // Al menos una variante logra acceso de admin, y el oráculo lo confirma.
    let mut confirmado = false;
    for v in &variantes {
        let (s, body) = get_con_token(&cliente, &url, v).await;
        if auth::es_bypass_confirmado(s_control, s, &body) {
            assert!(body.contains("\"role\":\"admin\""), "escaló a admin de verdad");
            confirmado = true;
            break;
        }
    }
    assert!(confirmado, "alg:none debe lograr bypass en el servidor vulnerable");
}

#[tokio::test]
async fn servidor_que_verifica_no_da_falso_positivo() {
    // PAREJA (dir. 33): un servidor que NO confía en alg:none (rechaza todo token no
    // verificado) NO debe producir un bypass — el oráculo no debe confirmar nada.
    async fn perfil_seguro(_headers: HeaderMap) -> (axum::http::StatusCode, String) {
        // Siempre exige firma válida (que no tenemos) → 401.
        (axum::http::StatusCode::UNAUTHORIZED, "{\"error\":\"invalid_token\"}".into())
    }
    let host = arranca(Router::new().route("/perfil", get(perfil_seguro))).await;
    let url = format!("http://{host}/perfil");
    let cliente = reqwest::Client::new();

    let (s_control, _) = get_con_token(&cliente, &url, "Bearer basura.no.jwt").await;
    let mutado = auth::mutar_payload(&serde_json::json!({"role":"user"}), &[("role", serde_json::json!("admin"))]);
    for v in &auth::forjar_alg_none(&mutado) {
        let (s, body) = get_con_token(&cliente, &url, v).await;
        assert!(!auth::es_bypass_confirmado(s_control, s, &body), "un server seguro no da bypass");
    }
}
