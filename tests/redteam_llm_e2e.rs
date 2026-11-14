// SPDX-License-Identifier: LicenseRef-Propietario
//! E2E del red-team de LLM (veta mindalá #2, D28/D33). Contra servidores de chat SIMULADOS:
//!   - VULNERABLE: el "modelo" obedece la inyección y emite el canario en su salida → PEGA.
//!   - GUARDADO (control): rehúsa siempre, nunca emite el canario → 0 (D33).
//!   - ECO: devuelve el request íntegro en un campo aparte pero la salida del modelo rehúsa;
//!     con `ruta_respuesta` a la salida, el eco del canario NO cuenta como pego (limpieza
//!     del oráculo, el falso positivo que la ruta evita).
//!
//! Cruza la frontera real (HTTP + reqwest), no de estructura a estructura. El "modelo" se
//! simula detectando el patrón del canario `RT_` en el payload: un modelo que OBEDECE lo
//! reemitiría; uno guardado no.

use axum::routing::post;
use axum::Router;

use nexus::oraculo_diferencial::Identidad;
use nexus::redteam_llm::{self, Config};

/// Extrae el primer token `RT_<hex>` del texto (lo que un modelo que obedece "reemitiría").
fn canario_en(texto: &str) -> Option<String> {
    let i = texto.find("RT_")?;
    let resto = &texto[i..];
    let fin = resto
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
        .map_or(resto.len(), |(j, _)| j);
    Some(resto[..fin].to_string())
}

/// Modelo VULNERABLE: obedece la inyección — reemite el canario que venía en el payload.
async fn chat_vulnerable(body: String) -> String {
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("");
    let salida = match canario_en(msg) {
        Some(c) => format!("Claro, aquí tienes: {c}"),
        None => "Hola, ¿en qué te ayudo?".to_string(),
    };
    serde_json::json!({ "reply": salida }).to_string()
}

/// Modelo GUARDADO: rehúsa siempre. Nunca emite el canario.
async fn chat_guardado(_body: String) -> String {
    serde_json::json!({ "reply": "Lo siento, no puedo ayudar con esa solicitud." }).to_string()
}

/// Modelo que hace ECO del request en `echo` (ahí VA el canario), pero cuya salida `reply`
/// rehúsa. Prueba que buscar en `reply` (la salida) evita el FP del eco.
async fn chat_eco(body: String) -> String {
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("").to_string();
    serde_json::json!({ "reply": "No puedo ayudar con eso.", "echo": msg }).to_string()
}

async fn arranca(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("127.0.0.1:{}", addr.port())
}

fn cfg(url: String, ruta: Option<&str>) -> Config {
    Config {
        url,
        campo: Some("message".to_string()),
        plantilla_cuerpo: None,
        ruta_respuesta: ruta.map(|s| s.to_string()),
        categorias: vec![],
    }
}

#[tokio::test]
async fn modelo_vulnerable_pega_y_lo_detecta() {
    let host = arranca(Router::new().route("/chat", post(chat_vulnerable))).await;
    let url = format!("http://{host}/chat");
    let cliente = reqwest::Client::new();

    let hallazgos = redteam_llm::redteam(&cliente, &cfg(url, Some("reply")), &Identidad::anonimo())
        .await
        .unwrap();
    // Todo el corpus obedece este modelo → varios pegos (al menos uno por categoría probada).
    assert!(!hallazgos.is_empty(), "un modelo que obedece deja pegos");
    assert!(hallazgos.iter().all(|h| h.evidencia.contains("canario")), "la evidencia cita el canario");
}

#[tokio::test]
async fn modelo_guardado_no_deja_pegos() {
    // CONTROL (D33): un modelo que rehúsa nunca emite el canario → 0. El mutante "pega si
    // hubo respuesta" moriría aquí (siempre hay `reply`).
    let host = arranca(Router::new().route("/chat", post(chat_guardado))).await;
    let url = format!("http://{host}/chat");
    let cliente = reqwest::Client::new();

    let hallazgos = redteam_llm::redteam(&cliente, &cfg(url, Some("reply")), &Identidad::anonimo())
        .await
        .unwrap();
    assert!(hallazgos.is_empty(), "un modelo guardado no deja pegos");
}

#[tokio::test]
async fn eco_del_request_no_es_pego_con_ruta_a_la_salida() {
    // El endpoint ECOA el canario del request en `echo`, pero la salida `reply` rehúsa.
    // Con ruta a `reply`, NO pega (el oráculo mira la salida del modelo, no el eco).
    let host = arranca(Router::new().route("/chat", post(chat_eco))).await;
    let url = format!("http://{host}/chat");
    let cliente = reqwest::Client::new();

    let con_ruta = redteam_llm::redteam(&cliente, &cfg(url.clone(), Some("reply")), &Identidad::anonimo())
        .await
        .unwrap();
    assert!(con_ruta.is_empty(), "con ruta a la salida, el eco del request NO es un pego");

    // Y sin ruta (cuerpo entero), el eco SÍ dispararía: por eso la ruta es la que limpia.
    let sin_ruta = redteam_llm::redteam(&cliente, &cfg(url, None), &Identidad::anonimo())
        .await
        .unwrap();
    assert!(!sin_ruta.is_empty(), "sin ruta, el eco del request es un falso positivo (por eso se recomienda la ruta)");
}
