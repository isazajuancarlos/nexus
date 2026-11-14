// SPDX-License-Identifier: LicenseRef-Propietario
//! E2E del descubridor de parámetros ocultos (D28): contra un servidor axum REAL que
//! REFLEJA un parámetro concreto (`debug`) e ignora el resto, `descubrir` —con reqwest de
//! verdad y la bisección real— debe encontrar EXACTAMENTE ese parámetro. El control (D33)
//! es un endpoint que ignora TODO: ahí no debe inventar ninguno. Cruza la frontera del
//! programa (HTTP real), no de estructura a estructura.

use axum::{http::Uri, routing::get, routing::post, Router};

use nexus::oraculo_diferencial::Identidad;
use nexus::parametros::{self, Config, Metodo};

/// Valor de `clave` en una cadena urlencoded `k=v&k2=v2` (los extractores `Query`/`Form`
/// de axum están gateados por feature aquí, así que se parsea a mano en la prueba).
fn valor_de(qs: &str, clave: &str) -> Option<String> {
    qs.split('&').find_map(|par| {
        let (k, v) = par.split_once('=')?;
        (k == clave).then(|| v.to_string())
    })
}

/// VULNERABLE: si llega el parámetro `debug`, lo REFLEJA en el cuerpo (el backend lo
/// procesa). Cualquier otro parámetro se ignora → cuerpo fijo.
async fn refleja_debug(uri: Uri) -> String {
    match valor_de(uri.query().unwrap_or(""), "debug") {
        Some(v) => format!("modo debug: {v}\nlínea dos"),
        None => "página normal\nlínea dos".to_string(),
    }
}

/// CONTROL: ignora TODOS los parámetros — cuerpo idéntico siempre.
async fn ignora_todo(_uri: Uri) -> String {
    "página estable\nlínea dos".to_string()
}

/// VULNERABLE por POST-form: refleja `debug` del cuerpo urlencoded.
async fn refleja_debug_form(cuerpo: String) -> String {
    match valor_de(&cuerpo, "debug") {
        Some(v) => format!("modo debug: {v}\nlínea dos"),
        None => "página normal\nlínea dos".to_string(),
    }
}

async fn arranca(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("127.0.0.1:{}", addr.port())
}

fn dic() -> Vec<String> {
    // Un diccionario que contiene el oculto (`debug`) entre varios inertes.
    ["id", "user_id", "debug", "role", "admin", "preview", "expand", "callback"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

#[tokio::test]
async fn descubre_el_parametro_reflejado_por_get() {
    let host = arranca(Router::new().route("/api", get(refleja_debug))).await;
    let url = format!("http://{host}/api");
    let cliente = reqwest::Client::new();

    let hallados = parametros::descubrir(&cliente, &url, &Identidad::anonimo(), &dic(), &Config::default())
        .await
        .expect("línea base establecida");

    let nombres: Vec<&str> = hallados.iter().map(|d| d.nombre.as_str()).collect();
    assert_eq!(nombres, vec!["debug"], "encuentra EXACTAMENTE el parámetro oculto reflejado");
    assert_eq!(hallados[0].senal, parametros::Senal::Reflexion, "por reflexión del centinela");
}

#[tokio::test]
async fn control_endpoint_que_ignora_todo_no_produce_falsos() {
    // ROJO/control (D33): un endpoint que ignora todos los parámetros NO debe dar ninguno.
    // Sin la disciplina de anomalía, cualquier sonda "distinta" pasaría por efectiva.
    let host = arranca(Router::new().route("/api", get(ignora_todo))).await;
    let url = format!("http://{host}/api");
    let cliente = reqwest::Client::new();

    let hallados = parametros::descubrir(&cliente, &url, &Identidad::anonimo(), &dic(), &Config::default())
        .await
        .expect("línea base establecida");
    assert!(hallados.is_empty(), "endpoint estable e insensible → 0 parámetros ocultos");
}

#[tokio::test]
async fn descubre_por_post_form() {
    let host = arranca(Router::new().route("/api", post(refleja_debug_form))).await;
    let url = format!("http://{host}/api");
    let cliente = reqwest::Client::new();
    let cfg = Config { metodo: Metodo::PostForm, ..Config::default() };

    let hallados = parametros::descubrir(&cliente, &url, &Identidad::anonimo(), &dic(), &cfg)
        .await
        .expect("línea base establecida");
    let nombres: Vec<&str> = hallados.iter().map(|d| d.nombre.as_str()).collect();
    assert_eq!(nombres, vec!["debug"], "el driver POST-form también aísla el oculto");
}
