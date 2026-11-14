//! E2E del motor adaptativo contra un objetivo REAL en localhost (directiva 28:
//! cruza la frontera con transporte HTTP de verdad —reqwest, inyección en
//! parámetros, oráculo por contenido, BD—, no una sonda simulada). RIESGO CERO:
//! todo el tráfico se queda en 127.0.0.1; un baneo aquí es imposible.
//!
//! El servidor imita un filtro SSRF real: bloquea la IP de metadata (literal y
//! codificada) con 403, y solo cede a un HOST ALTERNO (metadata.google.internal /
//! nip.io), devolviendo entonces metadata AWS falsa. Así el ciclo 1 tiene que
//! AGOTAR la familia de codificación antes de acertar (muchas sondas), y el ciclo
//! 2 —que recuerda— acierta directo. Es el demo de «cómo funciona», con HTTP real.
//!
//! Correr y VERLO:  cargo test --test arnm_e2e -- --nocapture

use axum::{http::StatusCode, http::Uri, routing::get, Router};

use nexus::arnm::{self, Resultado, SondaHttp};
use nexus::db;
use nexus::protection::{Guard, ProtectionConfig};
use nexus::secuencias;

/// El endpoint "vulnerable": busca la URL del parámetro `url` (la SSRF). Filtra
/// la IP de metadata en cualquier codificación numérica; solo cede al host
/// alterno, y ahí exfiltra credenciales AWS (falsas).
async fn fetch(uri: Uri) -> (StatusCode, String) {
    // La query cruda: los marcadores del host alterno (dominio con puntos) y la
    // IP viajan sin percent-encoding, así que `.contains()` sobre ella basta.
    let url = uri.query().unwrap_or_default();
    if url.contains("metadata.google.internal") || url.contains("nip.io") {
        (
            StatusCode::OK,
            r#"{"Code":"Success","AccessKeyId":"ASIAE2E","SecretAccessKey":"secret","ami-launch-index":0}"#
                .to_string(),
        )
    } else {
        // literal, decimal, hex, octal, IPv6-map, confusión: todo filtrado.
        (StatusCode::FORBIDDEN, "Blocked host: private ip".to_string())
    }
}

async fn levantar_objetivo() -> std::net::SocketAddr {
    let app = Router::new().route("/fetch", get(fetch));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn dos_ciclos_contra_objetivo_real_en_localhost() {
    let addr = levantar_objetivo().await;
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("e2e.db"), 4).await.unwrap();

    let cliente = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let url_objetivo = format!("http://{addr}/fetch?url=x");
    let sonda = SondaHttp { cliente: &cliente, url_objetivo: url_objetivo.clone() };

    let host = "objetivo-e2e.local";
    let mut guard = Guard::new(ProtectionConfig::default());
    // pausa 0: el test no espera de verdad (el anti-baneo se prueba aparte).
    let mut rng = || 0.5;

    // CICLO 1: el motor no conoce este objetivo. Adapta desde cero por HTTP real.
    let r1 = arnm::cazar_y_recordar(&pool, &sonda, "prog", host, 100, &mut guard, 0, &mut rng, &arnm::objetivos_base()[..4])
        .await
        .unwrap();
    let (fam1, pay1, n1) = confirmado(&r1, "ciclo 1");

    // CICLO 2: mismo objetivo, misma huella. Lidera con la mutación recordada.
    let r2 = arnm::cazar_y_recordar(&pool, &sonda, "prog", host, 100, &mut guard, 0, &mut rng, &arnm::objetivos_base()[..4])
        .await
        .unwrap();
    let (fam2, pay2, n2) = confirmado(&r2, "ciclo 2");

    println!("\n  ══ E2E: motor adaptativo REAL contra {url_objetivo} ══");
    println!("  (el objetivo filtra la IP en toda codificación; solo cede a host alterno)");
    println!("  CICLO 1 (adapta desde cero): {n1} sondas HTTP → gana {fam1} con {pay1}");
    println!("  CICLO 2 (recuerda):          {n2} sondas HTTP → gana {fam2}");
    println!("  la memoria ahorró {} peticiones reales ({n1}→{n2})\n", n1.saturating_sub(n2));

    assert_eq!(fam1, "host-alterno", "ciclo 1 descubre host-alterno por HTTP real");
    assert_eq!(fam2, fam1, "ciclo 2 confirma la MISMA mutación recordada");
    assert_eq!(pay2, pay1, "mismo payload ganador");
    assert!(n2 < n1, "la memoria reduce las peticiones reales: {n2} < {n1}");

    // La secuencia CONFIRMADA quedó en la memoria, vigente (la persistencia del
    // HALLAZGO la hace `procesar_url`, cubierta en las pruebas de fase; aquí el foco
    // es la adaptación + memoria por HTTP real). Camino A (2026-08-26): las variantes
    // IP amuralladas (403) de la adaptación también se guardan ahora, así que se
    // cuenta solo la CONFIRMADA —el acierto host-alterno—, no toda fila viva.
    assert_eq!(secuencias::contar_confirmadas(&pool, host).await.unwrap(), 1);
}

fn confirmado<'a>(r: &'a Resultado, cual: &str) -> (&'a str, &'a str, u32) {
    match r {
        Resultado::Confirmado { familia, payload_ganador, intentos, .. } => {
            (familia.nombre(), payload_ganador.as_str(), *intentos)
        }
        Resultado::Seco { intentos, .. } => panic!("{cual}: salió SECO ({intentos} sondas)"),
        Resultado::Detenido { motivo, .. } => panic!("{cual}: DETENIDO — {motivo}"),
        Resultado::Saltado { causa, .. } => panic!("{cual}: SALTADO por memoria negativa ({causa:?})"),
    }
}
