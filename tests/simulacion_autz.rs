//! SIMULACIÓN a escala del motor de control de acceso (directiva 8: 100+
//! operaciones, con concurrencia y caminos de error, midiendo la discriminación
//! FP/FN de verdad, no un caso suelto).
//!
//! Un stub axum sirve SIETE categorías de endpoint que modelan los desenlaces
//! reales; se corren 20 de cada (140 endpoints, 420 peticiones — dueño/par/anónimo
//! por endpoint) de forma CONCURRENTE y se cuenta cuántas marca. Invariante: marca
//! las 40 vulnerables (idor + reflejo) y NINGUNA de las 100 seguras —incluida la
//! categoría PÚBLICO, que el anónimo también obtiene—. Cero falsos positivos.

use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use nexus::autz::{self, Confianza, Costura, Identidad, Papel};

fn cookie_val(h: &HeaderMap) -> String {
    h.get("cookie").and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}
fn es_alice(h: &HeaderMap) -> bool {
    cookie_val(h).contains("ALICE")
}

// Cuerpo del recurso del dueño, largo y estable por id.
fn recurso(id: &str) -> String {
    format!("RECURSO-PRIVADO-DEL-DUENO-numero-{id}-con-relleno-para-pasar-de-64-bytes-0123456789")
}

// --- Categoría VULNERABLE (IDOR HORIZONTAL real): exige estar AUTENTICADO
//     (cualquier cookie), pero NO comprueba PROPIEDAD → alice y bob ven el dato
//     de alice. El anónimo (sin cookie) es DENEGADO: hay control que saltar. ---
async fn h_idor(Path(id): Path<String>, h: HeaderMap) -> Response {
    if cookie_val(&h).is_empty() {
        (StatusCode::UNAUTHORIZED, "").into_response()
    } else {
        (StatusCode::OK, recurso(&id)).into_response()
    }
}

// --- VULNERABLE con CREDENCIAL REFLEJADA: mismo recurso (auth requerida), pero el
//     cuerpo lleva el token de quien pide. La normalización debe hacer que case
//     (Alta). El anónimo, denegado. ---
async fn h_reflect(Path(id): Path<String>, h: HeaderMap) -> Response {
    if cookie_val(&h).is_empty() {
        (StatusCode::UNAUTHORIZED, "").into_response()
    } else {
        (StatusCode::OK, format!("{} tu-token:{}", recurso(&id), cookie_val(&h))).into_response()
    }
}

// --- SEGURO PÚBLICO: el recurso lo obtiene CUALQUIERA, incluido el anónimo (una
//     fuente, un SVG, .well-known). El par ve lo mismo que el dueño, pero NO es
//     IDOR —no hay control que saltar—. Es el FP medido el 2026-08-24: sin la
//     línea base anónima, esto se marcaba como IDOR Alta. ---
async fn h_publico(Path(id): Path<String>) -> String {
    recurso(&id)
}

// --- SEGURO 302: el ajeno es redirigido a login (no-2xx con no-follow) ---
async fn h_private(Path(id): Path<String>, h: HeaderMap) -> Response {
    if es_alice(&h) {
        (StatusCode::OK, recurso(&id)).into_response()
    } else {
        (StatusCode::FOUND, [("location", "/login")]).into_response()
    }
}

// --- SEGURO 404: el ajeno no existe (la señal de medico) ---
async fn h_notfound(Path(id): Path<String>, h: HeaderMap) -> Response {
    if es_alice(&h) {
        (StatusCode::OK, recurso(&id)).into_response()
    } else {
        (StatusCode::NOT_FOUND, "").into_response()
    }
}

// --- SEGURO 403: el ajeno tiene prohibido ---
async fn h_forbidden(Path(id): Path<String>, h: HeaderMap) -> Response {
    if es_alice(&h) {
        (StatusCode::OK, recurso(&id)).into_response()
    } else {
        (StatusCode::FORBIDDEN, "").into_response()
    }
}

// --- NO ES FUGA: cada identidad ve LO SUYO (cuerpos distintos) ---
async fn h_ownonly(Path(id): Path<String>, h: HeaderMap) -> Response {
    let quien = if es_alice(&h) { "alice" } else { "bob-con-un-perfil-de-longitud-claramente-distinta" };
    (StatusCode::OK, format!("PERFIL-de-{quien}-recurso-{id}-relleno-para-pasar-de-64-bytes-000")).into_response()
}

#[tokio::test]
async fn simulacion_autz_120_endpoints_discrimina_sin_falsos_positivos() {
    let app = axum::Router::new()
        .route("/idor/{id}", get(h_idor))
        .route("/reflect/{id}", get(h_reflect))
        .route("/publico/{id}", get(h_publico))
        .route("/private/{id}", get(h_private))
        .route("/notfound/{id}", get(h_notfound))
        .route("/forbidden/{id}", get(h_forbidden))
        .route("/ownonly/{id}", get(h_ownonly));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let client = autz::cliente("nexus-sim").unwrap();
    let ids = vec![
        Identidad { papel: Papel::Dueno, cabeceras: vec![("Cookie".into(), "session=ALICE_TOKEN_LARGO_1".into())] },
        Identidad { papel: Papel::Par, cabeceras: vec![("Cookie".into(), "session=BOB_TOKEN_LARGO_2".into())] },
    ];
    let base = format!("http://{addr}");

    // Categorías: (prefijo, ¿debe marcar?)
    let categorias: &[(&str, bool)] = &[
        ("idor", true),
        ("reflect", true),
        ("publico", false), // recurso público: el anónimo también accede → NO IDOR
        ("private", false),
        ("notfound", false),
        ("forbidden", false),
        ("ownonly", false),
    ];
    const POR_CATEGORIA: usize = 20;

    // Lanzar los 120 diffs CONCURRENTES.
    let mut tareas = Vec::new();
    for (cat, debe_marcar) in categorias.iter().copied() {
        for i in 0..POR_CATEGORIA {
            let client = client.clone();
            let ids = ids.clone();
            let sol = autz::Solicitud { url: format!("{base}/{cat}/{i}") };
            tareas.push(tokio::spawn(async move {
                let (v, _) = autz::diffear(&client, &sol, &ids, autz::UMBRAL_DEFECTO).await.unwrap();
                (cat, debe_marcar, v)
            }));
        }
    }

    let mut tp = 0u32; // vulnerables marcadas
    let mut fn_ = 0u32; // vulnerables perdidas
    let mut tn = 0u32; // seguras no marcadas
    let mut fp = 0u32; // seguras marcadas (¡malo!)
    let mut fp_urls = Vec::new();
    let mut altas_reflect = 0u32;

    for t in tareas {
        let (cat, debe_marcar, veredictos) = t.await.unwrap();
        let marcada = !veredictos.is_empty();
        match (debe_marcar, marcada) {
            (true, true) => {
                tp += 1;
                if cat == "reflect" && veredictos.iter().any(|h| h.veredicto.confianza == Confianza::Alta) {
                    altas_reflect += 1;
                }
                assert_eq!(veredictos[0].veredicto.costura, Costura::IdorHorizontal, "las vulnerables son IDOR horizontal");
            }
            (true, false) => fn_ += 1,
            (false, false) => tn += 1,
            (false, true) => {
                fp += 1;
                fp_urls.push(cat);
            }
        }
    }

    eprintln!("\n=== SIMULACIÓN autz — 140 endpoints, 420 peticiones (dueño/par/anónimo), concurrentes ===");
    eprintln!("  Verdaderos positivos (vulnerable → marcada):  {tp}/40");
    eprintln!("  Falsos negativos    (vulnerable → PERDIDA):   {fn_}");
    eprintln!("  Verdaderos negativos(segura → no marcada):    {tn}/100");
    eprintln!("  Falsos positivos    (segura → MARCADA):       {fp}  {fp_urls:?}");
    eprintln!("  Reflejo detectado con confianza ALTA:         {altas_reflect}/20 (normalización)");

    assert_eq!(fp, 0, "CERO falsos positivos: ninguna segura debe marcarse (incluido el recurso PÚBLICO)");
    assert_eq!(tp, 40, "las 40 vulnerables (idor+reflect) deben marcarse");
    assert_eq!(fn_, 0, "ninguna vulnerable perdida");
    assert_eq!(tn, 100, "las 100 seguras (público incluido) deben quedar sin marcar");
    assert_eq!(altas_reflect, 20, "la normalización sube el reflejo a Alta en las 20");
}

// --- Categoría ERROR: el servidor falla (500/503) — el motor no debe reventar
//     ni marcar (no-2xx = None), y las vulnerables mezcladas siguen saliendo. ---
async fn h_error500() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response()
}
async fn h_error503() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, "").into_response()
}

#[tokio::test]
async fn simulacion_autz_resiste_errores_inyectados() {
    let app = axum::Router::new()
        .route("/idor/{id}", get(h_idor))
        .route("/e500/{id}", get(|_p: Path<String>| h_error500()))
        .route("/e503/{id}", get(|_p: Path<String>| h_error503()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let client = autz::cliente("nexus-sim-err").unwrap();
    let ids = vec![
        Identidad { papel: Papel::Dueno, cabeceras: vec![("Cookie".into(), "session=ALICE_TOKEN_LARGO_1".into())] },
        Identidad { papel: Papel::Par, cabeceras: vec![("Cookie".into(), "session=BOB_TOKEN_LARGO_2".into())] },
    ];
    let base = format!("http://{addr}");

    // 150 peticiones concurrentes: 50 idor (deben marcar) + 50 e500 + 50 e503
    // (no deben marcar ni reventar). El dueño en e500/e503 recibe no-2xx → None.
    let mut tareas = Vec::new();
    for cat in ["idor", "e500", "e503"] {
        for i in 0..50 {
            let client = client.clone();
            let ids = ids.clone();
            let sol = autz::Solicitud { url: format!("{base}/{cat}/{i}") };
            tareas.push(tokio::spawn(async move {
                // No debe entrar en pánico pase lo que pase.
                let r = autz::diffear(&client, &sol, &ids, autz::UMBRAL_DEFECTO).await;
                (cat, r.map(|t| t.0).unwrap_or_default())
            }));
        }
    }
    let mut idor_marcadas = 0u32;
    let mut error_marcadas = 0u32;
    for t in tareas {
        let (cat, v) = t.await.unwrap();
        if cat == "idor" {
            if !v.is_empty() { idor_marcadas += 1; }
        } else if !v.is_empty() {
            error_marcadas += 1;
        }
    }
    eprintln!("\n=== SIMULACIÓN error-injection — 150 peticiones concurrentes ===");
    eprintln!("  idor marcadas:  {idor_marcadas}/50 (deben ser 50)");
    eprintln!("  error marcadas: {error_marcadas} (deben ser 0)");
    assert_eq!(idor_marcadas, 50, "las vulnerables siguen saliendo pese al ruido de errores");
    assert_eq!(error_marcadas, 0, "un 500/503 nunca marca (no-2xx = None); y no revienta");
}
