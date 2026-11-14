// SPDX-License-Identifier: LicenseRef-Propietario
//! E2E del ENGANCHE parámetros-ocultos → mass-assignment (veta mindalá, D28/D33).
//!
//! Escenario: un endpoint cuyo bug de mass-assignment está SOLO en un campo NO OBVIO
//! (`owner_id`), que el listado estático `CAMPOS_SENSIBLES` no enumera. El servidor:
//!   - refleja `owner_id` en el GET (el descubridor lo encuentra),
//!   - persiste `owner_id` en el PATCH pero IGNORA los campos privilegiados clásicos
//!     (`role`, `is_admin`…) — el bug es solo el de la ownership no documentada.
//!
//! ROJO/discriminación (D33): con descubrimiento ON se halla el mass-assignment; con OFF
//! el listado estático lo PIERDE (0). El enganche es exactamente lo que convierte el fallo
//! perdido en hallazgo. CONTROL: un servidor que refleja `owner_id` en GET pero NO lo
//! persiste en PATCH → 0 (descubrir un campo no basta; se exige que PEGUE).

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::Uri;
use axum::routing::get;
use axum::Router;

use nexus::autz::{Identidad, Papel};
use nexus::{db, mass_assign};

type Estado = Arc<Mutex<serde_json::Map<String, serde_json::Value>>>;

fn valor_de(qs: &str, clave: &str) -> Option<String> {
    qs.split('&').find_map(|par| {
        let (k, v) = par.split_once('=')?;
        (k == clave).then(|| v.to_string())
    })
}

/// GET del objeto propio. Sin query → devuelve el estado actual (lo que usa el re-fetch).
/// Con `owner_id` en la query → lo REFLEJA (el backend lo procesa): así el descubridor de
/// parámetros ocultos lo detecta. Los nombres basura de la línea base no se reflejan.
async fn get_obj(State(st): State<Estado>, uri: Uri) -> String {
    let cuerpo = serde_json::Value::Object(st.lock().unwrap().clone()).to_string();
    match valor_de(uri.query().unwrap_or(""), "owner_id") {
        Some(v) => format!("{cuerpo} owner_id={v}"),
        None => cuerpo,
    }
}

/// PATCH VULNERABLE solo en `owner_id`: persiste ese campo e IGNORA role/is_admin/etc.
async fn patch_solo_owner(State(st): State<Estado>, body: String) -> String {
    if let Ok(serde_json::Value::Object(m)) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(v) = m.get("owner_id") {
            st.lock().unwrap().insert("owner_id".to_string(), v.clone());
        }
    }
    "ok".to_string()
}

/// PATCH del CONTROL: no persiste NADA (el objeto no cambia).
async fn patch_ignora(State(_st): State<Estado>, _body: String) -> String {
    "ok".to_string()
}

async fn arranca(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("127.0.0.1:{}", addr.port())
}

async fn pool_temp() -> (tempfile::TempDir, sqlx::SqlitePool) {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("t.db"), 2).await.unwrap();
    (dir, pool)
}

fn dueno() -> Vec<Identidad> {
    vec![Identidad { papel: Papel::Dueno, cabeceras: vec![] }]
}

#[tokio::test]
async fn descubrir_convierte_un_mass_assignment_perdido_en_hallazgo() {
    let st: Estado = Arc::new(Mutex::new(serde_json::Map::new()));
    let app = Router::new()
        .route("/obj", get(get_obj).patch(patch_solo_owner))
        .with_state(st);
    let host = arranca(app).await;
    let url = format!("http://{host}/obj");

    // CON descubrimiento: encuentra `owner_id` (reflejado en GET), lo inyecta, PEGA → 1.
    let (_d1, pool) = pool_temp().await;
    let n = mass_assign::fase_mass_assign(&pool, "acme", &dueno(), std::slice::from_ref(&url), true, true, 5, None)
        .await
        .unwrap();
    assert_eq!(n, 1, "con descubrimiento se halla el mass-assignment del campo no documentado");

    // Y el hallazgo es sobre el campo DESCUBIERTO owner_id.
    let vuln: String =
        sqlx::query_scalar("SELECT vuln_name FROM findings WHERE url = ?1").bind(&url)
            .fetch_one(&pool).await.unwrap();
    assert_eq!(vuln, "mass-assignment-owner_id", "el hallazgo es sobre el campo descubierto");

    // SIN descubrimiento: el listado estático NO enumera owner_id → lo PIERDE (0).
    let st2: Estado = Arc::new(Mutex::new(serde_json::Map::new()));
    let app2 = Router::new()
        .route("/obj", get(get_obj).patch(patch_solo_owner))
        .with_state(st2);
    let host2 = arranca(app2).await;
    let url2 = format!("http://{host2}/obj");
    let (_d2, pool2) = pool_temp().await;
    let n0 = mass_assign::fase_mass_assign(&pool2, "acme", &dueno(), &[url2], true, false, 5, None)
        .await
        .unwrap();
    assert_eq!(n0, 0, "sin descubrimiento el listado estático pierde el campo no documentado");
}

#[tokio::test]
async fn control_reflejar_sin_persistir_no_es_hallazgo() {
    // El servidor refleja owner_id en GET (se DESCUBRE) pero el PATCH no persiste nada.
    // Descubrir un parámetro no es un mass-assignment: se exige que PEGUE al releer.
    let st: Estado = Arc::new(Mutex::new(serde_json::Map::new()));
    let app = Router::new()
        .route("/obj", get(get_obj).patch(patch_ignora))
        .with_state(st);
    let host = arranca(app).await;
    let url = format!("http://{host}/obj");

    let (_d, pool) = pool_temp().await;
    let n = mass_assign::fase_mass_assign(&pool, "acme", &dueno(), &[url], true, true, 5, None)
        .await
        .unwrap();
    assert_eq!(n, 0, "reflejar un campo sin persistirlo no es mass-assignment");
}
