//! E2E del panel: arranca el binario real (router axum + BD sembrada) y hace que
//! **Chromium headless DIBUJE la página**, luego afirma sobre el DOM resultante.
//!
//! Por qué un navegador y no un `assert` sobre el HTML de axum (directiva 28): un
//! fragmento de maud correcto en el cuerpo HTTP no prueba que la pantalla se vea
//! —con htmx, un `hx-swap` mal puesto devuelve el mismo 200 con el mismo cuerpo—.
//! Aquí Chromium parsea, ejecuta htmx y construye el DOM; afirmamos sobre lo que
//! el navegador realmente montó.
//!
//! Este arnés es la pieza reutilizable del piloto (directiva 9): «siembra BD →
//! levanta el binario en un puerto efímero → dibuja en Chromium → afirma DOM» es
//! el mismo esqueleto para todos los proyectos que migren a maud+htmx. Se
//! extraerá a un módulo común cuando el segundo proyecto lo estrene.

use mirilla::{Navegador, buscar_chromium};
use nexus::db;

/// Localiza el binario de Chromium. Si no está, **falla ruidosamente** en vez de
/// pasar en silencio (directivas 30 y 33): un E2E que se salta solo es
/// indistinguible de uno que pasa, y este test existe precisamente para cruzar
/// Pinta `url` en un Chromium de verdad y devuelve el DOM ya construido.
///
/// Aquí vivían 50 líneas propias —`buscar_chromium` y un `dibujar` con
/// `--dump-dom`—: eran la CUARTA copia del mismo arnés, y la última que quedaba
/// (informes, medico, chasqui e inventario ya consumen `mirilla`).
///
/// **La condición que se espera es propia de nexus**, y por eso el arnés es
/// reutilizable sin ser un molde: los otros cuatro esperan `data-boi="listo"`
/// porque cargan `boi`; nexus no lleva JavaScript propio —y eso es correcto, el
/// estándar pide el mínimo—, así que lo que hay que esperar es que el documento
/// esté completo y htmx haya quedado cableado.
fn dibujar(chromium: &str, url: &str) -> String {
    let mut nav = Navegador::abrir(chromium);
    nav.ir(url);
    nav.esperar(
        "document.readyState === 'complete' && !!window.htmx",
        "la página no terminó de cargar, o htmx no llegó a definirse (CSP, MIME \
         o un 404 del estático)",
    );
    nav.dom()
}

/// helper `seed_verified` de la suite de integración.
async fn sembrar(dir: &std::path::Path) -> sqlx::SqlitePool {
    let pool = db::open(&dir.join("nexus.db"), 4).await.unwrap();
    let pid = db::upsert_program(&pool, "acme").await.unwrap();
    let f = db::NewFinding {
        program_name: "acme".into(),
        vuln_name: "sql-injection".into(),
        severity: "critical".into(),
        url: "https://vuln.example.com/?id=1".into(),
        cwe: None,
        evidencia: None,
    };
    db::insert_finding_dedup(&pool, &f, pid).await.unwrap();
    let id = db::fetch_verifiable(&pool, 10).await.unwrap()[0].id;
    db::apply_verification(
        &pool, id, "VERIFIED", true, "sqlmap", "high", true, Some("UNION-based"), "sqli",
        Some("[sqlmap PoC]"), true, Some("3/3"),
    )
    .await
    .unwrap();
    pool
}

// multi_thread: el servidor corre en otro worker mientras bloqueamos el hilo en
// el subproceso de Chromium. Con el runtime de un solo hilo, `Command::output`
// congelaría la tarea del servidor y no habría a quién conectarse.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn el_panel_se_dibuja_con_tarjetas_y_tabla_en_un_navegador() {
    let chromium = buscar_chromium();
    let dir = tempfile::tempdir().unwrap();
    let pool = sembrar(dir.path()).await;

    // Levanta el binario real en un puerto efímero.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = nexus::web::router(pool);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let dom = dibujar(&chromium, &format!("http://127.0.0.1:{port}/"));

    // ── Positivos: lo que el navegador DEBE haber montado ──
    // Las seis tarjetas de estadísticas (por sus etiquetas).
    for etiqueta in ["Total", "Verificados", "Explotables", "Falsos +", "Manual", "Reintento"] {
        assert!(dom.contains(etiqueta), "falta la tarjeta «{etiqueta}» en el DOM dibujado");
    }
    // La fila del hallazgo sembrado, con su chip de severidad y la herramienta.
    assert!(dom.contains("sql-injection"), "no se dibujó el hallazgo");
    assert!(dom.contains("chip critical"), "el chip de severidad no llevó su clase");
    assert!(dom.contains("sqlmap"), "no se dibujó la herramienta de verificación");
    // htmx cargó y quedó cableado al contenedor.
    assert!(dom.contains("htmx.org") || dom.contains("hx-get"), "htmx no está en la página");

    // ── Negativo de control (directiva 33): con un hallazgo sembrado, el mensaje
    // de vacío NO puede aparecer. Si apareciera, estaríamos leyendo una pantalla
    // que no refleja los datos. ──
    assert!(!dom.contains("Sin hallazgos todavía"), "salió el estado vacío teniendo datos");
}
