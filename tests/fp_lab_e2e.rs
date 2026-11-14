//! E2E del FP-lab (directiva 28: cruza la frontera — arranca el router `axum` de la app-trampa
//! y le habla por HTTP de verdad, no de estructura a estructura).
//!
//! Dos pruebas:
//! 1. **Forma de los endpoints** (directiva 33, la pareja): cada SAFE *parece* vulnerable pero
//!    no filtra; cada VULN lo es. Sin esto, el runner podría dar FPR=0/TPR=1 midiendo una app
//!    que no discrimina (todos los endpoints iguales) — el banco de solo-negativos que la
//!    directiva 33 prohíbe.
//! 2. **El runner sobre el lab**: `evaluar_sistema` da FPR=0 y TPR=1 sobre las clases cableadas.
//!    La clase XSS se cablea solo si hay Chromium; si no, se EXCLUYE diciéndolo (directiva 30),
//!    no se cuenta como fallo.

use nexus::config::Config;
use nexus::{fp_app, fp_lab};

fn find_chromium() -> Option<String> {
    for p in [
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
    ] {
        if std::path::Path::new(p).exists() {
            return Some(p.to_string());
        }
    }
    None
}

fn cfg_con_chromium() -> Config {
    use clap::Parser;
    let chromium = find_chromium().unwrap_or_else(|| "chromium".to_string());
    Config::parse_from(["nexus", "--chromium-path", &chromium, "scan"])
}

/// Levanta la app-trampa en un puerto efímero y devuelve `(base_url, handle)`.
async fn levantar() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = fp_app::router();
    let h = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://127.0.0.1:{port}"), h)
}

async fn get(cli: &reqwest::Client, url: &str) -> (u16, String) {
    let r = cli.get(url).send().await.unwrap();
    let s = r.status().as_u16();
    let b = r.text().await.unwrap();
    (s, b)
}

/// **La FORMA: cada SAFE parece vuln y cada VULN lo es.** Es el control que impide que el runner
/// mida una app degenerada donde todo es igual.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn los_endpoints_trampa_tienen_su_forma_safe_y_vuln() {
    let (base, servidor) = levantar().await;
    let cli = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    // ── SSRF ── echo (SAFE) refleja la URL pero NO filtra el secreto; real (VULN) sí.
    let url_secreto = format!("{base}/_internal/secret");
    let (_s, echo) = get(&cli, &format!("{base}/ssrf-echo?url={url_secreto}")).await;
    assert!(echo.contains("_internal/secret"), "el echo debe reflejar la URL (parece SSRF): {echo}");
    assert!(!echo.contains(fp_app::SECRETO_INTERNO), "el echo NO puede filtrar el secreto (es SAFE)");
    let (_s, real) = get(&cli, &format!("{base}/ssrf-real?url={url_secreto}")).await;
    assert!(real.contains(fp_app::SECRETO_INTERNO), "el SSRF real DEBE filtrar el secreto interno: {real}");
    // El fetch fuera de loopback se rechaza (la trampa no sale a la red).
    let (s_ext, _b) = get(&cli, &format!("{base}/ssrf-real?url=http://evil.example.com/")).await;
    assert_eq!(s_ext, 400, "ssrf-real solo permite loopback");

    // ── XSS ── encoded (SAFE) escapa; real (VULN) refleja crudo.
    let (_s, enc) = get(&cli, &format!("{base}/xss-encoded?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")).await;
    assert!(enc.contains("&lt;script&gt;"), "xss-encoded debe ESCAPAR el <script>: {enc}");
    assert!(!enc.contains("<script>alert(1)"), "xss-encoded NO puede reflejar el script crudo");
    let (_s, xreal) = get(&cli, &format!("{base}/xss-real?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")).await;
    assert!(xreal.contains("<script>alert(1)</script>"), "xss-real DEBE reflejar el script crudo: {xreal}");

    // ── IDOR ── genfields (SAFE) idéntico para dos ids; real (VULN) distinto.
    let (_s, g1) = get(&cli, &format!("{base}/idor-genfields?id=1")).await;
    let (_s, g2) = get(&cli, &format!("{base}/idor-genfields?id=2")).await;
    assert_eq!(g1, g2, "idor-genfields debe dar el MISMO cuerpo para dos ids (SAFE)");
    let (_s, r1) = get(&cli, &format!("{base}/idor-real?id=1")).await;
    let (_s, r2) = get(&cli, &format!("{base}/idor-real?id=2")).await;
    assert_ne!(r1, r2, "idor-real debe filtrar datos DISTINTOS por id (VULN)");

    // ── File-oracle ── /file 403 uniforme; /file-real 200 vs 404.
    let (fa, _b) = get(&cli, &format!("{base}/file?name={}", fp_app::ARCHIVO_EXISTE)).await;
    let (fb, _b) = get(&cli, &format!("{base}/file?name=zzz_no_existe")).await;
    assert_eq!((fa, fb), (403, 403), "/file debe ser 403 uniforme (SAFE)");
    let (ra, _b) = get(&cli, &format!("{base}/file-real?name={}", fp_app::ARCHIVO_EXISTE)).await;
    let (rb, _b) = get(&cli, &format!("{base}/file-real?name=zzz_no_existe")).await;
    assert_eq!((ra, rb), (200, 404), "/file-real debe discriminar 200/404 (VULN)");

    // ── User-enum ── /login mismo cuerpo; /login-real distinto.
    let (_s, la) = get(&cli, &format!("{base}/login?user={}", fp_app::USUARIO_VALIDO)).await;
    let (_s, lb) = get(&cli, &format!("{base}/login?user=nadie")).await;
    assert_eq!(la, lb, "/login debe dar el mismo cuerpo (SAFE)");
    let (_s, ra) = get(&cli, &format!("{base}/login-real?user={}", fp_app::USUARIO_VALIDO)).await;
    let (_s, rb) = get(&cli, &format!("{base}/login-real?user=nadie")).await;
    assert_ne!(ra, rb, "/login-real debe distinguir usuario válido de inexistente (VULN)");

    servidor.abort();
}

/// **El runner sobre el lab: FPR = 0 y TPR = 1 en las clases cableadas.** Mide el SISTEMA de
/// nexus (las gates de `refutacion` + el oráculo por ejecución de `browser`) contra HTTP real.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn el_runner_da_fpr_cero_y_tpr_uno_sobre_el_lab() {
    let (base, servidor) = levantar().await;
    let cfg = cfg_con_chromium();
    let hay_navegador = find_chromium().is_some();

    let res = fp_lab::evaluar_sistema(&base, &cfg, 2).await;

    // La clase XSS se cablea SII hay navegador (directiva 30: si no, se excluye diciéndolo).
    let xss = res.iter().find(|r| r.clase == "xss").expect("debe existir la fila xss");
    assert_eq!(xss.cableado, hay_navegador, "xss.cableado debe seguir la presencia de Chromium");
    if !hay_navegador {
        assert!(xss.nota.is_some(), "una clase no medida debe DECIR por qué (D30)");
    }

    // Ninguna trampa SAFE reportada, en NINGUNA clase (falla nombrando la clase).
    for r in &res {
        if r.cableado {
            assert_eq!(r.metricas.fp, 0, "falso positivo en la clase «{}»: {:?}", r.clase, r.metricas);
        }
    }

    let total = fp_lab::total_cableado(&res);
    assert_eq!(total.fpr(), 0.0, "FPR del sistema debe ser 0: {total:?}");
    assert_eq!(total.tpr(), 1.0, "TPR del sistema debe ser 1 sobre las clases cableadas: {total:?}");
    // El total cableado incluye al menos las 5 clases HTTP (10 casos): 5 safe + 5 vuln.
    assert!(total.safe >= 5 && total.vuln >= 5, "faltan clases en el cómputo: {total:?}");

    servidor.abort();
}
