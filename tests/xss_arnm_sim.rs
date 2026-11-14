// SPDX-License-Identifier: LicenseRef-Propietario
//! BANCO A/B/C — calibración del bucle adaptativo de XSS (`xss::ciclo_xss`) ANTES de operar
//! en real (dir. 30). Tres servidores sintéticos con Chromium REAL confirmando por EJECUCIÓN
//! (dir. 28: no match de string —ese era el FP #11— sino el marcador computado en el DOM):
//!
//!   A  vulnerable-defendido : refleja `q`, con una blocklist NAÍF que quita `<script>` pero
//!                             deja pasar `onerror`/`onload`. → la canónica NO ejecuta, la
//!                             VARIANTE (img-onerror) SÍ; `secuencias` SIEMBRA el vector.
//!   B  defendido-limpio     : refleja `q` HTML-escapado → ninguna variante ejecuta.
//!                             → arnm transcribe TODO y confirma NADA; `secuencias` vacía.
//!   C  sin-sink             : no refleja `q`. → el selector PODA: 0 llamadas a Chromium.
//!
//! Además, una prueba de ESCALA del selector barato (120 endpoints, sin navegador): reflejo
//! vs sin-reflejo, para probar que la poda escala sin gastar el oráculo caro.
//!
//! RIESGO CERO: todo en 127.0.0.1; el payload solo pone un atributo-testigo (no roba nada).
//! Correr y VERLO:  cargo test --test xss_arnm_sim -- --nocapture --test-threads=1

use std::sync::Arc;

use axum::extract::RawQuery;
use axum::response::Html;
use axum::{routing::get, Router};
use nexus::config::Config;
use nexus::protection::{Guard, ProtectionConfig};
use nexus::{db, secuencias, xss};

/// Decodifica percent-encoding (el `inject_canary` codifica el payload en la URL).
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Extrae y decodifica el parámetro `q` de la query cruda.
fn q_de(raw: Option<String>) -> String {
    let raw = raw.unwrap_or_default();
    for kv in raw.split('&') {
        if let Some(v) = kv.strip_prefix("q=") {
            return pct_decode(v);
        }
    }
    String::new()
}

// ── Servidores sintéticos ────────────────────────────────────────────────────

/// A — vulnerable-defendido: blocklist case-sensitive que solo quita `<script`.
async fn srv_a(RawQuery(raw): RawQuery) -> Html<String> {
    let q = q_de(raw);
    let filt = q.replace("<script", "").replace("</script", "");
    Html(format!("<!doctype html><html><body><div>{filt}</div></body></html>"))
}

/// B — defendido-limpio: HTML-escapa la reflexión → todo llega como TEXTO.
async fn srv_b(RawQuery(raw): RawQuery) -> Html<String> {
    let q = q_de(raw);
    let esc = q
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;");
    Html(format!("<!doctype html><html><body><div>{esc}</div></body></html>"))
}

/// C — sin-sink: página estática, no refleja `q`.
async fn srv_c(RawQuery(_raw): RawQuery) -> Html<String> {
    Html("<!doctype html><html><body><p>pagina estatica</p></body></html>".into())
}

async fn arranca(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("127.0.0.1:{}", addr.port())
}

fn find_chromium() -> Option<String> {
    for p in ["/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome"] {
        if std::path::Path::new(p).exists() {
            return Some(p.to_string());
        }
    }
    None
}

fn cfg_chromium(path: &str) -> Config {
    use clap::Parser;
    Config::parse_from(["nexus", "--chromium-path", path, "scan"])
}

// ── EL BANCO A/B/C (Chromium real) ───────────────────────────────────────────

#[tokio::test]
async fn banco_abc_xss_discrimina() {
    let Some(chromium) = find_chromium() else {
        eprintln!("SKIP banco_abc_xss_discrimina: no hay Chromium en el sistema");
        return;
    };
    let cfg = cfg_chromium(&chromium);
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("xss.db"), 4).await.unwrap();
    let cli = reqwest::Client::new();
    let tries = 1; // en producción ≥2 (reproducibilidad); en el banco, 1 basta para discriminar

    let a = arranca(Router::new().route("/", get(srv_a))).await;
    let b = arranca(Router::new().route("/", get(srv_b))).await;
    let c = arranca(Router::new().route("/", get(srv_c))).await;
    let url = |h: &str| format!("http://{h}/?q=seed");

    eprintln!("\n┌─ BANCO A/B/C — calibración de arnm-XSS (oráculo = Chromium real) ───────");
    eprintln!("│ servidor          señal        variantes  vector          secuencias");
    eprintln!("├────────────────────────────────────────────────────────────────────────");

    // ── A: vulnerable-defendido — la canónica falla, la variante ejecuta ──
    let ra = xss::ciclo_xss(&pool, "sim", "host-a", &url(&a), &cli, &cfg, "", &[], tries, 700).await.unwrap();
    let seed_a = secuencias::contar_vigentes(&pool, "host-a").await.unwrap();
    eprintln!(
        "│ A vuln-defendido  {:<11?}  {:>4}       {:<14}  {}",
        ra.senal,
        ra.variantes_probadas,
        ra.hallazgo.as_ref().map(|h| h.vector.as_str()).unwrap_or("—"),
        seed_a
    );
    assert!(ra.hallazgo.is_some(), "A: la variante DEBE ejecutar");
    let hx = ra.hallazgo.as_ref().unwrap();
    assert_ne!(hx.vector, "script", "A: NO fue la canónica (esa la bloquea el filtro)");
    assert!(ra.variantes_probadas >= 2, "A: la canónica no bastó, hizo falta transcribir");
    assert_eq!(seed_a, 1, "A: `secuencias` SEMBRÓ el vector ganador");

    // ── A de nuevo: la MEMORIA acierta directo ──
    let ra2 = xss::ciclo_xss(&pool, "sim", "host-a", &url(&a), &cli, &cfg, "", &[], tries, 700).await.unwrap();
    eprintln!(
        "│ A (2ª vuelta)     {:<11?}  {:>4}       memoria={}",
        ra2.senal, ra2.variantes_probadas, ra2.desde_memoria
    );
    assert!(ra2.desde_memoria, "A-2: acierta DESDE memoria");
    assert_eq!(ra2.variantes_probadas, 1, "A-2: una sola prueba, no re-barre");

    // ── B: defendido-limpio — transcribe todo y NO confirma nada ──
    let rb = xss::ciclo_xss(&pool, "sim", "host-b", &url(&b), &cli, &cfg, "", &[], tries, 800).await.unwrap();
    let seed_b = secuencias::contar_vigentes(&pool, "host-b").await.unwrap();
    eprintln!(
        "│ B defend-limpio   {:<11?}  {:>4}       {:<14}  {}",
        rb.senal,
        rb.variantes_probadas,
        rb.hallazgo.as_ref().map(|h| h.vector.as_str()).unwrap_or("—"),
        seed_b
    );
    assert_eq!(rb.senal, xss::SenalXss::Reflejado, "B: hay reflejo (sink), pero escapado");
    assert!(rb.hallazgo.is_none(), "B: NADA ejecuta (anti-FP del match-de-string)");
    assert!(rb.variantes_probadas >= 6, "B: transcribió TODOS los vectores, sin confirmar");
    assert_eq!(seed_b, 0, "B: `secuencias` VACÍA");

    // ── C: sin-sink — el selector poda ──
    let rc = xss::ciclo_xss(&pool, "sim", "host-c", &url(&c), &cli, &cfg, "", &[], tries, 900).await.unwrap();
    let seed_c = secuencias::contar_vigentes(&pool, "host-c").await.unwrap();
    eprintln!(
        "│ C sin-sink        {:<11?}  {:>4}       {:<14}  {}",
        rc.senal, rc.variantes_probadas, "—", seed_c
    );
    assert_eq!(rc.senal, xss::SenalXss::SinReflejo, "C: sin reflejo");
    assert!(rc.hallazgo.is_none(), "C: sin sink, sin hallazgo");
    assert_eq!(rc.variantes_probadas, 0, "C: el selector PODA — 0 Chromium gastado");
    assert_eq!(seed_c, 0, "C: nada que sembrar");

    eprintln!("└────────────────────────────────────────────────────────────────────────\n");
}

// ── ESCALA del selector barato (sin navegador, dir. 8) ───────────────────────

#[tokio::test]
async fn selector_de_reflejo_escala_sin_navegador() {
    let app = Router::new().route("/r", get(srv_a)).route("/s", get(srv_c));
    let host = arranca(app).await;
    let cli = Arc::new(reqwest::Client::new());

    // 40 reflejantes (/r) + 80 estáticos (/s) = 120 sondas concurrentes, CERO Chromium.
    let mut tareas = Vec::new();
    for i in 0..120u32 {
        let (ruta, refleja) = if i % 3 == 0 { ("r", true) } else { ("s", false) };
        let cli = Arc::clone(&cli);
        let base = format!("http://{host}/{ruta}?q=seed");
        tareas.push(tokio::spawn(async move {
            use nexus::browser;
            let marca = format!("nxr{i}");
            let probe = browser::inject_canary(&base, &marca);
            let body = cli.get(&probe).send().await.unwrap().text().await.unwrap_or_default();
            (refleja, xss::clasificar_reflejo(&body, &marca))
        }));
    }

    let (mut refl_ok, mut poda_ok) = (0, 0);
    for t in tareas {
        let (refleja, senal) = t.await.unwrap();
        match (refleja, senal) {
            (true, xss::SenalXss::Reflejado) => refl_ok += 1,
            (false, xss::SenalXss::SinReflejo) => poda_ok += 1,
            _ => {}
        }
    }
    assert_eq!(refl_ok, 40, "los 40 reflejantes se detectan como sink");
    assert_eq!(poda_ok, 80, "los 80 estáticos se podan (sin gastar Chromium)");
    eprintln!("\n  escala: 120 endpoints → 40 sink detectados, 80 podados, 0 Chromium ✓\n");
}

// ── FAN-OUT: la FASE XSS sobre un corpus mixto, persistiendo hallazgos ────────

#[tokio::test]
async fn fase_xss_fanout_persiste_solo_los_vulnerables() {
    let Some(chromium) = find_chromium() else {
        eprintln!("SKIP fase_xss_fanout: no hay Chromium");
        return;
    };
    let cfg = cfg_chromium(&chromium);
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("xss_fanout.db"), 4).await.unwrap();
    let program = "sim-xss-fanout";
    let program_id = db::upsert_program(&pool, program).await.unwrap();

    let a = arranca(Router::new().route("/", get(srv_a))).await;
    let b = arranca(Router::new().route("/", get(srv_b))).await;
    let c = arranca(Router::new().route("/", get(srv_c))).await;
    // Corpus: A vuln, B escapa, C no refleja, + uno SIN parámetro (debe saltarse).
    let corpus = vec![
        format!("http://{a}/?q=seed"),
        format!("http://{b}/?q=seed"),
        format!("http://{c}/?q=seed"),
        format!("http://{a}/estatico"), // sin '?' → el fan-out lo salta
    ];
    let cli = reqwest::Client::new();
    let guard = Guard::new(ProtectionConfig::default());

    let n = xss::fase_xss_adaptativa(
        &pool, program, program_id, &corpus, &cli, &cfg, "", &guard, None, None, 1,
    )
    .await
    .unwrap();

    assert_eq!(n, 1, "solo el endpoint parametrizado vulnerable (A) produce hallazgo");
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM findings")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(total, 1, "exactamente 1 finding (ni B, ni C, ni el sin-parámetro)");
    let (url, cwe): (String, Option<String>) =
        sqlx::query_as("SELECT url, cwe FROM findings LIMIT 1").fetch_one(&pool).await.unwrap();
    assert!(url.contains(&a), "el finding es del endpoint vulnerable A");
    assert_eq!(cwe.as_deref(), Some("CWE-79"), "CWE-79 (XSS)");
    eprintln!("\n  fan-out xss: 4 endpoints (A vuln, B escapa, C no-refl, 1 sin-param) → 1 hallazgo (A), CWE-79 ✓\n");
}

// ── LA INVERSIÓN: un molde de nuclei cubre lo que los 6 vectores a mano no ─────
//
// Servidor que BLOQUEA los 6 vectores a mano (strip de <script/<img/<svg/<body/<details) pero
// deja pasar el resto. Un molde derivado de un vector REAL de nuclei (<input autofocus onfocus>,
// que no está en los 6) DEBE ejecutar y confirmarse por nuestro oráculo. nuclei = fórmula,
// arnm = atacante, oráculo limpio = ejecución (no el match de string de nuclei).

async fn srv_solo_nuclei(RawQuery(raw): RawQuery) -> Html<String> {
    let q = q_de(raw);
    let filt = q
        .replace("<script", "")
        .replace("<img", "")
        .replace("<svg", "")
        .replace("<body", "")
        .replace("<details", "");
    Html(format!("<!doctype html><html><body><div>{filt}</div></body></html>"))
}

#[tokio::test]
async fn inversion_molde_de_nuclei_cubre_lo_que_los_seis_no() {
    let Some(chromium) = find_chromium() else {
        eprintln!("SKIP inversion: no hay Chromium");
        return;
    };
    let cfg = cfg_chromium(&chromium);
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("inv.db"), 4).await.unwrap();
    let cli = reqwest::Client::new();
    let s = arranca(Router::new().route("/", get(srv_solo_nuclei))).await;

    // Molde derivado de un vector REAL de nuclei (el alert sustituido por el placeholder).
    let molde = nexus::nuclei_moldes::a_molde("<input autofocus onfocus=alert(document.domain)>").unwrap();
    assert_eq!(molde, "<input autofocus onfocus=__NXJS__>", "extracción: alert→placeholder, breakout intacto");
    let moldes = vec![molde];

    let r = xss::ciclo_xss(
        &pool, "sim", "host-inv", &format!("http://{s}/?q=seed"), &cli, &cfg, "", &moldes, 1, 1234,
    )
    .await
    .unwrap();

    assert!(r.hallazgo.is_some(), "los 6 a mano están bloqueados; el molde de nuclei DEBE ejecutar");
    let h = r.hallazgo.as_ref().unwrap();
    assert!(h.vector.starts_with("nuclei/"), "el vector ganador es de nuclei, no de los 6 (fue {})", h.vector);
    assert!(r.variantes_probadas >= 7, "probó los 6 a mano (fallaron) + el de nuclei");
    let seed = secuencias::contar_vigentes(&pool, "host-inv").await.unwrap();
    assert_eq!(seed, 1, "sembró el molde ganador");
    eprintln!("\n  inversión: 6 a mano BLOQUEADOS, molde de nuclei ({}) EJECUTA → hallazgo ✓\n", h.vector);
}
