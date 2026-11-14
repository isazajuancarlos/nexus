// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
//! **La app-HTTP TRAMPA del FP-lab: endpoints etiquetados SAFE/VULN, por clase.**
//!
//! El banco de gates puras ([`crate::fp_lab`]) mide el JUICIO sobre artefactos fijos; no cruza
//! la frontera del programa (directiva 28). Este módulo levanta un servidor `axum` REAL —bind
//! SIEMPRE a `127.0.0.1`, jamás expuesto— con parejas de endpoints por cada clase de bug:
//!
//! - **SAFE** (una TRAMPA): *parece* vulnerable pero es seguro. La detección NO debe reportarlo
//!   (si lo hace, es un falso positivo).
//! - **VULN** (un CONTROL): vulnerable de verdad. La detección SÍ debe reportarlo (si no, es un
//!   falso negativo).
//!
//! Es la pareja rojo/verde de la directiva 33, pero contra HTTP de verdad: el runner
//! ([`crate::fp_lab::evaluar_sistema`]) golpea estos endpoints con `reqwest`, aplica la gate de
//! nexus que le toca a cada clase, y cuenta FP/TP. Un endpoint SAFE que la detección reporta
//! delata que la gate se degradó; un VULN que calla, que perdió sensibilidad.
//!
//! **Es LOCAL y de PRUEBA.** No se sirve nunca en producción: existe solo para medir el sistema
//! contra sí mismo. El endpoint `/ssrf-real` hace un fetch server-side de verdad, pero acotado a
//! loopback (rechaza cualquier host que no sea `127.0.0.1`/`localhost`), así que la trampa no se
//! puede volver un SSRF real contra un tercero.
//!
//! No usa el extractor `Query` de axum a propósito: la feature `query` no está activada en el
//! `Cargo.toml` de nexus (solo `http1`/`json`/`tokio`), así que se parsea el query-string a mano
//! desde el `Uri` (extractor ungated) — sin tocar dependencias.

use axum::{
    http::{StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use maud::{html, Markup, DOCTYPE};
use std::collections::HashMap;
use std::time::Duration;

/// El secreto que SOLO un fetch server-side real (SSRF) puede sacar del recurso interno del
/// lab. Es un marcador disciplinado (largo, alfanumérico, sin palabras naturales): si aparece
/// en la respuesta de un endpoint, es porque se fetcheó de verdad, no porque el input se reflejó.
pub const SECRETO_INTERNO: &str = "S3CRET0NXFP9f2a7c1eDEADBEEF";

/// Usuario "válido" del lab, para las clases user-enum y timing. El resto de nombres son
/// inexistentes.
pub const USUARIO_VALIDO: &str = "juan";

/// Un `name` que EXISTE en el file-oracle real (el resto no existen).
pub const ARCHIVO_EXISTE: &str = "reporte.pdf";

/// Parsea el query-string del `Uri` a un mapa, con percent-decoding (`+` → espacio, `%XX`).
fn params(uri: &Uri) -> HashMap<String, String> {
    let mut m = HashMap::new();
    let Some(qs) = uri.query() else { return m };
    for par in qs.split('&') {
        if par.is_empty() {
            continue;
        }
        let (k, v) = par.split_once('=').unwrap_or((par, ""));
        m.insert(decode(k), decode(v));
    }
    m
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decoding tolerante: `+` → espacio, `%XX` → byte; un `%` mal formado se deja crudo.
fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => match (hex(b[i + 1]), hex(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn val(uri: &Uri, clave: &str) -> String {
    params(uri).get(clave).cloned().unwrap_or_default()
}

// ── Índice ───────────────────────────────────────────────────────────────────

async fn indice() -> Markup {
    html! {
        (DOCTYPE)
        html lang="es" {
            head {
                meta charset="utf-8";
                title { "FP-lab — app trampa (LOCAL)" }
            }
            body {
                h1 { "FP-lab de NEXUS — app trampa" }
                p { b { "LOCAL y de prueba." } " Bind a 127.0.0.1, nunca expuesta. Mide el sistema de detección contra HTTP real (directiva 28)." }
                p { "Cada clase trae una pareja: " b{"SAFE"} " (parece vuln, es segura — no debe reportarse) y " b{"VULN"} " (lo es — debe reportarse)." }
                ul {
                    li { "SSRF — SAFE " code{"/ssrf-echo?url="} " · VULN " code{"/ssrf-real?url="} }
                    li { "XSS — SAFE " code{"/xss-encoded?q="} " y " code{"/xss-collision?q="} " · VULN " code{"/xss-real?q="} }
                    li { "IDOR — SAFE " code{"/idor-genfields?id="} " · VULN " code{"/idor-real?id="} }
                    li { "File-oracle — SAFE " code{"/file?name="} " · VULN " code{"/file-real?name="} }
                    li { "User-enum — SAFE " code{"/login?user="} " · VULN " code{"/login-real?user="} }
                    li { "Timing — SAFE " code{"/timing?user="} " · VULN " code{"/timing-real?user="} }
                }
            }
        }
    }
}

// ── SSRF ───────────────────────────────────────────────────────────────────────

/// SAFE: refleja la URL pedida dentro de un mensaje de error, pero **no fetchea**. Parece un
/// SSRF (acepta una URL y la nombra), pero jamás sale a la red: el secreto interno nunca aparece.
async fn ssrf_echo(uri: Uri) -> Response {
    let url = val(&uri, "url");
    (StatusCode::OK, format!("no pude conectar a {url}")).into_response()
}

/// VULN: hace un fetch server-side de la URL pedida y **devuelve su cuerpo**. Acotado a loopback
/// (la trampa no puede convertirse en un SSRF real). Apuntado al recurso interno, filtra el
/// secreto: es el SSRF clásico basado en contenido.
async fn ssrf_real(uri: Uri) -> Response {
    let url = val(&uri, "url");
    if !es_loopback(&url) {
        return (StatusCode::BAD_REQUEST, "solo loopback en el lab".to_string()).into_response();
    }
    let cli = match reqwest::Client::builder().timeout(Duration::from_secs(5)).build() {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("cliente: {e}")).into_response(),
    };
    match cli.get(&url).send().await {
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            (StatusCode::OK, format!("respuesta del origen:\n{body}")).into_response()
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("fetch falló: {e}")).into_response(),
    }
}

/// ¿La URL apunta a loopback? Barandilla de la trampa SSRF: solo `127.0.0.1`/`localhost`.
fn es_loopback(url: &str) -> bool {
    let sin_esquema = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let host = sin_esquema.split(['/', ':', '?', '#']).next().unwrap_or("");
    host == "127.0.0.1" || host == "localhost"
}

/// Recurso INTERNO: devuelve el secreto. Solo se alcanza vía el fetch server-side de
/// `/ssrf-real` (en un objetivo real estaría en la red interna, inalcanzable desde fuera).
async fn interno_secreto() -> Response {
    (StatusCode::OK, format!("token de servicio interno: {SECRETO_INTERNO}")).into_response()
}

/// Recurso interno PÚBLICO (sin secreto): el baseline del oráculo SSRF de contenido.
async fn interno_publico() -> Response {
    (StatusCode::OK, "recurso interno de estado, sin secreto".to_string()).into_response()
}

// ── XSS ─────────────────────────────────────────────────────────────────────────

/// SAFE: refleja `q` **HTML-escapado** (maud escapa por defecto). El `<script>` inyectado se
/// convierte en `&lt;script&gt;` y NO ejecuta. Un detector por reflexión de texto lo marcaría;
/// el oráculo por ejecución (navegador) no.
async fn xss_encoded(uri: Uri) -> Markup {
    let q = val(&uri, "q");
    html! {
        (DOCTYPE)
        html { head { meta charset="utf-8"; } body { h1 { "búsqueda" } p { "resultados para: " (q) } } }
    }
}

/// SAFE: refleja `q` escapado, pero la página CONTIENE de forma estática tokens de XSS como
/// TEXTO visible (`<script>alert(1)</script>`, `onerror=`). Es la COLISIÓN: un detector que
/// busca esas cadenas en el cuerpo dispara aunque nada ejecute. El oráculo por ejecución no cae.
async fn xss_collision(uri: Uri) -> Markup {
    let q = val(&uri, "q");
    html! {
        (DOCTYPE)
        html { head { meta charset="utf-8"; } body {
            h1 { "ayuda de seguridad" }
            // Estos tokens aparecen ESCAPADOS (texto visible), no como HTML vivo:
            p { "Ejemplos de payload que bloqueamos: <script>alert(1)</script> y <img src=x onerror=alert(1)>." }
            p { "tu consulta: " (q) }
        } }
    }
}

/// VULN: refleja `q` **CRUDO** (sin escapar) en un sink que ejecuta. El `<script>` del canary
/// corre en el navegador y pone el atributo-testigo computado → el oráculo lo confirma.
async fn xss_real(uri: Uri) -> Html<String> {
    let q = val(&uri, "q");
    Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"></head><body><h1>búsqueda</h1><div>resultados para: {q}</div></body></html>"
    ))
}

// ── IDOR ────────────────────────────────────────────────────────────────────────

/// SAFE: 200 con un cuerpo GENÉRICO idéntico para cualquier `id`. Parece que el objeto existe y
/// responde, pero no filtra datos de nadie: el cuerpo no depende del `id`, así que dos ids dan
/// bytes idénticos y el body-diff es `Identico`.
async fn idor_genfields(_uri: Uri) -> Response {
    (StatusCode::OK, "{\"status\":\"ok\",\"perfil\":\"restringido\"}".to_string()).into_response()
}

/// VULN: 200 con los datos DEL id pedido (incluye el de OTRO usuario). Dos ids dan cuerpos
/// distintos → body-diff `Difiere` → IDOR.
async fn idor_real(uri: Uri) -> Response {
    let id = val(&uri, "id");
    (
        StatusCode::OK,
        format!("{{\"id\":\"{id}\",\"email\":\"user{id}@lab.local\",\"saldo\":{}}}", id.len() * 137 + 42),
    )
        .into_response()
}

// ── File-oracle ───────────────────────────────────────────────────────────────

/// SAFE: 403 UNIFORME para todo `name` (mismo status y mismo cuerpo exista o no el archivo). No
/// filtra existencia: es política, no estado → el oráculo no discrimina.
async fn file_safe(_uri: Uri) -> Response {
    (StatusCode::FORBIDDEN, "acceso denegado por política".to_string()).into_response()
}

/// VULN: 200 con contenido si el archivo EXISTE, 404 si no. Discrimina estado → oráculo de
/// existencia (enumeración de archivos).
async fn file_real(uri: Uri) -> Response {
    let name = val(&uri, "name");
    if name == ARCHIVO_EXISTE {
        (StatusCode::OK, "%PDF-1.7 contenido del reporte...".to_string()).into_response()
    } else {
        (StatusCode::NOT_FOUND, "not found".to_string()).into_response()
    }
}

// ── User-enum ─────────────────────────────────────────────────────────────────

/// SAFE: mismo cuerpo y status para usuario válido o inválido. No filtra qué cuentas existen.
async fn login_safe(_uri: Uri) -> Response {
    (StatusCode::UNAUTHORIZED, "credenciales inválidas".to_string()).into_response()
}

/// VULN: cuerpo distinto según el usuario exista o no ("contraseña incorrecta" vs "usuario no
/// existe"). Enumeración de usuarios por diferencia de respuesta.
async fn login_real(uri: Uri) -> Response {
    let user = val(&uri, "user");
    let cuerpo = if user == USUARIO_VALIDO {
        "contraseña incorrecta"
    } else {
        "usuario no existe"
    };
    (StatusCode::UNAUTHORIZED, cuerpo.to_string()).into_response()
}

// ── Timing ────────────────────────────────────────────────────────────────────

/// SAFE: latencia CONSTANTE (más un jitter pequeño IGUAL para todos), independiente de si el
/// usuario existe. No hay canal temporal: los dos grupos vienen de la misma distribución.
async fn timing_safe(_uri: Uri) -> Response {
    tokio::time::sleep(Duration::from_millis(8) + jitter(4)).await;
    (StatusCode::OK, "ok".to_string()).into_response()
}

/// VULN: los usuarios VÁLIDOS tardan claramente más (se "verifica la contraseña"), de forma
/// estable; los inexistentes cortan rápido. Diferencia de medias real y baja varianza → señal.
async fn timing_real(uri: Uri) -> Response {
    let user = val(&uri, "user");
    if user == USUARIO_VALIDO {
        tokio::time::sleep(Duration::from_millis(45) + jitter(2)).await;
    } else {
        tokio::time::sleep(Duration::from_millis(8) + jitter(2)).await;
    }
    (StatusCode::OK, "ok".to_string()).into_response()
}

/// Jitter uniforme en `[0, max_ms)` milisegundos. Igual para safe (mismo para ambos grupos) que
/// para el ruido de fondo del vuln.
fn jitter(max_ms: u64) -> Duration {
    use rand::Rng;
    let ms = rand::rng().random_range(0..max_ms.max(1));
    Duration::from_millis(ms)
}

/// Construye el router de la app-trampa. Sin estado: cada handler es autocontenido.
pub fn router() -> Router {
    Router::new()
        .route("/", get(indice))
        // SSRF
        .route("/ssrf-echo", get(ssrf_echo))
        .route("/ssrf-real", get(ssrf_real))
        .route("/_internal/secret", get(interno_secreto))
        .route("/_internal/public", get(interno_publico))
        // XSS
        .route("/xss-encoded", get(xss_encoded))
        .route("/xss-collision", get(xss_collision))
        .route("/xss-real", get(xss_real))
        // IDOR
        .route("/idor-genfields", get(idor_genfields))
        .route("/idor-real", get(idor_real))
        // File-oracle
        .route("/file", get(file_safe))
        .route("/file-real", get(file_real))
        // User-enum
        .route("/login", get(login_safe))
        .route("/login-real", get(login_real))
        // Timing
        .route("/timing", get(timing_safe))
        .route("/timing-real", get(timing_real))
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn es_loopback_solo_acepta_127_y_localhost() {
        assert!(es_loopback("http://127.0.0.1:8080/_internal/secret"));
        assert!(es_loopback("http://localhost/x"));
        assert!(es_loopback("127.0.0.1:9/a"));
        // Su pareja: cualquier host externo se rechaza (la trampa no sale a la red).
        assert!(!es_loopback("http://169.254.169.254/latest/meta-data"));
        assert!(!es_loopback("http://evil.example.com/"));
        assert!(!es_loopback("http://127.0.0.1.evil.com/"));
    }

    #[test]
    fn decode_revierte_percent_y_mas() {
        assert_eq!(decode("hola+mundo"), "hola mundo");
        assert_eq!(decode("%3Cscript%3E"), "<script>");
        assert_eq!(decode("a%2Bb"), "a+b");
        // `%` mal formado se deja crudo, sin panicar.
        assert_eq!(decode("100%"), "100%");
        assert_eq!(decode("50%z"), "50%z");
    }

    #[test]
    fn params_separa_pares_y_decodifica() {
        let u: Uri = "/x?url=http%3A%2F%2F127.0.0.1%2Fa&q=%3Cb%3E".parse().unwrap();
        let m = params(&u);
        assert_eq!(m.get("url").unwrap(), "http://127.0.0.1/a");
        assert_eq!(m.get("q").unwrap(), "<b>");
        assert!(!m.contains_key("falta"));
    }
}
