//! UI web: axum sirve el panel renderizado EN EL SERVIDOR con `maud` + htmx
//! (directiva 26). El HTML lo teje `rustc` a partir de los tipos del dominio —un
//! error de plantilla es un error de compilación—, así que el build NO necesita
//! Node ni npm: no hay `web/dist`, ni `node_modules`, ni paso de bundling.
//!
//! htmx va VENDORIZADO y embebido en el binario por `include_str!` (nunca CDN):
//! un producto que corre offline en casa del cliente no puede depender de que un
//! tercero le sirva un archivo. El estado vive en el servidor; htmx refresca el
//! panel por sondeo. El panel se pinta también SIN JavaScript (mejora
//! progresiva): htmx solo añade el refresco automático.
//!
//! Migrado desde Angular 22 + Material el 2026-08-06 (piloto del cambio de
//! estándar de frontend): mismas dos vistas —tarjetas de estadísticas y tabla de
//! hallazgos—, cero dependencias npm.

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use maud::{html, Markup, PreEscaped, DOCTYPE};
use sqlx::SqlitePool;

/// htmx 2.0.4, vendorizado y con versión fijada (línea estable 2.x, directiva
/// 35). Embebido en el binario y servido desde `/htmx.min.js`, jamás desde un
/// CDN. Se actualiza como cualquier dependencia: bajando el archivo nuevo.
const HTMX_JS: &str = include_str!("../web/estaticos/htmx.min.js");

/// CSS propio con variables, sin framework (directiva 26). Theme-aware: respeta
/// el modo claro/oscuro del sistema. Los colores de severidad son fijos porque
/// funcionan sobre ambos fondos.
const CSS: &str = include_str!("../web/estaticos/panel.css");

/// Construye el router con el pool como estado compartido.
pub fn router(pool: SqlitePool) -> Router {
    Router::new()
        .route("/", get(panel))
        .route("/panel/refresco", get(refresco))
        .route("/htmx.min.js", get(htmx_js))
        // La API JSON se conserva para consumidores externos / herramientas; el
        // panel ya no la usa (se pinta en el servidor).
        .route("/api/stats", get(stats))
        .route("/api/findings", get(findings))
        .route("/health", get(|| async { "ok" }))
        .with_state(pool)
}

async fn htmx_js() -> Response {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        HTMX_JS,
    )
        .into_response()
}

// ── El panel, tejido con maud ───────────────────────────────────────────────

/// La página completa. El contenido se pinta en el servidor (funciona sin JS) y
/// htmx lo refresca cada 15 s sondeando `/panel/refresco`.
async fn panel(State(pool): State<SqlitePool>) -> Response {
    let (s, f) = match cargar(&pool).await {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    html! {
        (DOCTYPE)
        html lang="es" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "NEXUS — panel de hallazgos" }
                style { (PreEscaped(CSS)) }
                script src="/htmx.min.js" {}
            }
            body {
                header.barra {
                    span.marca { "NEXUS" }
                    span.sub { "panel de hallazgos" }
                }
                main #panel
                     hx-get="/panel/refresco"
                     hx-trigger="every 15s"
                     hx-swap="innerHTML" {
                    (contenido(&s, &f))
                }
            }
        }
    }
    .into_response()
}

/// El fragmento que htmx inserta en `#panel` cada 15 s: solo tarjetas + tabla.
async fn refresco(State(pool): State<SqlitePool>) -> Response {
    match cargar(&pool).await {
        Ok((s, f)) => contenido(&s, &f).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn cargar(pool: &SqlitePool) -> anyhow::Result<(crate::db::DashStats, Vec<crate::db::FindingApi>)> {
    let s = crate::db::dashboard_stats(pool).await?;
    let f = crate::db::findings_for_api(pool, 500).await?;
    Ok((s, f))
}

/// Tarjetas de estadísticas y tabla de hallazgos. Es el trozo que comparten la
/// página completa y el fragmento de refresco, para que los dos digan lo mismo.
fn contenido(s: &crate::db::DashStats, f: &[crate::db::FindingApi]) -> Markup {
    let tarjetas = [
        ("Total", s.total),
        ("Verificados", s.verified),
        ("Explotables", s.exploitable),
        ("Falsos +", s.false_positive),
        ("Manual", s.manual),
        ("Reintento", s.retry),
    ];
    html! {
        section.tarjetas {
            @for (etiqueta, n) in tarjetas {
                article.tarjeta {
                    div.n { (n) }
                    div.l { (etiqueta) }
                }
            }
        }
        @if f.is_empty() {
            p.vacio { "Sin hallazgos todavía." }
        } @else {
            table.tabla {
                thead {
                    tr {
                        th { "Severidad" }
                        th { "Vulnerabilidad" }
                        th { "URL" }
                        th { "Estado" }
                        th { "Verif." }
                    }
                }
                tbody {
                    @for x in f {
                        tr {
                            td { span class=(format!("chip {}", sev_clase(&x.severity))) { (x.severity) } }
                            td { (x.vuln_name) }
                            td.url title=(x.url) { (x.url) }
                            td { (x.status) }
                            td { (verificacion(x)) }
                        }
                    }
                }
            }
        }
    }
}

/// La clase CSS del chip según la severidad. Toda severidad desconocida cae a
/// `unknown` en vez de quedarse sin estilo (directiva 20: sin relleno silencioso,
/// pero con un camino visible para lo que no se reconoce).
fn sev_clase(sev: &str) -> &'static str {
    match sev.to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        "info" => "info",
        _ => "unknown",
    }
}

/// Qué mostrar en la columna «Verif.»: la herramienta que verificó, «sí» si se
/// verificó sin nombrar herramienta, o «—» si no se verificó. Reproduce
/// exactamente lo que hacía el template de Angular.
fn verificacion(x: &crate::db::FindingApi) -> String {
    if x.verified != 0 {
        x.verification_tool.clone().unwrap_or_else(|| "sí".into())
    } else {
        "—".into()
    }
}

// ── API JSON (conservada para consumidores externos) ────────────────────────

async fn stats(State(pool): State<SqlitePool>) -> Response {
    match crate::db::dashboard_stats(&pool).await {
        Ok(s) => Json(s).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn findings(State(pool): State<SqlitePool>) -> Response {
    match crate::db::findings_for_api(&pool, 500).await {
        Ok(f) => Json(f).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
