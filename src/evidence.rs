//! Evidencia (F5): captura un screenshot de cada hallazgo verificado usando
//! Chromium headless como SUBPROCESS. Coherente con la arquitectura de nexus
//! (Rust orquesta binarios externos) y mucho más ligero que embeber un cliente
//! CDP — importante en el VPS sin swap, donde Chromium ya es pesado de por sí.
//!
//! Alternativa considerada y descartada: chromiumoxide (cliente CDP por
//! websocket en proceso, ~40 deps más). Se puede cambiar si se necesita control
//! fino del navegador.

use crate::config::Config;
use crate::error::Result;
use crate::scope::host_of;
use crate::tools;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Nombre de archivo de la captura, estable por id+host. Puro.
pub fn screenshot_filename(id: i64, url: &str) -> String {
    let host = host_of(url);
    let safe: String = host.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect();
    format!("{id}_{safe}.png")
}

/// Captura un screenshot de `url` en `out`. Devuelve true si el archivo se creó
/// Y la página NO es de error/challenge. Usa Chromium headless; los flags evitan
/// sandbox (para correr como servicio) y acotan el tiempo de render.
///
/// **La evidencia es una PUERTA, no un adorno** (directiva 28): antes se guardaba
/// cualquier render como prueba —por eso el FP #11 capturó un login limpio de Temu
/// y contó como evidencia—. Ahora se vuelca primero el DOM y, si es una página de
/// error (Cloudflare "Just a moment", "Whoops", 403…), NO se guarda captura: una
/// imagen de un muro no prueba nada.
pub async fn capture(cfg: &Config, url: &str, out: &Path) -> Result<bool> {
    // Puerta: si la carga es una página de error/challenge, no hay evidencia válida.
    if let Ok(dom) = crate::browser::dump_dom(cfg, url).await {
        if crate::browser::is_error_page(&dom) {
            tracing::warn!("evidencia: {url} sirvió una página de error/challenge; no se guarda captura");
            return Ok(false);
        }
    }
    let args: Vec<String> = vec![
        "--headless=new".into(),
        "--disable-gpu".into(),
        "--no-sandbox".into(),
        "--hide-scrollbars".into(),
        "--disable-dev-shm-usage".into(), // clave en contenedores/VPS con /dev/shm pequeño
        format!("--screenshot={}", out.display()),
        "--window-size=1440,900".into(),
        "--virtual-time-budget=8000".into(),
        url.into(),
    ];
    // Timeout de proceso generoso: Chromium puede tardar en arrancar.
    let _ = tools::run(&cfg.chromium_path, &args, Duration::from_secs(30)).await?;
    Ok(tokio::fs::metadata(out).await.is_ok())
}

/// ¿La URL apunta a un ASSET ESTÁTICO (fuente, imagen, media, css/js)? Un asset no es una
/// página de vuln screenshoteable, y peor: Chromium se cuelga ~30-60s intentando "renderizar"
/// un binario (fuentes .woff2/.ttf), lo que agotaba el TimeoutStartSec del hunt (medido
/// 2026-08-25: nexus-hunt muerto por timeout capturando font-awesome). Mira la extensión del
/// PATH, no de la query. Puro (dir. 33: su pareja es el test).
pub fn es_asset_estatico(url: &str) -> bool {
    let sin_query = url.split(['?', '#']).next().unwrap_or(url);
    let ultimo = sin_query.rsplit('/').next().unwrap_or(sin_query);
    let Some((_, ext)) = ultimo.rsplit_once('.') else {
        return false;
    };
    const ASSETS: &[&str] = &[
        "woff", "woff2", "ttf", "eot", "otf", // fuentes (las que colgaban el hunt)
        "css", "js", "mjs", "map", // estáticos web (su evidencia es el texto, no un screenshot)
        "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif", "bmp", // imágenes
        "mp4", "webm", "mp3", "wav", "ogg", "avi", "mov", // media
    ];
    ASSETS.contains(&ext.to_ascii_lowercase().as_str())
}

/// Captura evidencia de todos los hallazgos verificados que aún no la tengan.
/// Devuelve cuántas capturas se lograron. Secuencial: una instancia de Chromium
/// a la vez para no reventar la RAM del VPS.
pub async fn capture_all(cfg: &Config, pool: &sqlx::SqlitePool) -> Result<usize> {
    tokio::fs::create_dir_all(&cfg.evidence_dir).await.ok();
    let rows = crate::db::verified_findings(pool).await?;
    let mut count = 0usize;
    for r in rows {
        // Si ya tiene una evidencia que apunta a un .png, no repetimos.
        if r.verification_evidence.as_deref().map(|e| e.ends_with(".png")).unwrap_or(false) {
            continue;
        }
        // Assets estáticos: no se screenshotean (cuelgan Chromium y no son evidencia de vuln).
        if es_asset_estatico(&r.url) {
            tracing::debug!("evidencia: {} es un asset estático; se omite la captura", r.url);
            continue;
        }
        let out: PathBuf = cfg.evidence_dir.join(screenshot_filename(r.id, &r.url));
        match capture(cfg, &r.url, &out).await {
            Ok(true) => {
                crate::db::set_evidence(pool, r.id, &out.display().to_string()).await?;
                count += 1;
            }
            Ok(false) => tracing::warn!("captura vacía para {}", r.url),
            Err(e) => tracing::warn!("Chromium no disponible o falló ({e}); se omite evidencia"),
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nombre_de_captura_estable_y_seguro() {
        assert_eq!(screenshot_filename(7, "https://api.example.com/a?b=1"), "7_api.example.com.png");
        assert_eq!(screenshot_filename(1, "http://10.0.0.1:8080/x"), "1_10.0.0.1.png");
    }

    #[test]
    fn asset_estatico_discrimina() {
        // ROJO (los que colgaban el hunt) — DEBEN saltarse:
        assert!(es_asset_estatico("https://x.com/assets/font-awesome/fa-regular-400-abc.woff2"));
        assert!(es_asset_estatico("https://x.com/f.TTF")); // extensión case-insensitive
        assert!(es_asset_estatico("https://x.com/logo.png"));
        assert!(es_asset_estatico("https://x.com/app.min.js"));
        assert!(es_asset_estatico("https://x.com/a/b/c.css?v=3")); // ext del PATH, no de la query
        // VERDE (páginas de vuln reales) — DEBEN capturarse:
        assert!(!es_asset_estatico("https://x.com/admin"));
        assert!(!es_asset_estatico("https://x.com/api/user?id=1"));
        assert!(!es_asset_estatico("https://x.com/search?q=foo.png")); // .png en la QUERY, no en el path
        assert!(!es_asset_estatico("https://x.com/")); // sin extensión
        assert!(!es_asset_estatico("https://x.com/reset?token=abc.def")); // punto en la query
    }
}
