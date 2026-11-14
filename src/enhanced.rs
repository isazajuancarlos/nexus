//! Enhanced recon (F4): amplía la superficie ANTES de escanear con nuclei.
//! Portado de bounty/recon.py (ReconEngine).
//!   1. PASIVO   gau + waybackurls  (archivos históricos, 0 peticiones al target)
//!   2. CRAWL    katana             (rastreo siguiendo enlaces)
//!   3. DISCOVER ffuf               (descubrimiento de contenido con wordlist)
//!   4. PARAMS   arjun              (parámetros ocultos)
//!
//! Cada herramienta es OPCIONAL: si falta, esa fase se salta (no aborta). Los
//! parsers de salida (ffuf/arjun JSON) son puros y testables. Tope de URLs para
//! no reventar la RAM del VPS.

use crate::config::Config;
use crate::error::Result;
use crate::scope::host_of;
use crate::tools;
use serde_json::Value;
use std::collections::BTreeSet;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Default, Clone, Copy)]
pub struct ReconStats {
    pub passive: usize,
    pub crawled: usize,
    pub discovered: usize,
    pub params: usize,
    pub added: usize,
}

/// URL base (esquema://host) sin path. Puro.
pub fn base_url(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split('/').next()?;
    if host.is_empty() {
        None
    } else {
        Some(format!("{scheme}://{host}"))
    }
}

/// Resuelve un endpoint extraído de un `.js` contra la URL del propio fichero:
/// las URLs absolutas pasan tal cual; las rutas relativas (`/api/x`) se resuelven
/// contra el origen del `.js`. Puro (`Url::join` hace la resolución RFC).
pub fn resolver_endpoint(base_js: &str, ep: &str) -> String {
    if ep.starts_with("http://") || ep.starts_with("https://") {
        return ep.to_string();
    }
    match reqwest::Url::parse(base_js).and_then(|b| b.join(ep)) {
        Ok(u) => u.to_string(),
        Err(_) => ep.to_string(),
    }
}

/// ¿La URL puede llevar parámetros (interesante para arjun)? Puro.
pub fn is_parameterizable(url: &str) -> bool {
    let u = url.to_lowercase();
    u.contains('?')
        || u.contains("/api")
        || [".php", ".asp", ".aspx", ".jsp"].iter().any(|e| u.contains(e))
}

/// ¿Se OMITE arjun (descubrimiento de params)? Se omite si el presupuesto venció, o en modo
/// pasivo SALVO que se pida `recon_params` — arjun es targeted (nombres de param sobre
/// endpoints conocidos), no la fuerza bruta de ffuf, así que se desacopla del pasivo. Puro
/// (dir. 33: su pareja es el test). ffuf sigue gateado solo por `recon_passive_only`.
pub fn omitir_arjun(passive_only: bool, recon_params: bool, vencido: bool) -> bool {
    vencido || (passive_only && !recon_params)
}

/// Extrae `results[].url` de la salida JSON de ffuf. Puro.
pub fn parse_ffuf_json(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(v) = serde_json::from_str::<Value>(s) {
        if let Some(results) = v.get("results").and_then(|r| r.as_array()) {
            for r in results {
                if let Some(u) = r.get("url").and_then(|u| u.as_str()) {
                    out.push(u.to_string());
                }
            }
        }
    }
    out
}

/// Parsea el JSON de arjun (mapa url → params, con params lista u objeto). Puro.
pub fn parse_arjun_json(s: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(s) {
        for (url, params) in map {
            let names: Vec<String> = match params {
                Value::Array(a) => a.iter().filter_map(|p| p.as_str().map(String::from)).collect(),
                Value::Object(o) => o.keys().cloned().collect(),
                _ => Vec::new(),
            };
            if !names.is_empty() {
                out.push((url, names));
            }
        }
    }
    out
}

/// Ritmo conservador para herramientas activas de recon (tocan el target).
fn active_rate(cfg: &Config) -> u32 {
    cfg.rate_limit.min(50)
}

async fn run_lines(path: &str, args: &[String], timeout: Duration) -> Vec<String> {
    match tools::run(path, args, timeout).await {
        Ok(out) if !out.timed_out => out.stdout.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
        _ => Vec::new(),
    }
}

/// Genera una wordlist mínima de rutas sensibles si no existe.
async fn ensure_wordlist(cfg: &Config) -> Result<()> {
    if cfg.wordlist.exists() {
        return Ok(());
    }
    if let Some(parent) = cfg.wordlist.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    let defaults = ".env\n.git/config\n.git/HEAD\nadmin\napi\nbackup\nconfig\nconfig.json\ndebug\n.htaccess\nphpinfo.php\nrobots.txt\nserver-status\n.svn/entries\nswagger\nwp-config.php.bak\n";
    tokio::fs::write(&cfg.wordlist, defaults).await?;
    Ok(())
}

/// ¿Ya venció el presupuesto de recon? Entre fases se comprueba para no comerse
/// el tiempo del escaneo en la caza frecuente (el deadline lo pasa `cmd_recon`).
/// Sin deadline (`None`), nunca vence — es la caza profunda, que corre a fondo.
fn vencido(deadline: Option<std::time::Instant>) -> bool {
    deadline.is_some_and(|d| std::time::Instant::now() >= d)
}

/// Ejecuta el pipeline de enhanced recon y AÑADE las URLs nuevas a `targets_file`
/// (dedup contra lo existente, tope `max_urls`). Devuelve estadísticas.
///
/// `deadline`: instante en que el recon debe parar; entre fases se comprueba y se
/// salta lo que falte (la caza frecuente lo acota; la profunda pasa `None`).
///
/// Con `cfg.recon_passive_only` corre SOLO pasivo (gau/wayback) + crawl (katana)
/// y OMITE la fase activa (ffuf brute-force + arjun): la superficie que gana
/// nuclei sin la fuerza bruta que arriesga baneo. Es lo que hace seguro encender
/// enhanced recon en el ciclo de 2 h.
pub async fn enhance(
    cfg: &Config,
    targets_file: &std::path::Path,
    deadline: Option<std::time::Instant>,
) -> Result<ReconStats> {
    let mut stats = ReconStats::default();
    ensure_wordlist(cfg).await?;

    let existing: Vec<String> = if targets_file.exists() {
        tokio::fs::read_to_string(targets_file).await?.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()
    } else {
        Vec::new()
    };
    let mut seen: BTreeSet<String> = existing.iter().cloned().collect();
    let mut new_urls: Vec<String> = Vec::new();
    let rate = active_rate(cfg);

    // Hosts y dominios raíz de los hosts vivos.
    let domains: BTreeSet<String> = existing.iter().map(|u| host_of(u)).filter(|h| !h.is_empty()).collect();

    // --- 1. PASIVO: gau + waybackurls (archivos, sin tocar el target) ---
    // Entre dominios se comprueba el deadline: cada dominio son hasta 180 s
    // (dos subprocesos de 90 s), y 50 dominios sin este corte se comían el
    // ciclo ENTERO —recon a 48 min sobre un tope de 40— dejando a nuclei 0 s.
    // Medido en producción 2026-08-19: cero fases de escaneo en 2 días. Es el
    // mismo corte que ya hacían las fases 2 (crawl) y 3 (ffuf); la pasiva era
    // la única sin él.
    for d in domains.iter().take(50) {
        if vencido(deadline) {
            break;
        }
        let gau = run_lines(&cfg.gau_path, &["--threads".into(), "5".into(), "--timeout".into(), "60".into(), d.clone()], Duration::from_secs(90)).await;
        let wb =
            run_lines(&cfg.waybackurls_path, std::slice::from_ref(d), Duration::from_secs(90))
                .await;
        stats.passive += gau.len() + wb.len();
        for u in gau.into_iter().chain(wb) {
            push_new(&mut seen, &mut new_urls, u);
        }
    }

    // --- 2. CRAWL: katana sobre los hosts vivos (tope 100) ---
    let crawl_input = cfg.scans_dir.join("crawl_input.txt");
    let sample: Vec<&String> = existing.iter().take(100).collect();
    if !sample.is_empty() && !vencido(deadline) {
        let mut f = tokio::fs::File::create(&crawl_input).await?;
        for h in &sample {
            f.write_all(h.as_bytes()).await?;
            f.write_all(b"\n").await?;
        }
        f.flush().await?;
        let katana = run_lines(
            &cfg.katana_path,
            &[
                "-list".into(), crawl_input.display().to_string(),
                "-depth".into(), cfg.crawl_depth.to_string(),
                "-rate-limit".into(), rate.to_string(),
                "-concurrency".into(), "10".into(),
                "-silent".into(), "-no-color".into(),
                "-js-crawl".into(), "-known-files".into(), "all".into(), "-form-extraction".into(),
            ],
            Duration::from_secs(600),
        ).await;
        stats.crawled += katana.len();
        let mut js_urls: Vec<String> = Vec::new();
        for u in katana {
            if u.split('?').next().unwrap_or(&u).to_ascii_lowercase().ends_with(".js") {
                js_urls.push(u.clone());
            }
            push_new(&mut seen, &mut new_urls, u);
        }
        // 2.1: extrae ENDPOINTS de los .js descubiertos (Rust-nativo). Acotado a 30
        // ficheros para proteger la IP compartida; los endpoints alimentan el corpus
        // (más superficie para el foso). Los secretos en JS ya los pesca la fase 0.1
        // cuando el .js se toca como exposición.
        if !js_urls.is_empty() && !vencido(deadline) {
            if let Ok(cl) = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(Duration::from_secs(15))
                .user_agent(crate::evasion::UA_POOL[0])
                .build()
            {
                for ju in js_urls.into_iter().take(30) {
                    if vencido(deadline) {
                        break;
                    }
                    if let Ok(r) = cl.get(&ju).send().await {
                        if let Ok(cuerpo) = r.text().await {
                            for ep in crate::js_extract::extraer_endpoints(&cuerpo) {
                                let abs = resolver_endpoint(&ju, &ep);
                                stats.discovered += 1;
                                push_new(&mut seen, &mut new_urls, abs);
                            }
                        }
                    }
                }
            }
        }
    }

    // --- 3. DISCOVER: ffuf sobre URLs base (tope 20). FASE ACTIVA (fuerza bruta):
    //        se omite en modo pasivo y cuando el presupuesto ya venció. ---
    let base_urls: BTreeSet<String> = if cfg.recon_passive_only || vencido(deadline) {
        BTreeSet::new()
    } else {
        existing.iter().filter_map(|u| base_url(u)).collect()
    };
    for (i, b) in base_urls.iter().take(20).enumerate() {
        let out = cfg.scans_dir.join(format!("ffuf_{i}.json"));
        let args: Vec<String> = vec![
            "-u".into(), format!("{}/FUZZ", b.trim_end_matches('/')),
            "-w".into(), cfg.wordlist.display().to_string(),
            "-t".into(), "20".into(),
            "-rate".into(), rate.to_string(),
            "-timeout".into(), "10".into(),
            "-mc".into(), "200,201,204,301,302,307,401,403,405,500".into(),
            "-fc".into(), "404".into(),
            "-o".into(), out.display().to_string(),
            "-of".into(), "json".into(),
            "-s".into(),
        ];
        let _ = tools::run(&cfg.ffuf_path, &args, Duration::from_secs(600)).await;
        if let Ok(txt) = tokio::fs::read_to_string(&out).await {
            for u in parse_ffuf_json(&txt) {
                stats.discovered += 1;
                push_new(&mut seen, &mut new_urls, u);
            }
            tokio::fs::remove_file(&out).await.ok();
        }
    }

    // --- 4. PARAMS: arjun sobre URLs parametrizables (tope 50). Se DESACOPLA de ffuf: arjun
    //        prueba nombres de parámetro sobre endpoints conocidos (targeted), y corre en modo
    //        pasivo si `--recon-params` lo pide — es la superficie que la fase XSS necesita, sin
    //        encender la fuerza bruta de ffuf. Siempre se omite si el presupuesto venció. ---
    let param_urls: Vec<String> = if omitir_arjun(cfg.recon_passive_only, cfg.recon_params, vencido(deadline)) {
        Vec::new()
    } else {
        existing.iter().chain(new_urls.iter()).filter(|u| is_parameterizable(u)).take(50).cloned().collect()
    };
    if !param_urls.is_empty() {
        let arjun_in = cfg.scans_dir.join("arjun_input.txt");
        let arjun_out = cfg.scans_dir.join("arjun_out.json");
        tokio::fs::write(&arjun_in, param_urls.join("\n")).await?;
        let args: Vec<String> = vec![
            "-i".into(), arjun_in.display().to_string(),
            "-oJ".into(), arjun_out.display().to_string(),
            "-t".into(), "5".into(),
            "--rate-limit".into(), rate.to_string(),
            "-q".into(),
        ];
        let _ = tools::run(&cfg.arjun_path, &args, Duration::from_secs(600)).await;
        if let Ok(txt) = tokio::fs::read_to_string(&arjun_out).await {
            for (url, params) in parse_arjun_json(&txt) {
                stats.params += 1;
                // Construye una URL con el primer parámetro para que nuclei lo pruebe.
                if let Some(p) = params.first() {
                    let sep = if url.contains('?') { '&' } else { '?' };
                    push_new(&mut seen, &mut new_urls, format!("{url}{sep}{p}=1"));
                }
            }
            tokio::fs::remove_file(&arjun_out).await.ok();
        }
    }

    // --- Fusión: añadir URLs nuevas al archivo de objetivos (con tope) ---
    new_urls.truncate(cfg.max_urls);
    if !new_urls.is_empty() {
        let mut f = tokio::fs::OpenOptions::new().create(true).append(true).open(targets_file).await?;
        for u in &new_urls {
            f.write_all(u.as_bytes()).await?;
            f.write_all(b"\n").await?;
        }
        f.flush().await?;
    }
    stats.added = new_urls.len();
    Ok(stats)
}

/// Añade a `dst` si es http(s) y no se había visto. Mantiene `seen` para dedup.
fn push_new(seen: &mut BTreeSet<String>, dst: &mut Vec<String>, url: String) {
    let url = url.trim().to_string();
    if !url.starts_with("http") {
        return;
    }
    if seen.insert(url.clone()) {
        dst.push(url);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitir_arjun_desacopla_params_de_ffuf() {
        // Deep hunt (no pasivo): arjun corre.
        assert!(!omitir_arjun(false, false, false));
        // Pasivo sin recon_params: se omite (comportamiento previo, sin params).
        assert!(omitir_arjun(true, false, false));
        // Pasivo CON recon_params: arjun corre (params sin ffuf) — el desacople.
        assert!(!omitir_arjun(true, true, false));
        // Presupuesto vencido: siempre se omite, aunque se pidan params.
        assert!(omitir_arjun(true, true, true));
        assert!(omitir_arjun(false, true, true));
    }

    #[test]
    fn base_url_extrae_esquema_y_host() {
        assert_eq!(base_url("https://x.example.com/a/b?q=1").as_deref(), Some("https://x.example.com"));
        assert_eq!(base_url("http://h.example.com").as_deref(), Some("http://h.example.com"));
        assert_eq!(base_url("no-url"), None);
    }

    #[test]
    fn parametrizable_discrimina() {
        assert!(is_parameterizable("https://x/y?id=1"));
        assert!(is_parameterizable("https://x/api/users"));
        assert!(is_parameterizable("https://x/index.php"));
        assert!(!is_parameterizable("https://x/static/logo.png"));
    }

    #[test]
    fn parsea_ffuf() {
        let j = r#"{"results":[{"url":"https://x/admin","status":200},{"url":"https://x/.git","status":403}]}"#;
        let urls = parse_ffuf_json(j);
        assert_eq!(urls, vec!["https://x/admin", "https://x/.git"]);
        assert!(parse_ffuf_json("no json").is_empty());
    }

    #[test]
    fn parsea_arjun_lista_y_objeto() {
        let j = r#"{"https://x/a":["id","token"],"https://x/b":{"q":{},"p":{}},"https://x/c":[]}"#;
        let mut got = parse_arjun_json(j);
        got.sort();
        assert_eq!(got[0].0, "https://x/a");
        assert_eq!(got[0].1, vec!["id", "token"]);
        assert_eq!(got[1].0, "https://x/b");
        assert_eq!(got[1].1.len(), 2);
        // 'c' con lista vacía se descarta.
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn push_new_dedup_y_solo_http() {
        let mut seen = BTreeSet::new();
        let mut dst = Vec::new();
        push_new(&mut seen, &mut dst, "https://a".into());
        push_new(&mut seen, &mut dst, "https://a".into()); // dup
        push_new(&mut seen, &mut dst, "ftp://b".into());    // no http
        assert_eq!(dst, vec!["https://a"]);
    }
}
