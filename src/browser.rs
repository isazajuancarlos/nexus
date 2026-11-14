//! Confirmación de XSS por EJECUCIÓN en un navegador real (Chromium headless como
//! subprocess, coherente con `evidence.rs` — sin cliente CDP en proceso).
//!
//! El problema que resuelve: `verify::interpret_xss` marcaba una XSS como
//! explotable con solo que xsstrike imprimiera "Payload:". xsstrike NO ejecuta un
//! navegador — hace análisis heurístico de reflexión —, así que una reflexión
//! INERTE (un marcador que no ejecuta, o un payload reflejado dentro de un string
//! JS sin breakout) pasaba como VERIFIED+explotable y alimentaba el auto-envío a
//! H1. Es la directiva 28 sin aplicar: nunca se cruzaba la frontera real (un
//! navegador que DIBUJE la página y EJECUTE el JS).
//!
//! El discriminador (directiva 33) es un **marcador COMPUTADO**: el payload
//! inyectado ejecuta `setAttribute('data-nxproof', nonce*2)`. Se comprueba que el
//! DOM resultante (tras correr el JS) contenga `data-nxproof="<nonce*2 YA
//! CALCULADO>"`. El TEXTO del payload reflejado contiene `nonce*2` literal, NUNCA
//! el producto; que aparezca el producto prueba que el script se EJECUTÓ, no que
//! se reflejó. Caso rojo (reflexión inerte) → marcador ausente; caso verde
//! (ejecución) → marcador presente.

use crate::config::Config;
use crate::error::Result;
use std::time::Duration;

/// Nombre del atributo-testigo que el payload pone sobre <html> al ejecutar.
const PROOF_ATTR: &str = "data-nxproof";

/// Resultado de una comprobación de ejecución.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecCheck {
    /// El marcador computado apareció en el DOM → el JS inyectado ejecutó.
    pub executed: bool,
    /// La página servida es de error/challenge (Cloudflare, 403, "Whoops"…): la
    /// ausencia de ejecución NO es concluyente en ese caso.
    pub error_page: bool,
}

/// Veredicto de la confirmación de XSS tras N intentos.
#[derive(Debug, Clone)]
pub struct XssConfirm {
    /// Ejecutó de forma REPRODUCIBLE (aciertos ≥ mínimo).
    pub confirmed: bool,
    pub oks: usize,
    pub tries: usize,
    /// "aciertos/intentos", p. ej. "3/3". Para `repro_ratio` en BD.
    pub ratio: String,
}

/// Percent-encoding de TODO byte que no sea "unreserved" (RFC 3986: ALPHA/DIGIT/
/// `-._~`). Suficientemente agresivo para meter un payload con `<>"'/` en una URL
/// sin romperla. Puro.
pub fn percent_encode_all(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for &b in s.as_bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~');
        if unreserved {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

/// El JS de prueba y su marcador computado, para un nonce. Pone el atributo-testigo COMPUTADO
/// (`data-nxproof="2·nonce"`) sobre `<html>` vía `dataset` — la prueba máquina-verificable. Se
/// EXPONE para que el bucle de XSS (`crate::xss`) lo envuelva en VECTORES distintos
/// (img/svg/onload/ontoggle… y los moldes de nuclei), no solo `<script>`.
///
/// **Sin COMILLAS ni ESPACIOS a propósito**: `dataset.nxproof=N*2` no usa literales de cadena,
/// así el MISMO JS inyecta en atributo con comillas (`onerror="…"`), SIN comillas (los vectores
/// de nuclei, `onfocus=…`) y dentro de `<script>`. Con `setAttribute('…')` las comillas simples
/// rompían el contexto sin comillas y el molde de nuclei no ejecutaba (medido 2026-08-25). El
/// banner visible se retiró por la misma razón; el marcador es el atributo, no el banner.
pub fn canary_js(nonce: u64) -> (String, String) {
    let computed = nonce * 2; // el navegador calcula esto; el texto reflejado no.
    let js = format!("(function(){{try{{document.documentElement.dataset.nxproof={nonce}*2}}catch(e){{}}}})()");
    // Cómo Chromium serializa el atributo en outerHTML: name="value".
    let marker = format!("{PROOF_ATTR}=\"{computed}\"");
    (js, marker)
}

pub fn build_canary(nonce: u64) -> (String, String) {
    let (js, marker) = canary_js(nonce);
    let payload = format!(
        "'\"></title></textarea></style></noscript></script><script>{js}</script>"
    );
    (payload, marker)
}

/// ¿El DOM (tras ejecutar JS) contiene el marcador computado? Puro. Es el
/// discriminador: solo aparece si el script inyectado corrió.
pub fn executed(dom: &str, marker: &str) -> bool {
    dom.contains(marker)
}

/// ¿El DOM es una página de error o un challenge (no la página real)? Regla por
/// enumeración de señales conocidas (directiva 23). Puro. Se usa para no tratar un
/// "no ejecutó" como negativo real cuando en realidad nos sirvieron un muro.
pub fn is_error_page(dom: &str) -> bool {
    let d = dom.to_lowercase();
    const SIGNALS: &[&str] = &[
        "something went wrong",
        "just a moment",          // challenge de Cloudflare
        "attention required",     // Cloudflare block
        "access denied",
        "request unsuccessful",
        "error 1020",             // Cloudflare access rule
        "captcha",
        "verify you are human",
        "temporarily unavailable",
        "403 forbidden",
    ];
    SIGNALS.iter().any(|s| d.contains(s))
}

/// Inyecta el payload en la URL. Si hay query, sustituye el VALOR del último
/// parámetro (el caso común de reflected-xss de nuclei: payload en un parámetro);
/// si no, lo añade como último segmento del path. Puro y testable.
///
/// No pretende cubrir todos los puntos de inyección: si el reflejo estaba en otro
/// parámetro, el gate no confirmará y el hallazgo se queda en MANUAL_READY —
/// fail-closed, que es la dirección segura para algo que puede auto-enviarse.
pub fn inject_canary(url: &str, payload: &str) -> String {
    let enc = percent_encode_all(payload);
    // Separa fragmento (#...) para no inyectar dentro de él.
    let (pre, frag) = match url.split_once('#') {
        Some((p, f)) => (p.to_string(), format!("#{f}")),
        None => (url.to_string(), String::new()),
    };
    let injected = if let Some((base, query)) = pre.split_once('?') {
        let mut params: Vec<String> = query.split('&').map(String::from).collect();
        if let Some(last) = params.last_mut() {
            let key = last.split_once('=').map(|(k, _)| k.to_string()).unwrap_or_else(|| last.clone());
            *last = format!("{key}={enc}");
        } else {
            params.push(enc);
        }
        format!("{base}?{}", params.join("&"))
    } else {
        // Sin query: añade un segmento de path (reflexión en el path).
        let trimmed = pre.trim_end_matches('/');
        format!("{trimmed}/{enc}")
    };
    format!("{injected}{frag}")
}

/// Codificación LIGERA para el fragmento: solo lo que rompe la URL como token (espacio,
/// `#`, `%`, control). Deja `<>"'/=` CRUDOS a propósito — un sink de DOM-XSS que lee
/// `location.hash` los interpreta tal cual, y percent-encodearlos impediría la ejecución en
/// el sink común (`document.write(location.hash)` sin `decodeURIComponent`). Puro.
fn encode_fragmento(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b' ' | b'#' | b'%' | 0..=0x1f => format!("%{b:02X}"),
            _ => (b as char).to_string(),
        })
        .collect()
}

/// Inyecta el payload en el **#FRAGMENTO**, que [`inject_canary`] deja intacto a propósito y
/// que es donde vive el DOM-XSS clásico de `location.hash` (`#<img src=x onerror=…>`). Es el
/// punto que nexus no probaba: el fragmento no viaja al servidor, así que solo un navegador
/// que EJECUTE el JS de la página lo alcanza — justo lo que este módulo hace. Puro.
pub fn inject_canary_fragmento(url: &str, payload: &str) -> String {
    let base = url.split_once('#').map(|(p, _)| p).unwrap_or(url);
    format!("{base}#{}", encode_fragmento(payload))
}

/// Un punto donde inyectar el canary en una URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Punto {
    /// El i-ésimo parámetro de la query (se sustituye su VALOR).
    Parametro(usize),
    /// El fragmento (`#…`), para DOM-XSS de `location.hash`.
    Fragmento,
    /// Un segmento de path (cuando no hay query).
    Path,
}

/// **Enumera los puntos de inyección de una URL, no solo el último parámetro.** Cada
/// parámetro de la query, el FRAGMENTO, y —si no hay query— el path. Probar solo el último
/// parámetro (lo que hace [`inject_canary`]) deja fuera el DOM-XSS de un parámetro arbitrario
/// o del hash. Puro.
pub fn puntos_de(url: &str) -> Vec<Punto> {
    let pre = url.split_once('#').map(|(p, _)| p).unwrap_or(url);
    let mut v = Vec::new();
    if let Some((_, query)) = pre.split_once('?') {
        for i in 0..query.split('&').count() {
            v.push(Punto::Parametro(i));
        }
    } else {
        v.push(Punto::Path);
    }
    v.push(Punto::Fragmento);
    v
}

/// Inyecta `payload` en el `punto` dado de `url`. Puro. `Parametro`/`Path` van con
/// percent-encode agresivo; `Fragmento`, con el ligero (el sink DOM lo lee crudo).
pub fn inject_canary_en(url: &str, payload: &str, punto: Punto) -> String {
    if punto == Punto::Fragmento {
        return inject_canary_fragmento(url, payload);
    }
    let enc = percent_encode_all(payload);
    let (pre, frag) = match url.split_once('#') {
        Some((p, f)) => (p.to_string(), format!("#{f}")),
        None => (url.to_string(), String::new()),
    };
    let inj = match (pre.split_once('?'), punto) {
        (Some((base, query)), Punto::Parametro(i)) => {
            let mut params: Vec<String> = query.split('&').map(String::from).collect();
            if let Some(p) = params.get_mut(i) {
                let key = p.split_once('=').map(|(k, _)| k.to_string()).unwrap_or_else(|| p.clone());
                *p = format!("{key}={enc}");
            }
            format!("{base}?{}", params.join("&"))
        }
        _ => {
            // Path, o Parametro sobre una URL sin query: un segmento de path.
            let trimmed = pre.trim_end_matches('/');
            format!("{trimmed}/{enc}")
        }
    };
    format!("{inj}{frag}")
}

/// Una comprobación de ejecución en un PUNTO concreto (variante de [`confirm_execution_once`]
/// que elige dónde inyectar).
async fn confirm_execution_once_en(cfg: &Config, target: &str, punto: Punto, nonce: u64) -> ExecCheck {
    let (payload, marker) = build_canary(nonce);
    let url = inject_canary_en(target, &payload, punto);
    match dump_dom(cfg, &url).await {
        Ok(dom) => ExecCheck { executed: executed(&dom, &marker), error_page: is_error_page(&dom) },
        Err(_) => ExecCheck { executed: false, error_page: false },
    }
}

/// **Confirma una XSS probando TODOS los puntos** (cada parámetro y el fragmento), no solo el
/// último parámetro. Por cada punto corre `tries` intentos con nonces distintos y exige
/// `min_ok` ejecuciones (la misma reproducibilidad que [`confirm_xss`]); devuelve el primer
/// punto que confirma. Amplía la COBERTURA sin tocar el discriminador (marcador computado).
pub async fn confirm_xss_multipunto(
    cfg: &Config,
    target: &str,
    tries: usize,
    min_ok: usize,
    nonce_base: u64,
) -> XssConfirm {
    for (idx, punto) in puntos_de(target).into_iter().enumerate() {
        let mut oks = 0usize;
        for i in 0..tries {
            let nonce = nonce_base + (idx as u64) * 1000 + i as u64;
            if confirm_execution_once_en(cfg, target, punto, nonce).await.executed {
                oks += 1;
            }
        }
        if decide(oks, tries, min_ok) {
            return XssConfirm { confirmed: true, oks, tries, ratio: format!("{oks}/{tries}") };
        }
    }
    XssConfirm { confirmed: false, oks: 0, tries, ratio: format!("0/{tries}") }
}

/// Corre Chromium headless y devuelve el DOM SERIALIZADO tras ejecutar el JS de la
/// página (`--dump-dom`). Cruza la frontera del programa (directiva 28).
pub async fn dump_dom(cfg: &Config, url: &str) -> Result<String> {
    let args: Vec<String> = vec![
        "--headless=new".into(),
        "--disable-gpu".into(),
        "--no-sandbox".into(),
        "--hide-scrollbars".into(),
        "--disable-dev-shm-usage".into(),
        "--virtual-time-budget=6000".into(), // deja correr timers/carga antes de volcar
        "--dump-dom".into(),
        url.into(),
    ];
    let out = crate::tools::run(&cfg.chromium_path, &args, Duration::from_secs(30)).await?;
    Ok(out.stdout)
}

/// Una comprobación de ejecución: inyecta el canary en `target`, lo abre en
/// Chromium y mira si el marcador computado ejecutó. `nonce` varía por intento.
pub async fn confirm_execution_once(cfg: &Config, target: &str, nonce: u64) -> ExecCheck {
    let (payload, marker) = build_canary(nonce);
    let url = inject_canary(target, &payload);
    match dump_dom(cfg, &url).await {
        Ok(dom) => ExecCheck { executed: executed(&dom, &marker), error_page: is_error_page(&dom) },
        // Chromium ausente o caído: fail-closed (no confirmado), no es página de error.
        Err(_) => ExecCheck { executed: false, error_page: false },
    }
}

/// Decide si N aciertos de M intentos bastan. Puro (directiva 33: su pareja
/// verde/rojo en tests). `min_ok` aciertos EJECUTADOS hacen falta.
pub fn decide(oks: usize, tries: usize, min_ok: usize) -> bool {
    oks >= min_ok && tries > 0
}

/// Confirma una XSS por ejecución reproducible: corre el gate `tries` veces y
/// exige `min_ok` ejecuciones. La reproducibilidad está aquí: un reflejo
/// intermitente (p. ej. gateado por un challenge) no junta los aciertos y NO se
/// confirma → no se auto-envía.
pub async fn confirm_xss(cfg: &Config, target: &str, tries: usize, min_ok: usize, nonce_base: u64) -> XssConfirm {
    let mut oks = 0usize;
    for i in 0..tries {
        let c = confirm_execution_once(cfg, target, nonce_base + i as u64).await;
        if c.executed {
            oks += 1;
        }
    }
    XssConfirm {
        confirmed: decide(oks, tries, min_ok),
        oks,
        tries,
        ratio: format!("{oks}/{tries}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_marcador_es_el_producto_calculado_no_el_texto_del_payload() {
        // El payload contiene "124*2" LITERAL; el marcador esperado contiene 248.
        let (payload, marker) = build_canary(124);
        assert!(payload.contains("124*2"), "el payload lleva la multiplicación sin resolver");
        assert!(!payload.contains("\"248\""), "el payload NO contiene el producto ya calculado");
        assert_eq!(marker, "data-nxproof=\"248\"");
    }

    #[test]
    fn executed_discrimina_ejecucion_de_reflexion() {
        let (payload, marker) = build_canary(124);
        // Caso VERDE: el DOM trae el atributo con el valor COMPUTADO (el navegador corrió el JS).
        let dom_ejecuto = r#"<html data-nxproof="248"><body><div id="nxproof">NEXUS-XSS-CONFIRMED 248</div></body></html>"#;
        assert!(executed(dom_ejecuto, &marker));
        // Caso ROJO: el DOM solo trae el TEXTO del payload reflejado, sin ejecutar.
        // Contiene "124*2" y hasta la subcadena "data-nxproof" dentro del script como
        // TEXTO, pero NO el atributo serializado con el producto.
        let dom_reflejo = format!("<html><body>busqueda: {payload}</body></html>");
        assert!(!executed(&dom_reflejo, &marker), "reflexión inerte NO debe contar como ejecución");
    }

    #[test]
    fn is_error_page_reconoce_muros_y_deja_pasar_lo_normal() {
        assert!(is_error_page("<h1>Whoops! Something went wrong</h1>"));
        assert!(is_error_page("<title>Just a moment...</title>")); // Cloudflare
        assert!(is_error_page("Access Denied"));
        assert!(!is_error_page("<html><body>Bienvenido a la tienda</body></html>"));
    }

    #[test]
    fn inject_canary_en_query_sustituye_el_ultimo_parametro() {
        let u = inject_canary("https://x.com/buscar?q=hola&page=2", "<b>P</b>");
        assert!(u.starts_with("https://x.com/buscar?q=hola&page="));
        assert!(u.contains("%3Cb%3E"), "el payload va percent-encoded");
        assert!(!u.contains("<b>"), "no queda crudo en la URL");
    }

    #[test]
    fn inject_canary_sin_query_lo_pone_en_el_path() {
        let u = inject_canary("https://x.com/gitlab/build_now", "<s>P</s>");
        assert!(u.starts_with("https://x.com/gitlab/build_now/"));
        assert!(u.contains("%3Cs%3E"));
    }

    #[test]
    fn inject_canary_respeta_el_fragmento() {
        let u = inject_canary("https://x.com/a?p=1#seccion", "X<Y");
        assert!(u.ends_with("#seccion"), "el fragmento queda al final, sin payload dentro");
        assert!(u.contains("p=X%3CY"));
    }

    #[test]
    fn percent_encode_no_toca_unreserved_y_codifica_lo_demas() {
        assert_eq!(percent_encode_all("aZ9-._~"), "aZ9-._~");
        assert_eq!(percent_encode_all("<>\"'"), "%3C%3E%22%27");
        assert_eq!(percent_encode_all(" "), "%20");
    }

    #[test]
    fn decide_exige_el_minimo_de_aciertos() {
        assert!(decide(2, 3, 2), "2/3 con mínimo 2 → confirma");
        assert!(decide(3, 3, 2));
        assert!(!decide(1, 3, 2), "1/3 con mínimo 2 → intermitente, no confirma");
        assert!(!decide(0, 0, 1), "sin intentos, nunca confirma");
    }

    /// **El delta de cobertura: se enumeran TODOS los puntos, incluido el fragmento.** Una
    /// URL con dos parámetros da tres puntos (param 0, param 1, fragmento); una sin query da
    /// dos (path, fragmento). Sin esto, el DOM-XSS de un parámetro que no es el último, o del
    /// hash, quedaba sin probar.
    #[test]
    fn puntos_de_enumera_cada_parametro_y_el_fragmento() {
        assert_eq!(
            puntos_de("https://x.com/b?q=1&page=2"),
            vec![Punto::Parametro(0), Punto::Parametro(1), Punto::Fragmento]
        );
        assert_eq!(puntos_de("https://x.com/perfil"), vec![Punto::Path, Punto::Fragmento]);
        // El fragmento previo no cambia los puntos (se re-inyecta sobre la base).
        assert_eq!(
            puntos_de("https://x.com/b?q=1#seccion"),
            vec![Punto::Parametro(0), Punto::Fragmento]
        );
    }

    /// Inyectar en el FRAGMENTO pone el payload tras `#`, con los `<>` CRUDOS (el sink DOM los
    /// lee tal cual) y solo lo que rompe la URL codificado. Su pareja: inyectar en el
    /// parámetro 0 (no el último) toca ese parámetro y deja el otro intacto.
    #[test]
    fn inject_canary_en_cubre_fragmento_y_parametro_arbitrario() {
        // Fragmento: <> crudos, espacio codificado.
        let f = inject_canary_en("https://x.com/a?p=1", "<img src=x onerror=alert>", Punto::Fragmento);
        assert!(f.starts_with("https://x.com/a?p=1#"));
        assert!(f.contains("<img"), "el sink DOM lee el hash crudo: los <> no se codifican");
        assert!(f.contains("onerror=alert"));
        // Parámetro 0 de dos: toca q, deja page.
        let p0 = inject_canary_en("https://x.com/a?q=hola&page=2", "<b>P</b>", Punto::Parametro(0));
        assert!(p0.contains("q=%3Cb%3E"), "el payload va en q, percent-encoded");
        assert!(p0.contains("&page=2"), "el otro parámetro queda intacto");
    }
}
