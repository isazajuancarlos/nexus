// SPDX-License-Identifier: LicenseRef-Propietario
//! Secretos en el JS SERVIDO de un objetivo (cableado de la fase 0.1 al crawler).
//!
//! `secretos::detectar` ya reconoce secretos por PATRÓN en un cuerpo, y `rastreo`
//! ya BAJA los bundles `.js` (con evasión de WAF) para minar endpoints. Lo que
//! faltaba era unir las dos: pasar el JS servido por el detector. Es la clase del
//! leak de partners de Microsoft (faav, ago-2025: API key de Azure Search en el JS
//! del cliente) y, más en general, de cualquier programa con frontend web — una
//! key/token filtrada en un bundle de cliente.
//!
//! Disciplina (la misma de `secretos.rs`): se reporta por patrón, el VALOR se
//! ENMASCARA (nunca se vuelca el secreto al log/informe), y la confirmación de que
//! está VIVA es opt-in y por ejecución contra el proveedor (`secretos::verificar`),
//! no por presencia. Un `publicable()` (p.ej. `pk_live_` de Stripe) se detecta pero
//! NO es fuga, y se marca como tal.

use crate::secretos::{self, ClaseSecreto, Veredicto};

/// Un secreto hallado en un asset JS (o en el HTML raíz) de un objetivo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HallazgoSecretoJs {
    /// URL del asset donde apareció (el HTML raíz o un bundle `.js`).
    pub url: String,
    pub clase: ClaseSecreto,
    /// El secreto ENMASCARADO (prefijo + cola, centro oculto). Nunca el valor pleno.
    pub valor_enmascarado: String,
    /// Veredicto de verificación VIVA, si se corrió (`--verificar`). `None` = no se
    /// verificó; `Publicable`/`NoVerificable`/`Vivo`/`Muerto` según el caso.
    pub veredicto: Option<Veredicto>,
}

/// Enmascara un secreto para mostrarlo sin filtrarlo: conserva hasta 8 chars de
/// cabecera (incluye el prefijo que da la clase) y 2 de cola; el centro, `…`.
pub fn enmascarar(valor: &str) -> String {
    let n = valor.chars().count();
    if n <= 12 {
        // Corto: muestra solo la cabecera, nunca entero.
        let cab: String = valor.chars().take(4).collect();
        return format!("{cab}…");
    }
    let cab: String = valor.chars().take(8).collect();
    let cola: String = valor.chars().skip(n - 2).collect();
    format!("{cab}…{cola}")
}

/// Escanea una colección de `(url, cuerpo)` ya descargados. PURO y testable: no
/// toca la red. Es el núcleo que el driver y las pruebas comparten.
pub fn escanear_cuerpos(cuerpos: &[(String, String)]) -> Vec<HallazgoSecretoJs> {
    let mut out = Vec::new();
    let mut vistos = std::collections::BTreeSet::new();
    for (url, cuerpo) in cuerpos {
        for s in secretos::detectar(cuerpo) {
            // Dedup por (url, clase, valor): el mismo bundle repite el mismo literal.
            let clave = (url.clone(), s.clase.nombre(), s.valor.clone());
            if !vistos.insert(clave) {
                continue;
            }
            out.push(HallazgoSecretoJs {
                url: url.clone(),
                clase: s.clase,
                valor_enmascarado: enmascarar(&s.valor),
                veredicto: None,
            });
        }
    }
    out
}

/// Positivo de control del escaneo (D30): distingue "escaneado y limpio" de "no
/// se bajó nada". Sin esto, un `Vec` vacío es ambiguo — un fetch fallido (302 no
/// seguido, WAF, DNS) se ve idéntico a un objetivo sin secretos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Diag {
    /// Status del HTML raíz (tras seguir redirects del cliente). 0 = no respondió.
    pub root_status: u16,
    /// Nº de recursos (HTML raíz + bundles `.js`) efectivamente bajados y escaneados.
    pub recursos: usize,
    /// Bytes totales escaneados.
    pub bytes: usize,
}

/// Driver: baja el HTML raíz del objetivo, extrae y baja sus bundles `.js` (con
/// evasión de WAF, antibaneo por el `Guard`), y escanea TODO por secretos. Si
/// `verificar` está activo, confirma por ejecución los secretos verificables.
///
/// Devuelve los hallazgos con el valor enmascarado. El HTML raíz también se escanea
/// (un secreto inline en el index es tan fuga como en un bundle).
#[allow(clippy::too_many_arguments)]
pub async fn escanear_objetivo(
    cliente: &reqwest::Client,
    base: &str,
    curl_impersonate_path: &str,
    max_js: usize,
    timeout_secs: u64,
    guard: &mut crate::protection::Guard,
    mut rng: impl FnMut() -> f64,
    verificar: bool,
) -> (Vec<HallazgoSecretoJs>, Diag) {
    let base = if base.starts_with("http") {
        base.trim_end_matches('/').to_string()
    } else {
        format!("https://{}", base.trim_end_matches('/'))
    };

    let mut cuerpos: Vec<(String, String)> = Vec::new();
    let root =
        crate::impersonate::fetch_evasion(cliente, &base, &[], curl_impersonate_path, timeout_secs)
            .await;
    tokio::time::sleep(guard.cooldown(1, rng())).await;
    if matches!(root.status, 200..=299) && !root.body.is_empty() {
        // El HTML raíz también puede llevar un secreto inline.
        cuerpos.push((base.clone(), root.body.clone()));
        for js in crate::rastreo::extraer_scripts_js(&root.body).into_iter().take(max_js) {
            let js_url = crate::rastreo::resolver(&base, &js);
            let r = crate::impersonate::fetch_evasion(
                cliente,
                &js_url,
                &[],
                curl_impersonate_path,
                timeout_secs,
            )
            .await;
            tokio::time::sleep(guard.cooldown(1, rng())).await;
            if matches!(r.status, 200..=299) && !r.body.is_empty() {
                cuerpos.push((js_url, r.body));
            }
        }
    }

    let diag = Diag {
        root_status: root.status,
        recursos: cuerpos.len(),
        bytes: cuerpos.iter().map(|(_, c)| c.len()).sum(),
    };

    let mut hallazgos = escanear_cuerpos(&cuerpos);

    if verificar {
        for h in &mut hallazgos {
            // Reconstruye el detectado para pasarlo a `verificar`. El valor pleno no
            // se conserva en el hallazgo (enmascarado), así que re-detectamos sobre
            // el cuerpo de su url para recuperar el literal exacto a verificar.
            if let Some(cuerpo) = cuerpos.iter().find(|(u, _)| *u == h.url).map(|(_, c)| c) {
                if let Some(det) =
                    secretos::detectar(cuerpo).into_iter().find(|d| d.clase == h.clase)
                {
                    h.veredicto = Some(secretos::verificar(&det).await);
                }
            }
        }
    }
    (hallazgos, diag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enmascara_sin_filtrar_el_secreto() {
        let v = format!("ghp_{}", "a".repeat(36));
        let m = enmascarar(&v);
        assert!(m.starts_with("ghp_"), "conserva el prefijo de clase");
        assert!(m.contains('…'));
        assert!(!m.contains(&"a".repeat(36)), "NO filtra el cuerpo del secreto");
        // Corto: solo cabecera.
        assert_eq!(enmascarar("sk-short"), "sk-s…");
    }

    #[test]
    fn detecta_secreto_en_js_y_no_en_benigno() {
        let ghp = format!("ghp_{}", "a".repeat(36));
        let cuerpos = vec![
            ("https://t/app.js".to_string(), format!("var T='{ghp}';")),
            // PAREJA (D33): un bundle con solo texto benigno NO produce hallazgo.
            ("https://t/vendor.js".to_string(), "const api_key = cfg.get('apikey');".to_string()),
        ];
        let h = escanear_cuerpos(&cuerpos);
        assert_eq!(h.len(), 1, "solo el bundle con el token real marca");
        assert_eq!(h[0].clase, ClaseSecreto::GithubToken);
        assert_eq!(h[0].url, "https://t/app.js");
        assert!(h[0].veredicto.is_none(), "sin --verificar no hay veredicto");
    }

    #[test]
    fn publicable_se_detecta_pero_no_es_fuga() {
        // Una pk_live de Stripe es pública por diseño: aparece, pero su clase lo dice.
        let pk = format!("pk_live_{}", "c".repeat(30));
        let h = escanear_cuerpos(&[("https://t/app.js".to_string(), format!("k='{pk}'"))]);
        assert_eq!(h.len(), 1);
        assert!(h[0].clase.publicable(), "clasificada como publicable, no fuga");
    }
}
