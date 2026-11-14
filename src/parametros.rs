// SPDX-License-Identifier: LicenseRef-Propietario
//! Descubrimiento de PARÁMETROS OCULTOS por ANOMALÍA (veta mindalá, 2026-09-24).
//!
//! Reimplementa la técnica de **Arjun** (`core/anomaly.py` + `bruter.py`, AGPL-3.0):
//! un parámetro que el backend PROCESA —aunque no esté documentado— cambia la respuesta.
//! Se fija una LÍNEA BASE de "factores" observables (estado, cabeceras, longitud, líneas,
//! y sobre todo REFLEXIÓN de un centinela) y se compara; los parámetros efectivos se
//! aíslan por **bisección de lotes**. AGPL ⇒ **reimplementado desde el entendimiento, sin
//! copiar** (D10/estándar `[[estandar-clonar-y-estudiar-repos]]`).
//!
//! **Por qué en nexus** (veta `conocimiento/proyectos/mindala/estudios/nexus-recon-llm.md`):
//! `autz`/`mass_assign`/`graphql` prueban IDOR/BOLA/mass-assignment sobre parámetros que
//! ya CONOCEN; ninguno ENUMERA la superficie oculta. Un parámetro no documentado que el
//! backend acepta es superficie fresca de esas mismas clases. Este módulo produce esa
//! lista para alimentarlos — cae en el área VIVA (authz), no despierta el nexus dormido.
//!
//! **Estatuto** (`[[nexus-detector-ataca-para-encontrar]]`): sondea con nombres de un
//! diccionario y un VALOR CENTINELA benigno (`nexusprb_*`). No escribe recursos ajenos, no
//! borra, no descarga en masa (techo de lectura); por defecto usa `GET`. Es descubrimiento
//! de superficie, read-oriented, no un ataque.
//!
//! El núcleo (factores, línea base, anomalía, bisección) es **PURO** y se prueba en proceso
//! con su caso rojo (D33); el driver HTTP inyecta el oráculo en la MISMA `aislar` que usan
//! las pruebas, así que el rojo falla por la vía real (D28/D33).

use std::collections::BTreeSet;
use std::future::Future;

use crate::oraculo_diferencial::Identidad;

/// Prefijo del valor CENTINELA que se inyecta como valor de cada parámetro sondeado.
/// Es único y no aparece en una respuesta natural, así que si REFLEJA sabemos que el
/// backend procesó (y devolvió) algún parámetro del lote. El sufijo aleatorio lo pone el
/// driver por corrida para no colisionar con un centinela cacheado de una sonda previa.
pub const CENTINELA_PREFIJO: &str = "nexusprb";

/// Los factores observables de UNA respuesta. Un parámetro procesado cambia ≥1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Factores {
    pub status: u16,
    /// Nombres de cabecera presentes (en minúsculas; los valores varían demasiado).
    pub cabeceras: BTreeSet<String>,
    pub cuerpo_len: usize,
    pub lineas: usize,
    /// ¿Apareció el centinela en el cuerpo? La señal más robusta y monótona bajo
    /// bisección: si refleja en un lote, refleja en el sub-lote que contiene al culpable.
    pub reflejo: bool,
}

/// Recorta `s` a lo sumo `max` BYTES, retrocediendo hasta una FRONTERA DE CARÁCTER. PURO.
/// `&str[..n]` por índice de byte crudo panica si `n` cae en medio de un multibyte, así que
/// un cuerpo grande del objetivo con UTF-8 en el límite tumbaría nexus. Se usa en todos los
/// techos de lectura de los drivers HTTP.
#[must_use]
pub fn recorte_seguro(s: &str, max: usize) -> &str {
    let mut n = s.len().min(max);
    while n > 0 && !s.is_char_boundary(n) {
        n -= 1;
    }
    &s[..n]
}

/// Calcula los factores de una respuesta. PURO. `cabeceras` = nombres tal cual llegan;
/// se normalizan a minúsculas aquí. `centinela` = el valor inyectado a buscar en el cuerpo.
#[must_use]
pub fn factores(status: u16, cabeceras: &[String], cuerpo: &str, centinela: &str) -> Factores {
    Factores {
        status,
        cabeceras: cabeceras.iter().map(|h| h.to_ascii_lowercase()).collect(),
        cuerpo_len: cuerpo.len(),
        lineas: cuerpo.lines().count(),
        reflejo: !centinela.is_empty() && cuerpo.contains(centinela),
    }
}

/// La línea base ESTABLE, derivada de ≥2 muestras con parámetros basura. Un factor solo
/// se usa para comparar si fue IDÉNTICO en todas las muestras: así una página dinámica
/// (longitud que fluctúa sola) no dispara una anomalía falsa (D23 — la señal que dispara
/// sobre variación legítima es la alarma que a la tercera nadie mira).
#[derive(Debug, Clone)]
pub struct LineaBase {
    pub status: u16,
    pub status_estable: bool,
    pub cabeceras: BTreeSet<String>,
    pub cabeceras_estable: bool,
    pub cuerpo_len: usize,
    pub len_estable: bool,
    pub lineas: usize,
    pub lineas_estable: bool,
}

/// Deriva la línea base de las muestras basura. Un factor es estable si TODAS coinciden.
/// Sin muestras → todo inestable (nada se compara: falla ruidosamente hacia "no sé", D20).
#[must_use]
pub fn linea_base(muestras: &[Factores]) -> LineaBase {
    let primera = muestras.first();
    let todas_igual = |f: &dyn Fn(&Factores) -> bool| muestras.iter().all(f);
    match primera {
        None => LineaBase {
            status: 0,
            status_estable: false,
            cabeceras: BTreeSet::new(),
            cabeceras_estable: false,
            cuerpo_len: 0,
            len_estable: false,
            lineas: 0,
            lineas_estable: false,
        },
        Some(p) => LineaBase {
            status: p.status,
            status_estable: todas_igual(&|m| m.status == p.status),
            cabeceras: p.cabeceras.clone(),
            cabeceras_estable: todas_igual(&|m| m.cabeceras == p.cabeceras),
            cuerpo_len: p.cuerpo_len,
            len_estable: todas_igual(&|m| m.cuerpo_len == p.cuerpo_len),
            lineas: p.lineas,
            lineas_estable: todas_igual(&|m| m.lineas == p.lineas),
        },
    }
}

/// Qué factor delató al parámetro. Se reporta para que el consumidor sepa por qué.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Senal {
    /// El centinela apareció en el cuerpo (el parámetro se refleja). La más fiable.
    Reflexion,
    Estado,
    Cabeceras,
    Longitud,
    Lineas,
}

impl Senal {
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Senal::Reflexion => "reflexión del centinela",
            Senal::Estado => "cambio de código de estado",
            Senal::Cabeceras => "cambio en el juego de cabeceras",
            Senal::Longitud => "cambio de longitud del cuerpo",
            Senal::Lineas => "cambio de número de líneas",
        }
    }
}

/// ¿La observación es anómala frente a la línea base? Devuelve la PRIMERA señal, o `None`.
///
/// `sensible_longitud` gatea los factores RUIDOSOS (longitud/líneas): en una página que
/// varía sola disparan sobre cualquier cosa y rompen la bisección (que asume que si un
/// lote es anómalo, un sub-lote lo hereda). La reflexión, el estado y el juego de
/// cabeceras SÍ son monótonos bajo bisección. Por eso longitud/líneas van OFF por defecto
/// y solo se encienden a mano en un endpoint que se sabe estable (D21: la restricción se
/// prueba contra el uso legítimo — un endpoint dinámico es el caso normal).
#[must_use]
pub fn anomalia(base: &LineaBase, obs: &Factores, sensible_longitud: bool) -> Option<Senal> {
    if obs.reflejo {
        return Some(Senal::Reflexion);
    }
    if base.status_estable && obs.status != base.status {
        return Some(Senal::Estado);
    }
    if base.cabeceras_estable && obs.cabeceras != base.cabeceras {
        return Some(Senal::Cabeceras);
    }
    if sensible_longitud {
        if base.len_estable && obs.cuerpo_len != base.cuerpo_len {
            return Some(Senal::Longitud);
        }
        if base.lineas_estable && obs.lineas != base.lineas {
            return Some(Senal::Lineas);
        }
    }
    None
}

/// Aísla, por BISECCIÓN, qué parámetros de `candidatos` son efectivos: los que hacen que
/// el `oraculo` marque anómalo un lote que los contiene. Iterativa (no recursiva) para
/// poder awaitear el oráculo async del driver; la MISMA función la usan las pruebas con un
/// oráculo síncrono envuelto en `async` (D33: el rojo falla por la vía real).
///
/// El oráculo debe ser MONÓTONO: si un lote es anómalo, al partirlo en dos, ≥1 mitad hereda
/// la anomalía. Con la señal de reflexión/estado/cabeceras se cumple. Un efecto que solo
/// aparece por COMBINACIÓN de dos parámetros (no monótono) NO se aísla: se devuelve vacío
/// en vez de fabricar un culpable (lo verifica una prueba). Coste: ≤ `n + k·log n` sondas
/// para `k` efectivos en `n` candidatos, no `n` sondas por parámetro.
pub async fn aislar<F, Fut>(candidatos: &[String], mut oraculo: F) -> Vec<String>
where
    F: FnMut(Vec<String>) -> Fut,
    Fut: Future<Output = bool>,
{
    let mut pila: Vec<Vec<String>> = vec![candidatos.to_vec()];
    let mut efectivos: Vec<String> = Vec::new();
    while let Some(grupo) = pila.pop() {
        if grupo.is_empty() {
            continue;
        }
        if !oraculo(grupo.clone()).await {
            continue; // el lote no altera la respuesta → ningún efectivo dentro
        }
        if grupo.len() == 1 {
            let p = grupo.into_iter().next().unwrap();
            if !efectivos.contains(&p) {
                efectivos.push(p);
            }
            continue;
        }
        let mitad = grupo.len() / 2;
        // Ambas mitades vuelven a la pila: un efectivo puede estar en cualquiera.
        pila.push(grupo[mitad..].to_vec());
        pila.push(grupo[..mitad].to_vec());
    }
    efectivos.sort();
    efectivos
}

/// Método con el que se inyectan los parámetros sondeados.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metodo {
    /// `GET ?p=centinela` (por defecto: read-only puro).
    Get,
    /// `POST` con cuerpo `application/x-www-form-urlencoded`.
    PostForm,
    /// `POST` con cuerpo JSON `{"p":"centinela"}`.
    PostJson,
}

/// Configuración del descubrimiento.
#[derive(Debug, Clone)]
pub struct Config {
    pub metodo: Metodo,
    /// Parámetros por sonda (techo de longitud de URL / cuerpo). Cada lote es 1 petición
    /// al inicio; la bisección solo añade sondas donde HAY señal.
    pub tam_lote: usize,
    /// Enciende los factores de longitud/líneas (OFF por defecto; ver `anomalia`).
    pub sensible_longitud: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config { metodo: Metodo::Get, tam_lote: 64, sensible_longitud: false }
    }
}

/// Un parámetro oculto descubierto y por qué.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descubierto {
    pub nombre: String,
    pub senal: Senal,
}

/// Nombres basura para la línea base: no están en ningún diccionario real y no deberían
/// tener efecto. Si UNO tiene efecto, el objetivo acepta CUALQUIER parámetro (comodín):
/// entonces el diccionario no discrimina y se aborta (lo maneja `descubrir`).
fn nombres_basura(centinela: &str) -> Vec<String> {
    (0..3).map(|i| format!("zqx{centinela}{i}")).collect()
}

/// Construye la petición con los parámetros del lote (cada uno = `centinela`), aplica las
/// cabeceras de la identidad, la envía y calcula sus factores. `None` si la red falla.
async fn sondar(
    cliente: &reqwest::Client,
    url: &str,
    id: &Identidad,
    cfg: &Config,
    nombres: &[String],
    centinela: &str,
) -> Option<Factores> {
    let pares: Vec<(String, String)> =
        nombres.iter().map(|n| (n.clone(), centinela.to_string())).collect();
    let mut req = match cfg.metodo {
        Metodo::Get => cliente.get(url).query(&pares),
        Metodo::PostForm => {
            // Cuerpo `application/x-www-form-urlencoded` a mano: `reqwest::form` está tras
            // una feature no activada (deps mínimas). Nombres = diccionario (ASCII seguro),
            // valor = centinela hex, así que un join `k=v&…` es correcto sin escapar.
            let cuerpo = pares
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("&");
            cliente
                .post(url)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(cuerpo)
        }
        Metodo::PostJson => {
            let mapa: serde_json::Map<String, serde_json::Value> = pares
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect();
            cliente.post(url).json(&mapa)
        }
    };
    for (k, v) in &id.cabeceras {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = req.send().await.ok()?;
    let status = resp.status().as_u16();
    let nombres_cab: Vec<String> = resp.headers().keys().map(|k| k.as_str().to_string()).collect();
    let cuerpo = resp.text().await.ok()?;
    // Techo de lectura (read-only ≠ leer gigas): con 512 KiB basta para los factores.
    let recorte = recorte_seguro(&cuerpo, 512 * 1024);
    Some(factores(status, &nombres_cab, recorte, centinela))
}

/// Descubre los parámetros ocultos de `url` bajo `identidad`. Devuelve los efectivos con su
/// señal. La lista alimenta a `autz`/`mass_assign`/`graphql` (superficie nueva de IDOR/
/// mass-assignment). Vacío si no hay señal o si el objetivo es COMODÍN (acepta cualquier
/// nombre → el diccionario no discrimina, D30: un negativo solo vale si el camino discrimina).
pub async fn descubrir(
    cliente: &reqwest::Client,
    url: &str,
    identidad: &Identidad,
    diccionario: &[String],
    cfg: &Config,
) -> anyhow::Result<Vec<Descubierto>> {
    // Centinela único por corrida.
    let sufijo: u32 = rand::random();
    let centinela = format!("{CENTINELA_PREFIJO}{sufijo:08x}");

    // Línea base: 2 muestras con nombres basura. Si un basura refleja o el juego es
    // inestable de entrada, se ajusta la sensibilidad.
    let basura = nombres_basura(&centinela);
    let mut muestras = Vec::new();
    for _ in 0..2 {
        if let Some(f) = sondar(cliente, url, identidad, cfg, &basura, &centinela).await {
            muestras.push(f);
        }
    }
    if muestras.len() < 2 {
        anyhow::bail!("no se pudo establecer la línea base (red o objetivo inaccesible)");
    }
    // COMODÍN: si un nombre basura ya disparó anomalía (p.ej. refleja), el objetivo acepta
    // cualquier parámetro y el diccionario no discrimina — abortar en vez de reportar todo.
    let base = linea_base(&muestras);
    if muestras.iter().any(|m| anomalia(&base, m, cfg.sensible_longitud).is_some()) {
        anyhow::bail!(
            "objetivo COMODÍN: un parámetro inexistente ya altera la respuesta; el diccionario no discrimina (D30)"
        );
    }

    // Diccionario en lotes; bisección por lote. El centinela y la señal se recalculan en la
    // MISMA `sondar` dentro del oráculo, así que la señal reportada es la real.
    let mut hallados: Vec<Descubierto> = Vec::new();
    for lote in diccionario.chunks(cfg.tam_lote.max(1)) {
        let lote: Vec<String> = lote.to_vec();
        let efectivos = aislar(&lote, |grupo| {
            let cliente = &cliente;
            let centinela = &centinela;
            let base = &base;
            let cfg = &cfg;
            async move {
                match sondar(cliente, url, identidad, cfg, &grupo, centinela).await {
                    Some(f) => anomalia(base, &f, cfg.sensible_longitud).is_some(),
                    None => false,
                }
            }
        })
        .await;
        // Para cada efectivo aislado, una sonda individual da su SEÑAL concreta.
        for nombre in efectivos {
            if let Some(f) =
                sondar(cliente, url, identidad, cfg, std::slice::from_ref(&nombre), &centinela).await
            {
                if let Some(senal) = anomalia(&base, &f, cfg.sensible_longitud) {
                    hallados.push(Descubierto { nombre, senal });
                }
            }
        }
    }
    Ok(hallados)
}

/// Diccionario mínimo y curado de nombres de parámetro que más suelen estar OCULTOS y ser
/// superficie de authz/mass-assignment (id ajenos, banderas de depuración, controles de
/// admin). BREVE a propósito: cada nombre es superficie de sonda, no el diccionario de 26k
/// de Arjun. Se amplía con evidencia, no por inercia (D21).
pub const DICCIONARIO_AUTHZ: &[&str] = &[
    "id", "user_id", "userId", "uid", "account_id", "accountId", "org_id", "orgId",
    "tenant_id", "tenantId", "customer_id", "team_id", "project_id", "owner_id",
    "debug", "test", "admin", "is_admin", "role", "impersonate", "as_user", "sudo",
    "internal", "preview", "draft", "include", "expand", "fields", "format", "callback",
    "redirect", "next", "url", "file", "path", "template", "view", "action", "cmd",
];

#[cfg(test)]
mod pruebas {
    use super::*;

    fn f(status: u16, cabeceras: &[&str], cuerpo: &str, centinela: &str) -> Factores {
        let cab: Vec<String> = cabeceras.iter().map(|s| s.to_string()).collect();
        factores(status, &cab, cuerpo, centinela)
    }

    #[test]
    fn recorte_seguro_no_panica_en_medio_de_un_multibyte() {
        // ROJO del fix (D33): "é" son 2 bytes. Cortar en byte 1 con `&s[..1]` PANICA; el
        // helper retrocede a la frontera 0. El bug real era `&cuerpo[..n]` por byte crudo.
        let s = "é"; // 2 bytes, 1 char
        assert_eq!(s.len(), 2);
        assert_eq!(recorte_seguro(s, 1), "", "cortar en medio del multibyte retrocede a frontera");
        assert_eq!(recorte_seguro(s, 2), "é", "cabe entero");
        assert_eq!(recorte_seguro(s, 99), "é", "max mayor que la cadena");
        // Con ASCII el corte es exacto.
        assert_eq!(recorte_seguro("hola", 3), "hol");
        // Emoji (4 bytes): cortar en 1/2/3 retrocede a "".
        let e = "😀x";
        assert_eq!(recorte_seguro(e, 3), "", "3 bytes dentro del emoji → frontera 0");
        assert_eq!(recorte_seguro(e, 4), "😀");
        assert_eq!(recorte_seguro(e, 5), "😀x");
    }

    #[test]
    fn factores_captura_reflejo_len_y_lineas() {
        let fa = f(200, &["Content-Type"], "hola\nnexusprbAA mundo", "nexusprbAA");
        assert!(fa.reflejo, "el centinela reflejado se detecta");
        assert_eq!(fa.lineas, 2);
        assert!(fa.cabeceras.contains("content-type"), "cabecera normalizada a minúsculas");
        // Sin el centinela en el cuerpo, no hay reflejo.
        let fb = f(200, &["Content-Type"], "hola mundo", "nexusprbAA");
        assert!(!fb.reflejo);
    }

    #[test]
    fn linea_base_marca_inestable_lo_que_fluctua() {
        // Mismo estado y cabeceras, DISTINTA longitud entre muestras → len inestable.
        let m1 = f(200, &["x"], "aaaa", "c");
        let m2 = f(200, &["x"], "aaaaaa", "c");
        let b = linea_base(&[m1, m2]);
        assert!(b.status_estable, "estado idéntico → estable");
        assert!(b.cabeceras_estable, "cabeceras idénticas → estable");
        assert!(!b.len_estable, "longitud que fluctúa → INESTABLE (no se compara)");
    }

    #[test]
    fn anomalia_detecta_reflexion_estado_y_cabeceras() {
        let base_f = f(200, &["x"], "aaaa", "cent");
        let base = linea_base(&[base_f.clone(), base_f]);
        // Reflexión (con o sin sensibilidad de longitud).
        let refleja = f(200, &["x"], "aaaa cent", "cent");
        assert_eq!(anomalia(&base, &refleja, false), Some(Senal::Reflexion));
        // Estado.
        let otro_estado = f(500, &["x"], "aaaa", "cent");
        assert_eq!(anomalia(&base, &otro_estado, false), Some(Senal::Estado));
        // Cabecera nueva.
        let otra_cab = f(200, &["x", "set-cookie"], "aaaa", "cent");
        assert_eq!(anomalia(&base, &otra_cab, false), Some(Senal::Cabeceras));
    }

    #[test]
    fn control_rojo_pagina_dinamica_no_dispara_por_longitud() {
        // El caso rojo del anti-FP (D23/D33): la longitud fluctúa sola, así que NO es
        // estable, así que un cambio de longitud NO debe contar como parámetro efectivo.
        // El mutante — "cualquier diferencia de longitud es anomalía" — moriría aquí.
        let m1 = f(200, &["x"], "aaaa", "cent");
        let m2 = f(200, &["x"], "aaaaaa", "cent"); // fluctúa sola
        let base = linea_base(&[m1, m2]);
        let obs = f(200, &["x"], "aaaaaaaa", "cent"); // otra longitud, sin reflejo
        // Ni con sensibilidad encendida: la longitud es INESTABLE, no se compara.
        assert_eq!(anomalia(&base, &obs, true), None, "longitud inestable no dispara");
        assert_eq!(anomalia(&base, &obs, false), None);
    }

    #[test]
    fn longitud_estable_si_dispara_pero_solo_con_sensibilidad() {
        // Si la longitud SÍ es estable en la base, un cambio real es señal — pero solo con
        // el factor encendido (OFF por defecto, D23).
        let m = f(200, &["x"], "aaaa", "cent");
        let base = linea_base(&[m.clone(), m]);
        let obs = f(200, &["x"], "aaaaaa", "cent");
        assert_eq!(anomalia(&base, &obs, true), Some(Senal::Longitud), "estable + sensible → dispara");
        assert_eq!(anomalia(&base, &obs, false), None, "OFF por defecto → no dispara");
    }

    // --- Bisección: rojo (encuentra los efectivos) + verde (no fabrica) ---

    /// Oráculo síncrono envuelto en `async` inmediato: la MISMA `aislar` del driver.
    async fn corre(cands: &[&str], efectivos_reales: &[&str]) -> Vec<String> {
        let reales: BTreeSet<String> = efectivos_reales.iter().map(|s| s.to_string()).collect();
        let cands: Vec<String> = cands.iter().map(|s| s.to_string()).collect();
        aislar(&cands, |grupo| {
            let reales = &reales;
            // Anómalo si el grupo contiene ≥1 efectivo (señal monótona, como la reflexión).
            async move { grupo.iter().any(|g| reales.contains(g)) }
        })
        .await
    }

    #[tokio::test]
    async fn biseccion_aisla_los_efectivos_entre_muchos() {
        // ROJO: 8 candidatos, 2 efectivos escondidos. Debe devolver EXACTAMENTE esos 2.
        let cands = ["a", "b", "id", "d", "e", "debug", "g", "h"];
        let out = corre(&cands, &["id", "debug"]).await;
        assert_eq!(out, vec!["debug".to_string(), "id".to_string()], "aísla los 2 efectivos");
    }

    #[tokio::test]
    async fn biseccion_no_fabrica_cuando_no_hay_efectivos() {
        // VERDE/control (D33): ningún efectivo → vacío. El mutante "devuelve las hojas
        // siempre" moriría aquí (devolvería los 8).
        let cands = ["a", "b", "c", "d", "e", "f", "g", "h"];
        let out = corre(&cands, &[]).await;
        assert!(out.is_empty(), "sin efectivos, no se fabrica ninguno");
    }

    #[tokio::test]
    async fn biseccion_no_aisla_efecto_solo_por_combinacion() {
        // Discriminación: un oráculo NO monótono (anómalo solo si están LOS DOS juntos)
        // no permite aislar → vacío, no un culpable inventado.
        let cands: Vec<String> = ["p", "q", "r", "s"].iter().map(|s| s.to_string()).collect();
        let out = aislar(&cands, |grupo| {
            let g: BTreeSet<String> = grupo.into_iter().collect();
            async move { g.contains("p") && g.contains("q") } // solo la combinación
        })
        .await;
        assert!(out.is_empty(), "un efecto solo-por-combinación no se aísla (no se inventa culpable)");
    }
}
