//! Motor de detección de CONTROL DE ACCESO roto (IDOR/BOLA/BAC), headless.
//!
//! nuclei no lo ve por diseño: es un emparejador de plantillas SIN estado ni
//! identidad. Esto compara la MISMA petición vista por varias IDENTIDADES y marca
//! la costura donde se concede acceso que debería negarse.
//!
//! El predicado sale de nuestra propia doc DEFENSIVA, invertida
//! (`conocimiento/seguridad_medico_informes.md`): un IDOR bien cerrado responde
//! **404 —nunca 403—** al recurso ajeno. Luego: si una identidad que NO es dueña
//! del recurso recibe 200 con el MISMO cuerpo que la dueña, obtuvo el recurso →
//! costura. La misma pregunta la hace la skill `revisar-seguridad`: «¿este
//! endpoint enseña a un Tercero algo que otro endpoint le niega?».
//!
//! ESTE ARCHIVO es el corazón: el predicado de clasificación, lógica PURA y
//! testeable sin red ni credenciales (directiva 28: se cruza la frontera con
//! pruebas en proceso). El driver HTTP que repite las peticiones con cada
//! identidad y construye los `Observado` a partir de respuestas reales, la
//! integración con recon y la config del juego de identidades por programa son
//! el incremento 2 (necesita cuentas de prueba, que monta Juan).

use crate::verify::VulnType;

/// Papel de una identidad frente a un recurso concreto del DUEÑO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Papel {
    /// La identidad dueña del recurso (autorizada). Es la referencia.
    Dueno,
    /// Un par: otra cuenta del mismo nivel. Que vea el recurso del dueño es
    /// privesc HORIZONTAL (IDOR/BOLA).
    Par,
    /// Menor privilegio (p. ej. usuario normal contra función de admin). Que
    /// alcance el recurso es privesc VERTICAL.
    MenorPrivilegio,
    /// Sin autenticar. Que obtenga el recurso protegido es fuga SIN AUTH.
    Anonimo,
}

/// Lo mínimo observado de una respuesta para poder diffear. Lo construye el
/// driver HTTP (incremento 2) o el test (incremento 1).
#[derive(Debug, Clone, Copy)]
pub struct Observado {
    pub papel: Papel,
    pub status: u16,
    pub cuerpo_len: usize,
    /// Hash del cuerpo (normalizado en el incremento 2). "Mismo recurso" de más
    /// confianza = misma firma.
    pub cuerpo_sig: u64,
    /// ¿El cuerpo es una página HTML? Un endpoint de API sirve DATOS (JSON), no
    /// una página; un 2xx `text/html` sobre una ruta de API es casi siempre el
    /// *shell* del SPA servido por el catch-all del frontend, no un bypass. Es la
    /// discriminación que faltaba y dejaba pasar el FP de `app.aikido.dev/api/…`
    /// (verificado 2026-08-21: `/`,`%2e`,`..;/`,X-Original-URL → 200 con el
    /// `index.html` público de 19 KB). Ver `es_bypass`.
    pub es_html: bool,
    /// ¿El cuerpo es un CHALLENGE de WAF/bot (Cloudflare "Just a moment…")? Un
    /// 403/401 así NO es un endpoint protegido —es un desafío anti-bot— y variar
    /// la petición para "saltarlo" no es un bypass de control de acceso (FP medido
    /// en producción 2026-08-21 sobre platform.cloudways.com). Ver `es_bypass`.
    pub es_challenge: bool,
}

/// La costura de acceso detectada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Costura {
    /// Un par obtiene el recurso del dueño (IDOR/BOLA).
    IdorHorizontal,
    /// Una identidad de menor privilegio alcanza el recurso.
    PrivEscVertical,
    /// Sin autenticar se obtiene el recurso protegido.
    FugaSinAuth,
}

impl Costura {
    /// La clase con la que se reporta (mapea al `VulnType` extendido).
    pub fn vuln_type(self) -> VulnType {
        match self {
            Costura::IdorHorizontal => VulnType::Idor,
            Costura::PrivEscVertical | Costura::FugaSinAuth => VulnType::Bac,
        }
    }

    /// Nombre estable del hallazgo (dedup por (url, vuln_name), así que no lleva
    /// la confianza: misma costura en la misma URL es el mismo hallazgo).
    pub fn nombre(self) -> &'static str {
        match self {
            Costura::IdorHorizontal => "control-de-acceso-idor-horizontal",
            Costura::FugaSinAuth => "control-de-acceso-fuga-sin-auth",
            Costura::PrivEscVertical => "control-de-acceso-privesc-vertical",
        }
    }

    /// CWE para el reporte a H1.
    pub fn cwe(self) -> &'static str {
        match self {
            Costura::IdorHorizontal => "CWE-639", // Authorization Bypass Through User-Controlled Key
            Costura::FugaSinAuth => "CWE-862",     // Missing Authorization
            Costura::PrivEscVertical => "CWE-285", // Improper Authorization
        }
    }
}

impl Veredicto {
    /// Severidad: la de la clase si la confianza es Alta; UN ESCALÓN MENOS si es
    /// Media (firma no exacta, solo longitud), para que el revisor manual vea la
    /// incertidumbre en el propio hallazgo en vez de tener que recordarla.
    pub fn severity(self) -> &'static str {
        match (self.costura, self.confianza) {
            (Costura::IdorHorizontal, Confianza::Alta) => "medium",
            (Costura::IdorHorizontal, Confianza::Media) => "low",
            // fuga sin auth / privesc vertical: más graves de base.
            (_, Confianza::Alta) => "high",
            (_, Confianza::Media) => "medium",
        }
    }
}

/// Cuánta confianza da la señal. La firma EXACTA es alta; la mera coincidencia de
/// LONGITUD es media —puede ser el mismo molde con PII distinta (IDOR real) o dos
/// recursos distintos del mismo tamaño (falso positivo)—, así que se marca, no se
/// esconde (directiva 20). El incremento 2 manda las `Media` al verificador.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confianza {
    Alta,
    Media,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Veredicto {
    pub costura: Costura,
    pub confianza: Confianza,
}

/// Una costura detectada CON su evidencia real. La evidencia no es una etiqueta:
/// lleva el status/longitud/firma que vieron el dueño, la identidad no autorizada
/// y el anónimo — el diferencial que PRUEBA el acceso indebido y lo hace
/// reproducible (directiva 30: sin esto un VERIFIED es indistinguible del ruido;
/// el FP medido el 2026-08-24 tenía la evidencia vacía).
#[derive(Debug, Clone)]
pub struct Hallazgo {
    pub veredicto: Veredicto,
    pub evidencia: String,
}

/// ¿Dos cuerpos 2xx son "el mismo recurso" por longitud? Exige que ambos tengan
/// tamaño no trivial (una página de error genérica de pocos bytes no cuenta) y
/// que la razón menor/mayor supere `umbral`.
fn longitudes_equivalentes(a: usize, b: usize, umbral: f64) -> bool {
    const MIN_LEN: usize = 64; // por debajo de esto es ruido (error page, redirect)
    if a < MIN_LEN || b < MIN_LEN {
        return false;
    }
    let (menor, mayor) = if a <= b { (a, b) } else { (b, a) };
    (menor as f64 / mayor as f64) >= umbral
}

/// El predicado. Dada la respuesta del DUEÑO (autorizado) y la de OTRA identidad
/// sobre la MISMA petición a un recurso del dueño, ¿hay costura de acceso?
///
/// `publico` es la observación de la MISMA petición hecha SIN credenciales (línea
/// base anónima). Discrimina el recurso público del privado: es lo único que
/// separa un IDOR real de servir una fuente/página abierta a cualquiera.
///
/// Reglas, en orden (cada una descarta un falso positivo real):
/// 0. Recurso PÚBLICO: si el anónimo obtiene el mismo recurso 2xx, no hay control
///    que saltar (fuentes, SVG, .well-known, homepage). Descarta cualquier costura.
/// 1. El dueño tuvo que ver 2xx: si el propio dueño no accedió, no hay recurso
///    que filtrar (endpoint roto → nada que marcar).
/// 2. El otro tuvo que ver 2xx: un 404/403/401 es el control FUNCIONANDO
///    (la señal de `medico`, invertida).
/// 3. Y el MISMO recurso: firma igual (Alta) o longitud equivalente (Media). Si
///    el otro ve 200 pero con OTRO cuerpo, está viendo LO SUYO, no lo del dueño
///    → no es fuga. Este es el guardia contra el mayor falso positivo (un par
///    pidiendo /api/me recibe su propio perfil, 200, cuerpo distinto).
/// 4. El dueño consigo mismo nunca es costura.
///
/// `umbral` ∈ [0,1]: fracción de longitud para "equivalente" cuando la firma no
/// coincide. 1.0 = exige longitud idéntica; 0.0 = cualquier par de 2xx (no usar).
pub fn clasificar(
    dueno: &Observado,
    otro: &Observado,
    publico: Option<&Observado>,
    umbral: f64,
) -> Option<Veredicto> {
    let es_2xx = |s: u16| (200..300).contains(&s);
    if !es_2xx(dueno.status) || !es_2xx(otro.status) {
        return None;
    }
    // Regla 0 — GUARDIA DE RECURSO PÚBLICO (el falso positivo medido el
    // 2026-08-24: 46 "IDOR" sobre fuentes .ttf/.woff, SVGs y .well-known). Si un
    // cliente ANÓNIMO (sin credenciales) obtiene EL MISMO recurso 2xx —firma de
    // cuerpo IDÉNTICA a la del dueño— entonces no hay control de acceso que saltar:
    // lo ve cualquiera. Se aplica a TODAS las costuras: un recurso público no es ni
    // IDOR, ni privesc, ni fuga (era público de entrada).
    //
    // SOLO por firma EXACTA, NUNCA por longitud (contra el falso negativo de la
    // revisión): la firma idéntica PRUEBA que el anónimo obtuvo el mismo recurso; la
    // longitud parecida solo prueba que obtuvo ALGO del mismo tamaño, y eso no basta
    // para descartar. Descartar por longitud suprimiría en silencio un IDOR REAL
    // (par con firma idéntica al dueño) si el anónimo devuelve una página de
    // login/error 2xx que por azar cae dentro del umbral — el descarte no puede ser
    // más débil que la confirmación (la longitud vale para CONFIRMAR como Media,
    // regla 3; jamás para suprimir). Y un 401/403/404 anónimo es el control
    // FUNCIONANDO: NO descarta nada, ahí sí hay algo que proteger.
    if let Some(pub_obs) = publico {
        if es_2xx(pub_obs.status) && pub_obs.cuerpo_sig == dueno.cuerpo_sig {
            return None;
        }
    }
    let costura = match otro.papel {
        Papel::Dueno => return None,
        Papel::Par => Costura::IdorHorizontal,
        Papel::MenorPrivilegio => Costura::PrivEscVertical,
        Papel::Anonimo => Costura::FugaSinAuth,
    };
    if otro.cuerpo_sig == dueno.cuerpo_sig {
        return Some(Veredicto { costura, confianza: Confianza::Alta });
    }
    if longitudes_equivalentes(dueno.cuerpo_len, otro.cuerpo_len, umbral) {
        return Some(Veredicto { costura, confianza: Confianza::Media });
    }
    None
}

/// Umbral por defecto de longitud-equivalente: conservador (98%).
pub const UMBRAL_DEFECTO: f64 = 0.98;

/// Umbral de "mismo molde" para el diferencial KEYLESS (más laxo que el de
/// identidad: dos registros del mismo tipo —dos facturas, dos perfiles— varían de
/// tamaño según su PII, así que exigir 98% cegaría el caso normal). 0.5 = el menor
/// mide al menos la mitad del mayor; por debajo son objetos demasiado dispares
/// para afirmar que es la MISMA colección enumerada.
pub const UMBRAL_KEYLESS: f64 = 0.5;

/// EL ORÁCULO KEYLESS — distinto de `clasificar`, porque SIN CUENTAS no hay
/// `dueno` de referencia. No puede preguntar "¿otra identidad ve lo del dueño?";
/// pregunta "¿un anónimo enumera objetos por-registro que deberían estar
/// protegidos?". La señal es el **diferencial de enumeración**: dos IDs vecinos,
/// pedidos SIN credenciales, que devuelven DOS registros DISTINTOS del mismo molde.
///
/// Por qué esto y no "un objeto privado suelto": sin dueño no hay forma de PROBAR
/// que un único 2xx anónimo sea privado y no público (esa prueba es justo lo que
/// aporta la cuenta). Dos registros distintos enumerables sí lo es: un recurso
/// genuinamente público no expone una serie por-usuario indexada por id. Es el
/// único discriminador keyless defendible (directiva 30/33), y por eso un objeto
/// suelto NO dispara.
///
/// Reglas (cada una mata un FP real, heredadas de `clasificar`/`fase_bypass`):
/// 0. Ambos 2xx. Un 404/403 en el vecino es el control FUNCIONANDO → no hay serie.
/// 1. DATOS, no `text/html`: un 2xx HTML es el shell del SPA del catch-all, no un
///    registro (el FP de `es_html`, ya medido).
/// 2. No CHALLENGE de WAF/bot.
/// 3. Longitud no trivial (una página de error de pocos bytes no es un registro).
/// 4. No es la página PÚBLICA del host (ruta fantasma): si `orig`/`vecino` casan por
///    firma con el shell del catch-all, es esa página, no datos.
/// 5. FIRMAS DISTINTAS entre orig y vecino: firma IGUAL = recurso estático servido
///    para cualquier id (fuente, imagen), NO un objeto por-registro → descarta.
/// 6. Mismo MOLDE (longitud equivalente, `UMBRAL_KEYLESS`): sube la confianza de
///    que son registros de la MISMA colección y no dos endpoints cualesquiera.
///
/// Devuelve SIEMPRE `Confianza::Media` cuando dispara: keyless nunca es `Alta`
/// —esa la reserva `clasificar` para el diferencial con dueño (verdad de terreno)—.
/// Todo hallazgo keyless va a MANUAL_READY, jamás auto-confirmado.
///
/// LIMITACIÓN CONOCIDA (residuo del FP, dir. 20/34): un API que devuelve 2xx con un
/// SOBRE DE ERROR que refleja el id (`{"error":"registro 1002 no existe"}`) puede
/// pasar las reglas si el molde casa —firmas distintas, mismo tamaño—. Va a
/// MANUAL_READY con la evidencia (tamaños/firmas de ambos cuerpos), donde un humano
/// lo descarta al instante. NO se añade comparación de cuerpos aquí: se construiría
/// cuando ese FP se REPITA en la cola (positivo de control), no por adelantado.
pub fn clasificar_fuga_keyless(
    orig: &Observado,
    vecino: &Observado,
    publico: Option<&Observado>,
) -> Option<Confianza> {
    let es_2xx = |s: u16| (200..300).contains(&s);
    if !es_2xx(orig.status) || !es_2xx(vecino.status) {
        return None; // regla 0
    }
    if orig.es_html || vecino.es_html || orig.es_challenge || vecino.es_challenge {
        return None; // reglas 1-2
    }
    const MIN_LEN: usize = 64;
    if orig.cuerpo_len < MIN_LEN || vecino.cuerpo_len < MIN_LEN {
        return None; // regla 3
    }
    if let Some(p) = publico {
        if es_2xx(p.status) && (p.cuerpo_sig == orig.cuerpo_sig || p.cuerpo_sig == vecino.cuerpo_sig) {
            return None; // regla 4
        }
    }
    if orig.cuerpo_sig == vecino.cuerpo_sig {
        return None; // regla 5 — estático/público, no per-registro
    }
    if longitudes_equivalentes(orig.cuerpo_len, vecino.cuerpo_len, UMBRAL_KEYLESS) {
        Some(Confianza::Media) // regla 6 — nunca Alta en keyless
    } else {
        None
    }
}

/// Muta el ÚLTIMO identificador NUMÉRICO de una URL (segmento de ruta o valor de
/// query) para producir URLs VECINAS enumerables. Es lo que convierte el corpus en
/// "endpoints objeto-scoped": si una URL no tiene id enumerable, no hay serie que
/// probar y se salta (esa ausencia ES la señal de que no aplica el IDOR keyless).
///
/// Devuelve hasta dos vecinos (N-1 si N>0, y N+1), preservando el resto de la URL.
/// No usa regex sobre la URL cruda (directiva 17): parsea con `Url` y opera sobre
/// segmentos/pares ya estructurados.
pub fn mutar_id(url: &str) -> Vec<String> {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return Vec::new();
    };
    // 1) ÚLTIMO segmento de ruta puramente numérico.
    if let Some(segs) = parsed.path_segments() {
        let segs: Vec<&str> = segs.collect();
        if let Some(idx) = segs
            .iter()
            .rposition(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
        {
            if let Ok(n) = segs[idx].parse::<u64>() {
                let mut out = Vec::new();
                for vecino in vecinos(n) {
                    let mut nuevos = segs.clone();
                    let s = vecino.to_string();
                    nuevos[idx] = &s;
                    let mut u = parsed.clone();
                    u.set_path(&nuevos.join("/"));
                    out.push(u.to_string());
                }
                return out;
            }
        }
    }
    // 2) Si no hay id en la ruta: ÚLTIMO par de query con valor numérico que NO sea
    //    de PAGINACIÓN. Mutar `?page=1`→`0/2` enumera páginas de una lista (a menudo
    //    pública), no registros por-objeto — el FP estructural que cazó la revisión
    //    (dir. 23): dos páginas 2xx de una lista pública pasan las 6 reglas. Se
    //    excluye en el ORIGEN. Un id real jamás se llama `page`/`offset`/`limit`.
    let pares: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    if let Some(idx) = pares
        .iter()
        .rposition(|(k, v)| {
            !v.is_empty() && v.chars().all(|c| c.is_ascii_digit()) && !es_clave_paginacion(k)
        })
    {
        if let Ok(n) = pares[idx].1.parse::<u64>() {
            let mut out = Vec::new();
            for vecino in vecinos(n) {
                let mut nuevos = pares.clone();
                nuevos[idx].1 = vecino.to_string();
                let mut u = parsed.clone();
                u.query_pairs_mut().clear().extend_pairs(nuevos.iter().map(|(k, v)| (k.as_str(), v.as_str())));
                out.push(u.to_string());
            }
            return out;
        }
    }
    Vec::new()
}

/// Claves de query que NAVEGAN una lista, no identifican un objeto. Solo las
/// inequívocas: excluir de más crearía un falso NEGATIVO sobre un IDOR real cuyo
/// parámetro se llamara así (dir. 21 — el sesgo a cerrar aquí es ciega la caza).
/// Un identificador de objeto no se llama `page`/`offset`/`limit`/`cursor`.
const CLAVES_PAGINACION: &[&str] = &[
    "page", "offset", "limit", "cursor", "start", "skip", "per_page", "page_size", "pagesize",
];

/// ¿La clave de un par de query es navegación de lista (paginación)? Case-insensitive.
fn es_clave_paginacion(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    CLAVES_PAGINACION.contains(&k.as_str())
}

/// Los vecinos de un id numérico: N-1 (si existe) y N+1. Acotado a dos peticiones
/// extra por endpoint (anti-baneo: la ráfaga por endpoint sigue siendo pequeña).
fn vecinos(n: u64) -> Vec<u64> {
    let mut v = Vec::new();
    if n > 0 {
        v.push(n - 1);
    }
    v.push(n + 1);
    v
}

impl Papel {
    /// Parsea el `papel` de la tabla `identidades`. Devuelve None ante un papel
    /// desconocido para que el llamante falle RUIDOSO (directiva 20): un typo en
    /// la config a mano no debe convertirse en un juego silenciosamente incompleto.
    pub fn desde_str(s: &str) -> Option<Papel> {
        match s {
            "dueno" => Some(Papel::Dueno),
            "par" => Some(Papel::Par),
            "menor" => Some(Papel::MenorPrivilegio),
            "anonimo" => Some(Papel::Anonimo),
            _ => None,
        }
    }

    /// El `papel` tal como se ALMACENA en la tabla `identidades`. Es el inverso
    /// exacto de `desde_str`: lo que este método emite, aquel lo vuelve a leer
    /// (el test `papel_ida_y_vuelta` lo ancla, directiva 33).
    pub fn a_str(self) -> &'static str {
        match self {
            Papel::Dueno => "dueno",
            Papel::Par => "par",
            Papel::MenorPrivilegio => "menor",
            Papel::Anonimo => "anonimo",
        }
    }
}

/// Una identidad cargada del almacén: su papel y las cabeceras HTTP que la
/// autentican (Cookie / Authorization). El anónimo va sin cabeceras. Lo llena
/// Juan a mano (config manual por programa, decidido el 2026-08-19).
#[derive(Debug, Clone)]
pub struct Identidad {
    pub papel: Papel,
    pub cabeceras: Vec<(String, String)>,
}

/// ¿El juego permite diffear? Hace falta el DUEÑO (la referencia autorizada) y al
/// menos una identidad más contra la que comparar (par/menor/anónimo). Sin eso el
/// motor se salta el programa: no hay nada que comparar, y un juego a medias que
/// "corre" sería peor que uno que no corre (directiva 20).
pub fn juego_listo(ids: &[Identidad]) -> bool {
    let tiene_dueno = ids.iter().any(|i| i.papel == Papel::Dueno);
    let tiene_otro = ids.iter().any(|i| i.papel != Papel::Dueno);
    tiene_dueno && tiene_otro
}

// ---- Incremento 2b: el driver HTTP que cruza la frontera (directiva 28) ----

/// Una petición a repetir con cada identidad. Solo GET por diseño: idempotente,
/// «sin daño» (mandato de Juan). El motor NUNCA manda POST/PUT/DELETE sobre un
/// recurso ajeno — probar una escritura destructiva SÍ causa daño.
#[derive(Debug, Clone)]
pub struct Solicitud {
    pub url: String,
}

/// Cliente HTTP del motor: NO sigue redirecciones (un 302 a /login ES la
/// respuesta de control de acceso; seguirlo la enmascara) y con timeout corto.
pub fn cliente(user_agent: &str) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(user_agent.to_string())
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(20))
        .build()
}

/// Como `cliente`, pero SIGUE redirects (hasta 5). Para cosechar CONTENIDO —no
/// para fingerprintear un host— donde el apex 302-redirige a la app real (SPAs
/// modernas: console.*, app.*). `cliente` (sin redirect) es para authz, donde un
/// 302 a /login ES la señal y seguirlo la borraría.
pub fn cliente_redirigible(user_agent: &str) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(user_agent.to_string())
        .redirect(reqwest::redirect::Policy::limited(5))
        .timeout(std::time::Duration::from_secs(20))
        .build()
}

/// Firma del cuerpo: hash estable de los bytes. CRUDA en este incremento; la
/// normalización que retira lo reflejado del solicitante (CSRF token, su propio
/// nombre) —para no perder un IDOR cuyo cuerpo lleva algo de quien pide— es
/// refinamiento posterior. Mientras tanto ese caso cae al camino de longitud
/// (Confianza::Media), no se pierde.
pub fn firma_cuerpo(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

/// ¿La respuesta es una página HTML? Mira primero la cabecera `Content-Type` y,
/// como respaldo (servidores que la mienten o la omiten), olfatea el inicio del
/// cuerpo buscando `<!doctype html`/`<html`. Se usa para descartar el *shell*
/// del SPA como falso bypass (ver `es_bypass`). El *sniff* mira solo el prefijo:
/// una respuesta JSON que MENCIONE `<html>` en un valor no cuenta como página.
pub fn cuerpo_es_html(content_type: Option<&str>, cuerpo: &[u8]) -> bool {
    if let Some(ct) = content_type {
        if ct.to_ascii_lowercase().contains("text/html") {
            return true;
        }
    }
    let prefijo = &cuerpo[..cuerpo.len().min(256)];
    let txt = String::from_utf8_lossy(prefijo);
    let txt = txt.trim_start().to_ascii_lowercase();
    txt.starts_with("<!doctype html") || txt.starts_with("<html")
}

/// ¿El cuerpo es un CHALLENGE de WAF/bot (Cloudflare "Just a moment…" y afines)?
/// Un 401/403 con este cuerpo NO es un endpoint protegido —es un desafío anti-bot
/// contra nuestra IP— y variar la petición para "saltarlo" no es un bypass de
/// control de acceso, sino que la variante pasó el desafío y ve la página real
/// (FP medido en producción 2026-08-21 sobre platform.cloudways.com: 403
/// "Just a moment…" → 200 página real, html→html, que `es_html` no distingue).
pub fn cuerpo_es_challenge(cuerpo: &[u8]) -> bool {
    let prefijo = &cuerpo[..cuerpo.len().min(4096)];
    let txt = String::from_utf8_lossy(prefijo).to_ascii_lowercase();
    const MARCAS: &[&str] = &[
        "just a moment",
        "attention required",
        "cf-browser-verification",
        "checking your browser",
        "/cdn-cgi/challenge-platform",
        "enable javascript and cookies to continue",
    ];
    MARCAS.iter().any(|m| txt.contains(m))
}

/// Firma del cuerpo NORMALIZADA: retira los VALORES de credencial de la propia
/// identidad (cookies/tokens de sus cabeceras) que la app pueda REFLEJAR en la
/// respuesta antes de firmar. Sin esto, un IDOR cuyo cuerpo lleva el token de
/// quien pide daría firmas distintas para el MISMO recurso servido a dos
/// identidades → caería a Media en vez de Alta, o se perdería.
///
/// Seguro (bajo FP, directiva 23): retirar una cadena específica de UNA identidad
/// no puede hacer colisionar dos recursos DISTINTOS, salvo que solo se
/// diferenciaran en esa credencial —que es exactamente el caso reflejado que se
/// quiere neutralizar—. Solo se tocan tokens de ≥8 chars (alta entropía); el
/// anónimo (sin cabeceras) se firma crudo.
pub fn firma_normalizada(cuerpo: &[u8], id: &Identidad) -> u64 {
    let mut texto = String::from_utf8_lossy(cuerpo).into_owned();
    for (_, valor) in &id.cabeceras {
        // El valor puede ser "session=ABC123..." o "Bearer XYZ..."; se parte por
        // los separadores típicos y se retira cada trozo "jugoso" (≥8 chars).
        for token in valor
            .split([';', '=', ' ', ',', '"'])
            .map(str::trim)
            .filter(|t| t.len() >= 8)
        {
            texto = texto.replace(token, "<ID>");
        }
    }
    firma_cuerpo(texto.as_bytes())
}

/// Observa una petición GET vista por UNA identidad (idempotente, sin seguir
/// redirecciones). Construye el `Observado` real: status, longitud, firma.
pub async fn observar(
    client: &reqwest::Client,
    sol: &Solicitud,
    id: &Identidad,
) -> reqwest::Result<Observado> {
    let mut req = client.get(&sol.url);
    for (k, v) in &id.cabeceras {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = resp.bytes().await?;
    Ok(Observado {
        papel: id.papel,
        status,
        cuerpo_len: bytes.len(),
        // Normalizada: neutraliza lo reflejado de la propia credencial para que el
        // mismo recurso servido a dos identidades case por firma (Alta), no por
        // longitud (Media).
        cuerpo_sig: firma_normalizada(&bytes, id),
        es_html: cuerpo_es_html(ct.as_deref(), &bytes),
        es_challenge: cuerpo_es_challenge(&bytes),
    })
}

/// Diffea una petición sobre un juego de identidades: observa al DUEÑO (la
/// referencia) y a cada otra identidad, y clasifica cada par. Devuelve las
/// costuras. El anti-baneo (pacing/backoff entre ENDPOINTS) lo aplica el llamante
/// con el `Guard`; aquí solo se hacen las 2-3 peticiones al MISMO endpoint (una
/// ráfaga pequeña y realista, como cargar una página).
/// Devuelve `(costuras, vio_senal_de_baneo)`. La segunda es para que el llamante
/// APLIQUE el backoff/cortacircuitos: un 429/503 en cualquiera de las peticiones
/// significa que el objetivo nos frena, y en un VPS compartido eso manda parar.
pub async fn diffear(
    client: &reqwest::Client,
    sol: &Solicitud,
    ids: &[Identidad],
    umbral: f64,
) -> reqwest::Result<(Vec<Hallazgo>, bool)> {
    let dueno_id = match ids.iter().find(|i| i.papel == Papel::Dueno) {
        Some(d) => d,
        None => return Ok((vec![], false)), // sin dueño no hay referencia
    };
    let dueno_obs = observar(client, sol, dueno_id).await?;
    let mut baneo = crate::protection::es_senal_de_baneo(dueno_obs.status);

    // LÍNEA BASE ANÓNIMA: la MISMA petición SIN credenciales. Es el discriminante
    // que separa el IDOR real del recurso público (el FP medido el 2026-08-24). Se
    // hace SIEMPRE, exista o no una identidad `Anonimo` en el juego. Si el anónimo
    // obtiene el recurso, `clasificar` descarta la costura (regla 0).
    let anon = Identidad { papel: Papel::Anonimo, cabeceras: vec![] };
    let publico_obs = observar(client, sol, &anon).await?;
    if crate::protection::es_senal_de_baneo(publico_obs.status) {
        baneo = true;
    }

    let etiqueta_match = |otro: &Observado| -> &'static str {
        if otro.cuerpo_sig == dueno_obs.cuerpo_sig {
            "firma idéntica"
        } else {
            "longitud equivalente"
        }
    };
    let estado_anon = if (200..300).contains(&publico_obs.status) {
        "2xx (¡accede!)"
    } else {
        "denegado → recurso NO público"
    };

    let mut out = Vec::new();
    for otro in ids.iter().filter(|i| i.papel != Papel::Dueno) {
        let obs = observar(client, sol, otro).await?;
        if crate::protection::es_senal_de_baneo(obs.status) {
            baneo = true;
        }
        if let Some(veredicto) = clasificar(&dueno_obs, &obs, Some(&publico_obs), umbral) {
            let evidencia = format!(
                "control-de-acceso {costura} en {url}\n  \
                 dueño (autorizado)   HTTP {ds}  {dl} B  sig={dsig:016x}\n  \
                 {papel} (no dueño)   HTTP {os}  {ol} B  sig={osig:016x}  [{match}]\n  \
                 anónimo (sin cred.)  HTTP {ps}  {pl} B  [{anon}]\n\
                 confianza {conf:?}. Reproducible: GET {url} con las cabeceras de cada identidad.",
                costura = veredicto.costura.nombre(),
                url = sol.url,
                ds = dueno_obs.status, dl = dueno_obs.cuerpo_len, dsig = dueno_obs.cuerpo_sig,
                papel = otro.papel.a_str(),
                os = obs.status, ol = obs.cuerpo_len, osig = obs.cuerpo_sig,
                match = etiqueta_match(&obs),
                ps = publico_obs.status, pl = publico_obs.cuerpo_len, anon = estado_anon,
                conf = veredicto.confianza,
            );
            out.push(Hallazgo { veredicto, evidencia });
        }
    }
    Ok((out, baneo))
}

// ---- Evasión de control de acceso (bypass de 403/401), SIN login ----
//
// A un endpoint PROTEGIDO (401/403 sin auth) se le prueban trucos conocidos de
// evasión; si alguno devuelve 2xx con contenido real (distinto de la página de
// error), se saltó el control. No necesita NINGUNA cuenta — es la vía para
// atacar sin login. Todas las técnicas son GET/POST idempotentes (sin daño).

/// Una técnica de evasión.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tecnica {
    /// Cabecera de valor fijo (engaña ACLs por IP o proxies de reescritura).
    Cabecera(&'static str, &'static str),
    /// Cabecera cuyo valor es la RUTA de la URL (X-Original-URL / X-Rewrite-URL).
    CabeceraRuta(&'static str),
    /// Sufijo a la ruta (trailing slash, `%2e`, `..;/`…): confunde al normalizador.
    Sufijo(&'static str),
    /// Cambia el verbo HTTP (un GET bloqueado puede permitir POST).
    Verbo(&'static str),
}

/// El repertorio de evasión. Conocidas y no destructivas.
pub const TECNICAS_EVASION: &[Tecnica] = &[
    // Cabeceras de IP de confianza (proxies/ACLs que confían en el cliente).
    Tecnica::Cabecera("X-Forwarded-For", "127.0.0.1"),
    Tecnica::Cabecera("X-Custom-IP-Authorization", "127.0.0.1"),
    Tecnica::Cabecera("X-Originating-IP", "127.0.0.1"),
    Tecnica::Cabecera("X-Remote-IP", "127.0.0.1"),
    Tecnica::Cabecera("X-Client-IP", "127.0.0.1"),
    Tecnica::Cabecera("X-Real-IP", "127.0.0.1"),
    Tecnica::Cabecera("X-Forwarded-Host", "localhost"),
    // Ampliación 2026-08-21: cabeceras de confianza que usan proxies reales
    // (Cloudflare, clusters, HAProxy). Moderado a propósito —cada técnica es una
    // petición más sobre la IP compartida (memoria muro-403); la fase corta al
    // primer bypass y para ante el muro, así que el coste real es acotado—.
    Tecnica::Cabecera("True-Client-IP", "127.0.0.1"),
    Tecnica::Cabecera("X-Cluster-Client-IP", "127.0.0.1"),
    Tecnica::Cabecera("CF-Connecting-IP", "127.0.0.1"),
    Tecnica::Cabecera("X-ProxyUser-Ip", "127.0.0.1"),
    Tecnica::Cabecera("X-Forwarded-Scheme", "http"),
    // Reescritura de ruta por cabecera (proxies que enrutan por X-*-URL).
    Tecnica::CabeceraRuta("X-Original-URL"),
    Tecnica::CabeceraRuta("X-Rewrite-URL"),
    Tecnica::CabeceraRuta("X-Override-URL"),
    // Sufijos que confunden al normalizador de ruta (todos GET idempotentes).
    Tecnica::Sufijo("/"),
    Tecnica::Sufijo("/."),
    Tecnica::Sufijo("%2e"),
    Tecnica::Sufijo("/..;/"),
    Tecnica::Sufijo("//"),
    Tecnica::Sufijo("/%2e/"),
    Tecnica::Sufijo("?"),
    // Cambio de verbo (un GET bloqueado puede permitir POST). Sin verbos
    // destructivos (PUT/DELETE): el mandato es «sin daño».
    Tecnica::Verbo("POST"),
];

/// Longitud mínima de un cuerpo 2xx para considerarlo "contenido real" y no una
/// página de error/redirect que casualmente dio 2xx.
const MIN_BYPASS: usize = 64;

/// Pausa base (s, con jitter) ENTRE técnicas de un mismo endpoint. Evita la
/// ráfaga de 14 peticiones de un tirón — clave para no degradar la IP compartida.
/// Es el DEFECTO de producción; `ConfigAutz.pausa_tecnica_secs` lo lleva (0 en
/// tests, para no dormir la suite).
pub const PAUSA_TECNICA_SECS: u64 = 1;

/// Cuántos 403 SEGUIDOS (en peticiones base, endpoints distintos) se toleran
/// antes de concluir que el objetivo nos **amuralla la IP** —un WAF que devuelve
/// 403 a TODO, no protección por-endpoint— y PARAR. Sin esto, un muro-403 hacía
/// a la fase MÁS agresiva (14 técnicas de evasión por cada endpoint amurallado)
/// justo cuando nos frenan: lo contrario de proteger la IP compartida del VPS.
/// Una respuesta variada (un 200, un 401, un 403 aislado) reinicia la cuenta.
const MURO_403_MAX: u32 = 5;

/// El PREDICADO de evasión (puro, testeable). Dado el baseline (petición plana
/// sin auth) y la respuesta de una técnica, ¿se saltó el control?
///
/// Reglas: el baseline tiene que estar PROTEGIDO (401/403) —si ya daba 2xx el
/// endpoint es público, no hay control que saltar—; la variante tiene que dar
/// 2xx con cuerpo SUSTANTIVO y DISTINTO del baseline (si devuelve la misma página
/// de error, no es un bypass); y —añadido 2026-08-21— la variante NO puede ser
/// una página HTML cuando el baseline no lo era. Un endpoint que responde JSON al
/// bloquear (401/403 de API) y de pronto devuelve `text/html` no ha "abierto sus
/// datos": está sirviendo el *shell* del SPA por el catch-all del frontend cuando
/// la ruta manipulada (sufijo, X-Rewrite-URL) deja de casar con `/api/…`. Eso NO
/// es privilegio ganado. La regla mira el CAMBIO de tipo (no-HTML→HTML) para no
/// crear el falso negativo simétrico: si el propio recurso protegido ES una
/// página HTML (baseline ya HTML), un bypass a otra página HTML sí cuenta.
pub fn es_bypass(baseline: &Observado, variante: &Observado) -> bool {
    matches!(baseline.status, 401 | 403)
        && !baseline.es_challenge
        && (200..300).contains(&variante.status)
        && variante.cuerpo_len >= MIN_BYPASS
        && variante.cuerpo_sig != baseline.cuerpo_sig
        && !(variante.es_html && !baseline.es_html)
}

/// ¿La respuesta de una técnica es SOLO la página pública del sitio? `publica` es
/// la referencia por-host: un GET a una ruta que no existe. Si esa ruta dio 2xx,
/// es el *shell* que el catch-all del front sirve a cualquiera; todo lo que la
/// iguale por firma es ese shell, no datos abiertos por el bypass. Generaliza el
/// filtro `es_html` a CUALQUIER tipo de contenido —un 200 público en JSON o una
/// página de marketing idéntica también se descartan—: es la verificación de
/// «trae DATOS, no una página» pedida el 2026-08-21. Si la ruta inexistente NO
/// dio 2xx (404 propio), no hay shell y no se descarta nada.
pub fn es_pagina_publica(variante: &Observado, publica: &Observado) -> bool {
    (200..300).contains(&publica.status) && variante.cuerpo_sig == publica.cuerpo_sig
}

/// DISCIPLINA DE ESTADO (veta x64dbg-mcp #2, ver `conocimiento/patrones/disciplina-de-estado.md`):
/// el `base` de `fase_bypass` se muestrea en t0, ANTES del bucle de técnicas. Si el endpoint se
/// ABRE para todos a mitad (un deploy que apaga el auth, un WAF que se cae, un backend que
/// reinicia permisivo), una técnica da 2xx no por la evasión sino porque el recurso quedó
/// abierto — y el baseline rancio (403) lo reportaría como "bypass" (falso positivo, un reporte
/// basura a H1). El baseline RE-OBSERVADO solo cuenta si sigue protegido (401/403).
pub fn baseline_sigue_protegido(base_reconfirmado: &Observado) -> bool {
    matches!(base_reconfirmado.status, 401 | 403)
}

/// El bypass CONFIRMADO, y el listón para reportar en `fase_bypass`: pasa el predicado de
/// evasión, NO es solo la página pública del host, Y el baseline re-observado sigue protegido
/// (disciplina de estado). Puro y testeable; el runner hace la re-observación (1 petición, solo
/// cuando ya hay un candidato — respeta el anti-baneo de la IP compartida del VPS).
pub fn bypass_confirmado(
    base: &Observado,
    variante: &Observado,
    publica: Option<&Observado>,
    base_reconfirmado: &Observado,
) -> bool {
    es_bypass(base, variante)
        && publica.is_none_or(|p| !es_pagina_publica(variante, p))
        && baseline_sigue_protegido(base_reconfirmado)
}

/// Rutas de FORCED BROWSING (fase 1.2): endpoints de alto valor que suelen estar
/// PROTEGIDOS (401/403). Se prueban aunque `ffuf` no corra (el ciclo pasivo de 2h
/// no lo lanza). `fase_bypass` solo evade las que dan 401/403 en el baseline; una
/// ruta 404/200 se ignora — así que el coste real es 1 fetch base por ruta + la
/// evasión SOLO sobre las protegidas de verdad.
pub const RUTAS_FORCED_BROWSING: &[&str] = &[
    "/admin", "/api/admin", "/administrator", "/actuator", "/management",
    "/internal", "/api/internal", "/console", "/debug", "/private",
    "/api/private", "/dashboard",
];

/// Genera semillas de forced browsing (`https://{host}{ruta}`) desde los hosts
/// del corpus, ACOTADO a `max` para proteger la IP compartida del VPS (memoria
/// muro-403). Dedup de hosts, orden estable. Puro y testable.
pub fn semillas_forced_browsing(corpus: &[String], max: usize) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for u in corpus {
        let h = crate::scope::host_of(u);
        if !h.is_empty() && !hosts.contains(&h) {
            hosts.push(h);
        }
    }
    let mut out = Vec::new();
    'outer: for h in &hosts {
        for r in RUTAS_FORCED_BROWSING {
            out.push(format!("https://{h}{r}"));
            if out.len() >= max {
                break 'outer;
            }
        }
    }
    out
}

// ---- Incremento 2c: la FASE que corre en la caza ----

/// Ajustes de la fase de control de acceso.
pub struct ConfigAutz {
    pub user_agent: String,
    pub umbral: f64,
    /// Tope de endpoints por corrida (presupuesto: el corpus de recon puede ser
    /// enorme, y cada endpoint son 2-3 peticiones).
    pub cap: usize,
    /// Pausa base entre endpoints, en segundos (0 en tests). El anti-baneo real:
    /// no se ráfaga el corpus entero de un tirón.
    pub cooldown_secs: u64,
    /// Pausa base entre TÉCNICAS de evasión de un mismo endpoint (0 en tests).
    /// Producción: `PAUSA_TECNICA_SECS`.
    pub pausa_tecnica_secs: u64,
}

/// ¿Venció el presupuesto de tiempo del ciclo? `None` = sin presupuesto (caza
/// profunda), nunca vence. Las fases de control de acceso (`fase_autz`,
/// `fase_bypass`) la consultan al tope de su bucle de endpoints para NO seguir
/// moliendo un target rate-limited después del deadline —el `nexus-hunt.service`
/// moría por el `TimeoutStartSec` de systemd (~60 min) justo ahí: el trabajo útil
/// terminaba a los ~45 min y la fase bypass seguía con backoffs de 120-240s hasta
/// que systemd la mataba (medido 2026-08-21 en intigriti:cloudways)—.
pub fn deadline_vencido(deadline: Option<std::time::Instant>) -> bool {
    deadline.is_some_and(|d| std::time::Instant::now() >= d)
}

/// La fase de control de acceso: sobre el `corpus` de URLs, con el juego de
/// `ids`, diffea cada endpoint, pacea con el `Guard` entre ellos (anti-baneo:
/// cooldown con jitter + backoff ante fallo), y persiste las costuras como
/// findings. Devuelve cuántas costuras NUEVAS. Se salta el programa si el juego
/// no está listo (sin dueño + otro no hay nada que comparar).
#[allow(clippy::too_many_arguments)]
pub async fn fase_autz(
    pool: &sqlx::SqlitePool,
    program: &str,
    corpus: &[String],
    ids: &[Identidad],
    guard: &mut crate::protection::Guard,
    cfg: &ConfigAutz,
    deadline: Option<std::time::Instant>,
    mut rng: impl FnMut() -> f64,
) -> crate::error::Result<u64> {
    if !juego_listo(ids) {
        return Ok(0);
    }
    let program_id = crate::db::upsert_program(pool, program).await?;
    let client = cliente(&cfg.user_agent)?;
    let mut nuevas = 0u64;
    for url in corpus.iter().take(cfg.cap) {
        if deadline_vencido(deadline) {
            tracing::info!("control de acceso: presupuesto del ciclo agotado — paro la fase ({nuevas} costuras nuevas hasta aquí)");
            break;
        }
        // Cortacircuitos: si el objetivo nos frena, PARAMOS (IP compartida).
        if guard.should_pause() {
            tracing::warn!("control de acceso: PAUSA por rate-limit acumulado; protejo la IP del VPS");
            break;
        }
        let sol = Solicitud { url: url.clone() };
        match diffear(&client, &sol, ids, cfg.umbral).await {
            // Vio 429/503: el objetivo nos frena → backoff REAL, no contar éxito.
            Ok((_, true)) => {
                let espera = guard.record_failure();
                tracing::warn!("control de acceso: rate-limit en {url} — backoff {espera}s");
                if guard.should_pause() {
                    break;
                }
                tokio::time::sleep(guard.cooldown(espera, rng())).await;
            }
            Ok((hallazgos, false)) => {
                guard.record_success();
                for h in hallazgos {
                    let v = h.veredicto;
                    if crate::db::insert_costura(
                        pool,
                        program_id,
                        program,
                        url,
                        v.costura.nombre(),
                        v.costura.vuln_type().as_str(),
                        v.severity(),
                        v.costura.cwe(),
                        // Solo la ALTA (firma exacta, mismo recurso, y anónimo
                        // DENEGADO: las reglas de `clasificar`) se auto-confirma; la
                        // MEDIA sigue al verificador.
                        matches!(v.confianza, Confianza::Alta),
                        // Evidencia REAL del diferencial (dueño/no-dueño/anónimo),
                        // no una etiqueta — es la puerta de evidencia (dir. 30).
                        Some(h.evidencia.as_str()),
                    )
                    .await?
                    {
                        nuevas += 1;
                    }
                }
                if cfg.cooldown_secs > 0 {
                    tokio::time::sleep(guard.cooldown(cfg.cooldown_secs, rng())).await;
                }
            }
            // Un fallo de red no revienta la fase: cuenta para el backoff y sigue.
            Err(_) => {
                guard.record_failure();
            }
        }
    }
    Ok(nuevas)
}

/// Ejecuta UNA técnica de evasión sobre `url` y devuelve el Observado (papel
/// Anonimo: la evasión es sin auth).
pub async fn observar_evasion(
    client: &reqwest::Client,
    url: &str,
    tecnica: Tecnica,
) -> reqwest::Result<Observado> {
    let mut req = match tecnica {
        Tecnica::Verbo(m) => {
            let metodo = reqwest::Method::from_bytes(m.as_bytes()).unwrap_or(reqwest::Method::GET);
            client.request(metodo, url)
        }
        Tecnica::Sufijo(s) => client.get(format!("{url}{s}")),
        _ => client.get(url),
    };
    req = match tecnica {
        Tecnica::Cabecera(k, v) => req.header(k, v),
        Tecnica::CabeceraRuta(k) => {
            let ruta = reqwest::Url::parse(url)
                .map(|u| u.path().to_string())
                .unwrap_or_else(|_| "/".to_string());
            req.header(k, ruta)
        }
        _ => req,
    };
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = resp.bytes().await?;
    Ok(Observado {
        papel: Papel::Anonimo,
        status,
        cuerpo_len: bytes.len(),
        cuerpo_sig: firma_cuerpo(&bytes),
        es_html: cuerpo_es_html(ct.as_deref(), &bytes),
        es_challenge: cuerpo_es_challenge(&bytes),
    })
}

/// La fase de EVASIÓN de control de acceso, SIN login. Para cada endpoint del
/// corpus que esté PROTEGIDO (401/403 en una petición plana), prueba el
/// repertorio de evasión; si una técnica lo salta, persiste un finding `bac`.
/// No necesita identidades — corre en cualquier programa. Los hallazgos van a
/// revisión manual (severidad media, FP-prone).
///
/// Anti-baneo: pacea entre ENDPOINTS con el Guard; dentro de un endpoint son
/// hasta 14 técnicas seguidas, pero SOLO sobre los protegidos (subconjunto), y
/// corta al primer bypass.
pub async fn fase_bypass(
    pool: &sqlx::SqlitePool,
    program: &str,
    corpus: &[String],
    guard: &mut crate::protection::Guard,
    cfg: &ConfigAutz,
    deadline: Option<std::time::Instant>,
    mut rng: impl FnMut() -> f64,
) -> crate::error::Result<u64> {
    let client = cliente(&cfg.user_agent)?;
    let anon = Identidad { papel: Papel::Anonimo, cabeceras: vec![] };
    let program_id = crate::db::upsert_program(pool, program).await?;
    let mut nuevas = 0u64;
    // Racha de 403 seguidos en peticiones base: la señal del muro-403 (WAF que
    // bloquea nuestra IP y devuelve 403 a todo). Se reinicia con cualquier
    // respuesta que NO sea 403.
    let mut muro_403: u32 = 0;
    // Referencia PÚBLICA por host (GET a una ruta inexistente): si da 2xx es el
    // shell del front, y todo "bypass" que lo iguale por firma es ese shell —no
    // datos—. Se calcula una vez por host y se cachea.
    let mut ref_publica: std::collections::HashMap<String, Option<Observado>> =
        std::collections::HashMap::new();
    for url in corpus.iter().take(cfg.cap) {
        // PRESUPUESTO DEL CICLO: tras el deadline no seguimos moliendo endpoints
        // —los backoffs de 120-240s ante rate-limit hacían que la fase se comiera
        // el `TimeoutStartSec` de systemd (~60 min) y el ciclo muriera con
        // `Result=timeout` (medido 2026-08-21). El trabajo útil ya terminó; paramos.
        if deadline_vencido(deadline) {
            tracing::info!("evasión: presupuesto del ciclo agotado — paro la fase bypass ({nuevas} bypass nuevos hasta aquí)");
            break;
        }
        // CORTACIRCUITOS: si el objetivo nos frena (acumuló señales), PARAMOS. En
        // un VPS COMPARTIDO un baneo cae sobre medico, xiliux, el OPRF… — parar
        // cuesta menos que degradar la IP de todos (directiva 18/21).
        if guard.should_pause() {
            tracing::warn!("evasión: PAUSA por rate-limit acumulado; protejo la IP compartida del VPS");
            break;
        }
        let base = match observar(&client, &Solicitud { url: url.clone() }, &anon).await {
            Ok(o) => o,
            Err(_) => {
                guard.record_failure();
                continue;
            }
        };
        // 429/503 = el objetivo dice "para": backoff REAL (esperar), no seguir.
        if crate::protection::es_senal_de_baneo(base.status) {
            let espera = guard.record_failure();
            tracing::warn!("evasión: {} en {url} (rate-limit) — backoff {espera}s", base.status);
            if guard.should_pause() {
                break;
            }
            tokio::time::sleep(guard.cooldown(espera, rng())).await;
            continue;
        }
        // MURO-403: un run de 403 en peticiones base NO es protección por-endpoint,
        // es un WAF que amuralló nuestra IP. Seguir lanzando evasión ahí nos vuelve
        // MÁS agresivos justo cuando nos frenan → degradaría la IP compartida del
        // VPS. Al alcanzar el tope, PARAMOS toda la fase (directiva 18/21).
        if base.status == 403 {
            muro_403 += 1;
            if muro_403 >= MURO_403_MAX {
                tracing::warn!(
                    "evasión: {MURO_403_MAX} 403 seguidos en {program} — parece muro/IP bloqueada; paro para proteger el VPS compartido"
                );
                break;
            }
        } else {
            muro_403 = 0;
        }
        // Solo tiene sentido evadir lo que está PROTEGIDO.
        if !matches!(base.status, 401 | 403) {
            guard.record_success();
            continue;
        }
        // Muro en desarrollo: el PRIMER 403 de un run (muro==1) suele ser
        // protección genuina y se evade; a partir del 2º seguido NO se evade —solo
        // se muestrea el baseline para confirmar el muro sin añadir ruido—.
        if base.status == 403 && muro_403 > 1 {
            continue;
        }
        // Referencia pública del host (una vez por host, cacheada): un GET a una
        // ruta que no existe. Si responde 2xx es el shell del catch-all; sirve
        // para exigir que un bypass traiga DATOS y no esa página.
        let host = crate::scope::host_of(url);
        if !ref_publica.contains_key(&host) {
            let ruta_fantasma = format!("https://{host}/nexus-ctrl-inexistente-a7f3c1");
            let r = observar(&client, &Solicitud { url: ruta_fantasma }, &anon)
                .await
                .ok();
            ref_publica.insert(host.clone(), r);
        }
        let publica = ref_publica.get(&host).and_then(|o| *o);
        let mut freno = false;
        for &tec in TECNICAS_EVASION {
            let v = match observar_evasion(&client, url, tec).await {
                Ok(v) => v,
                Err(_) => {
                    guard.record_failure();
                    if guard.should_pause() {
                        freno = true;
                        break;
                    }
                    continue;
                }
            };
            // Señal de baneo probando: CORTA la ráfaga de este endpoint YA.
            if crate::protection::es_senal_de_baneo(v.status) {
                let espera = guard.record_failure();
                tracing::warn!("evasión: {} probando {url} — corto la ráfaga, backoff {espera}s", v.status);
                tokio::time::sleep(guard.cooldown(espera, rng())).await;
                freno = true;
                break;
            }
            // Bypass real = pasa el predicado Y no es solo la página pública del
            // host (el shell del catch-all): trae DATOS, no una página.
            if es_bypass(&base, &v)
                && publica.as_ref().is_none_or(|p| !es_pagina_publica(&v, p))
            {
                // DISCIPLINA DE ESTADO: el `base` es de t0 (antes del bucle). Re-observar el
                // baseline plano UNA vez antes de reportar; si el endpoint se abrió para todos a
                // mitad, la variante 2xx no es un bypass sino el recurso abierto (falso positivo).
                let base2 = match observar(&client, &Solicitud { url: url.clone() }, &anon).await {
                    Ok(o) => o,
                    Err(_) => {
                        // Sin el control re-observado no se afirma (D20/D30): dejo este endpoint.
                        guard.record_failure();
                        break;
                    }
                };
                if !bypass_confirmado(&base, &v, publica.as_ref(), &base2) {
                    tracing::info!(
                        "evasión: {url} — baseline re-observado ABIERTO ({}) tras candidato {tec:?}: el endpoint quedó público a mitad, no es bypass; no reporto",
                        base2.status
                    );
                    guard.record_success();
                    break; // el endpoint está abierto: no sigo probando técnicas aquí
                }
                let ev = format!(
                    "evasión sin login en {url}: técnica {tec:?} — baseline {} ({}B, {}) → variante {} ({}B, {}), firma distinta",
                    base.status,
                    base.cuerpo_len,
                    if base.es_html { "html" } else { "no-html" },
                    v.status,
                    v.cuerpo_len,
                    if v.es_html { "html" } else { "no-html" },
                );
                if crate::db::insert_costura(
                    pool, program_id, program, url,
                    "control-de-acceso-evasion-403", "bac", "medium", "CWE-863",
                    // La evasión 403→200 es señal MÁS DÉBIL que el diferencial de
                    // `clasificar` (sin la comprobación de mismo-recurso) y propensa
                    // al ruido de un WAF (muro-403): NO se auto-confirma. Sigue a
                    // MANUAL_READY como antes, hasta que haya una confirmación más
                    // fuerte para esta vía.
                    false,
                    Some(ev.as_str()),
                )
                .await?
                {
                    nuevas += 1;
                }
                break; // un bypass por endpoint basta
            }
            // Pacing ENTRE técnicas: nunca una ráfaga de 14 de un tirón.
            tokio::time::sleep(guard.cooldown(cfg.pausa_tecnica_secs, rng())).await;
        }
        if !freno {
            guard.record_success();
        }
        if cfg.cooldown_secs > 0 {
            tokio::time::sleep(guard.cooldown(cfg.cooldown_secs, rng())).await;
        }
    }
    Ok(nuevas)
}

/// LA FASE KEYLESS — IDOR/BOLA sin auth, sin una sola cuenta. Para cada URL del
/// corpus con un id enumerable, pide el objeto SIN credenciales y sus vecinos
/// (id±1), y con `clasificar_fuga_keyless` decide si es una serie por-registro
/// filtrada. No necesita identidades: corre en CUALQUIER programa, y es la forma
/// operable de autz que respeta "sin crear cuentas" (decidido por Juan 2026-08-25).
///
/// Estatuto nexus-detector: GET de solo lectura, no destructivo; los hallazgos van
/// a MANUAL_READY (nunca auto-confirmado — keyless no da `Alta`), auto-envío OFF.
///
/// Anti-baneo idéntico a `fase_bypass`: pacea entre ENDPOINTS con el Guard,
/// cortacircuitos ante rate-limit (IP compartida del VPS), muro-403, y referencia
/// pública por host (ruta fantasma, cacheada) para exigir que el objeto no sea el
/// shell del catch-all.
pub async fn fase_fuga_sin_auth(
    pool: &sqlx::SqlitePool,
    program: &str,
    corpus: &[String],
    guard: &mut crate::protection::Guard,
    cfg: &ConfigAutz,
    deadline: Option<std::time::Instant>,
    mut rng: impl FnMut() -> f64,
) -> crate::error::Result<u64> {
    let client = cliente(&cfg.user_agent)?;
    let anon = Identidad { papel: Papel::Anonimo, cabeceras: vec![] };
    let program_id = crate::db::upsert_program(pool, program).await?;
    let mut nuevas = 0u64;
    let mut muro_403: u32 = 0;
    // Referencia pública por host (GET a ruta inexistente): el shell del catch-all.
    let mut ref_publica: std::collections::HashMap<String, Option<Observado>> =
        std::collections::HashMap::new();
    // Solo endpoints objeto-scoped: los que tienen id enumerable. El resto no
    // aplica al IDOR keyless y se salta (no gasta petición).
    for url in corpus.iter().filter(|u| !mutar_id(u).is_empty()).take(cfg.cap) {
        if deadline_vencido(deadline) {
            tracing::info!("fuga sin auth: presupuesto del ciclo agotado — paro la fase ({nuevas} fugas nuevas hasta aquí)");
            break;
        }
        if guard.should_pause() {
            tracing::warn!("fuga sin auth: PAUSA por rate-limit acumulado; protejo la IP compartida del VPS");
            break;
        }
        let orig = match observar(&client, &Solicitud { url: url.clone() }, &anon).await {
            Ok(o) => o,
            Err(_) => {
                guard.record_failure();
                continue;
            }
        };
        if crate::protection::es_senal_de_baneo(orig.status) {
            let espera = guard.record_failure();
            tracing::warn!("fuga sin auth: {} en {url} (rate-limit) — backoff {espera}s", orig.status);
            if guard.should_pause() {
                break;
            }
            tokio::time::sleep(guard.cooldown(espera, rng())).await;
            continue;
        }
        // MURO-403: WAF que amuralla la IP → parar para no degradar la IP compartida.
        if orig.status == 403 {
            muro_403 += 1;
            if muro_403 >= MURO_403_MAX {
                tracing::warn!("fuga sin auth: {MURO_403_MAX} 403 seguidos en {program} — parece muro/IP bloqueada; paro para proteger el VPS");
                break;
            }
        } else {
            muro_403 = 0;
        }
        // Solo tiene sentido enumerar lo que da datos 2xx.
        if !(200..300).contains(&orig.status) {
            guard.record_success();
            continue;
        }
        // Referencia pública del host (una vez, cacheada).
        let host = crate::scope::host_of(url);
        if !ref_publica.contains_key(&host) {
            let ruta_fantasma = format!("https://{host}/nexus-ctrl-inexistente-a7f3c1");
            let r = observar(&client, &Solicitud { url: ruta_fantasma }, &anon).await.ok();
            ref_publica.insert(host.clone(), r);
        }
        let publica = ref_publica.get(&host).and_then(|o| o.as_ref());
        let mut freno = false;
        for vecino_url in mutar_id(url) {
            let vecino = match observar(&client, &Solicitud { url: vecino_url.clone() }, &anon).await {
                Ok(v) => v,
                Err(_) => {
                    guard.record_failure();
                    if guard.should_pause() {
                        freno = true;
                        break;
                    }
                    continue;
                }
            };
            if crate::protection::es_senal_de_baneo(vecino.status) {
                let espera = guard.record_failure();
                tracing::warn!("fuga sin auth: {} probando {vecino_url} — corto, backoff {espera}s", vecino.status);
                tokio::time::sleep(guard.cooldown(espera, rng())).await;
                freno = true;
                break;
            }
            if let Some(conf) = clasificar_fuga_keyless(&orig, &vecino, publica) {
                let ev = format!(
                    "IDOR keyless (sin auth) en {url}: enumeración anónima id vecino {vecino_url} — orig 2xx ({}B, sig {:x}) vs vecino 2xx ({}B, sig {:x}), firmas distintas mismo molde. Dos registros por-objeto legibles sin credenciales.",
                    orig.cuerpo_len, orig.cuerpo_sig, vecino.cuerpo_len, vecino.cuerpo_sig,
                );
                if crate::db::insert_costura(
                    pool, program_id, program, url,
                    Costura::FugaSinAuth.nombre(), Costura::FugaSinAuth.vuln_type().as_str(),
                    // keyless SIEMPRE Media → severidad "medium"; nunca auto-confirmado
                    // (confirmado=false → MANUAL_READY). La confianza va en la evidencia.
                    Veredicto { costura: Costura::FugaSinAuth, confianza: conf }.severity(),
                    Costura::FugaSinAuth.cwe(),
                    false,
                    Some(ev.as_str()),
                )
                .await?
                {
                    nuevas += 1;
                }
                break; // una fuga por endpoint basta
            }
            tokio::time::sleep(guard.cooldown(cfg.pausa_tecnica_secs, rng())).await;
        }
        if !freno {
            guard.record_success();
        }
        if cfg.cooldown_secs > 0 {
            tokio::time::sleep(guard.cooldown(cfg.cooldown_secs, rng())).await;
        }
    }
    Ok(nuevas)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(papel: Papel, status: u16, len: usize, sig: u64) -> Observado {
        Observado { papel, status, cuerpo_len: len, cuerpo_sig: sig, es_html: false, es_challenge: false }
    }
    /// Igual que `obs` pero marca el cuerpo como página HTML (shell del SPA).
    fn obs_html(papel: Papel, status: u16, len: usize, sig: u64) -> Observado {
        Observado { papel, status, cuerpo_len: len, cuerpo_sig: sig, es_html: true, es_challenge: false }
    }
    /// Igual que `obs` pero marca el baseline como CHALLENGE de WAF/bot.
    fn obs_challenge(papel: Papel, status: u16, len: usize, sig: u64) -> Observado {
        Observado { papel, status, cuerpo_len: len, cuerpo_sig: sig, es_html: true, es_challenge: true }
    }

    /// `a_str` es el inverso EXACTO de `desde_str`: lo que se almacena se vuelve
    /// a leer sin pérdida. Un `match` al que le falte un brazo (o lo mande al
    /// string equivocado) rompe aquí — es lo que hace montar una identidad por
    /// CLI y cargarla en el motor el mismo dato (directiva 33). El caso rojo va
    /// implícito: `desde_str` de un papel inventado ya devuelve None (probado en
    /// `cargar_identidades`, que falla ruidoso).
    #[test]
    fn papel_ida_y_vuelta() {
        for p in [Papel::Dueno, Papel::Par, Papel::MenorPrivilegio, Papel::Anonimo] {
            assert_eq!(Papel::desde_str(p.a_str()), Some(p), "round-trip roto para {p:?}");
        }
        // Y los literales que documentamos al usuario son los que a_str emite.
        assert_eq!(Papel::Dueno.a_str(), "dueno");
        assert_eq!(Papel::MenorPrivilegio.a_str(), "menor");
    }

    // Ninguna de estas pruebas del PREDICADO pasa `publico` (None): aíslan las
    // reglas 1-4. El guardia de recurso público (regla 0) tiene su propia pareja
    // más abajo, y la simulación E2E lo ejerce por la costura real.

    // --- RED cases: TIENEN que disparar ---

    #[test]
    fn idor_horizontal_por_firma_exacta_es_alta() {
        let dueno = obs(Papel::Dueno, 200, 500, 0xABCD);
        let par = obs(Papel::Par, 200, 500, 0xABCD); // mismo cuerpo
        let v = clasificar(&dueno, &par, None, UMBRAL_DEFECTO).expect("debe marcar IDOR");
        assert_eq!(v.costura, Costura::IdorHorizontal);
        assert_eq!(v.confianza, Confianza::Alta);
        assert_eq!(v.costura.vuln_type().as_str(), "idor");
    }

    #[test]
    fn fuga_sin_auth_se_detecta() {
        // Predicado sin línea base: FugaSinAuth se detecta. En el camino real
        // `diffear` pasa la línea base anónima, que para un recurso público la
        // descarta (regla 0) — ver `recurso_publico_no_marca_ninguna_costura`.
        let dueno = obs(Papel::Dueno, 200, 800, 0x11);
        let anon = obs(Papel::Anonimo, 200, 800, 0x11);
        let v = clasificar(&dueno, &anon, None, UMBRAL_DEFECTO).unwrap();
        assert_eq!(v.costura, Costura::FugaSinAuth);
        assert_eq!(v.costura.vuln_type().as_str(), "bac");
    }

    #[test]
    fn privesc_vertical_se_detecta() {
        let dueno = obs(Papel::Dueno, 200, 800, 0x22);
        let low = obs(Papel::MenorPrivilegio, 200, 800, 0x22);
        assert_eq!(clasificar(&dueno, &low, None, UMBRAL_DEFECTO).unwrap().costura, Costura::PrivEscVertical);
    }

    #[test]
    fn longitud_equivalente_sin_firma_es_media() {
        // Mismo molde, PII distinta → firmas distintas pero longitud casi igual.
        let dueno = obs(Papel::Dueno, 200, 1000, 0xAAAA);
        let par = obs(Papel::Par, 200, 990, 0xBBBB); // 99% del tamaño
        let v = clasificar(&dueno, &par, None, UMBRAL_DEFECTO).expect("longitud equivalente marca");
        assert_eq!(v.confianza, Confianza::Media, "sin firma exacta, confianza media");
    }

    // --- Regla 0 (recurso PÚBLICO): la pareja del FP medido el 2026-08-24 ---

    #[test]
    fn recurso_publico_no_marca_ninguna_costura() {
        // EL falso positivo medido: 46 "IDOR" sobre fuentes/SVG/.well-known. El
        // par ve el MISMO cuerpo que el dueño (firma idéntica), PERO un anónimo
        // también lo obtiene (2xx, mismo cuerpo) → recurso público → NO es costura.
        let dueno = obs(Papel::Dueno, 200, 500, 0xABCD);
        let par = obs(Papel::Par, 200, 500, 0xABCD); // mismo cuerpo que el dueño
        let anon = obs(Papel::Anonimo, 200, 500, 0xABCD); // ¡el anónimo también!
        assert!(
            clasificar(&dueno, &par, Some(&anon), UMBRAL_DEFECTO).is_none(),
            "un recurso que el anónimo obtiene es PÚBLICO, no IDOR"
        );
    }

    #[test]
    fn idor_real_con_anonimo_denegado_si_marca() {
        // El caso ROJO que la regla 0 NO debe tumbar: par ve el recurso del dueño
        // (firma idéntica) y el anónimo está DENEGADO (401) → hay control y se
        // saltó → IDOR real, Alta. Si la regla 0 descartara aquí, se caería la
        // detección: por eso el anónimo 2xx-equivalente es la ÚNICA vía de descarte.
        let dueno = obs(Papel::Dueno, 200, 500, 0xABCD);
        let par = obs(Papel::Par, 200, 500, 0xABCD);
        let anon = obs(Papel::Anonimo, 401, 0, 0x0); // control activo
        let v = clasificar(&dueno, &par, Some(&anon), UMBRAL_DEFECTO)
            .expect("anónimo denegado → el IDOR real sí marca");
        assert_eq!(v.costura, Costura::IdorHorizontal);
        assert_eq!(v.confianza, Confianza::Alta);
    }

    #[test]
    fn anonimo_de_tamano_parecido_no_tumba_un_idor_real() {
        // Falso negativo cazado por la revisión (2026-08-24): un IDOR REAL (par con
        // firma idéntica al dueño) NO se descarta porque el anónimo 2xx caiga por
        // azar dentro del 98% de longitud con OTRO cuerpo (una página de login/error
        // genérica). El descarte de la regla 0 es SOLO por firma exacta; la longitud
        // parecida jamás suprime. El caso rojo del arreglo: con el descarte por
        // longitud viejo, esto se perdía en silencio.
        let dueno = obs(Papel::Dueno, 200, 1000, 0xAAAA);
        let par = obs(Papel::Par, 200, 1000, 0xAAAA); // IDOR real, firma idéntica al dueño
        let anon = obs(Papel::Anonimo, 200, 990, 0xDDDD); // ~99% de longitud, cuerpo DISTINTO
        let v = clasificar(&dueno, &par, Some(&anon), UMBRAL_DEFECTO)
            .expect("un anónimo de tamaño parecido pero cuerpo distinto NO suprime el IDOR real");
        assert_eq!(v.costura, Costura::IdorHorizontal);
        assert_eq!(v.confianza, Confianza::Alta);
    }

    // --- GREEN cases: NO deben disparar (cada uno mata un falso positivo) ---

    #[test]
    fn recurso_ajeno_cerrado_con_404_no_marca() {
        // LA señal de medico: el control correcto devuelve 404, no 403.
        let dueno = obs(Papel::Dueno, 200, 500, 0xABCD);
        let par = obs(Papel::Par, 404, 20, 0x0);
        assert!(clasificar(&dueno, &par, None, UMBRAL_DEFECTO).is_none());
    }

    #[test]
    fn recurso_ajeno_cerrado_con_403_no_marca() {
        let dueno = obs(Papel::Dueno, 200, 500, 0xABCD);
        let par = obs(Papel::Par, 403, 30, 0x0);
        assert!(clasificar(&dueno, &par, None, UMBRAL_DEFECTO).is_none());
    }

    #[test]
    fn par_ve_su_propio_dato_no_es_idor() {
        // EL falso positivo grande: /api/me → cada uno ve LO SUYO. 200 los dos,
        // pero cuerpos distintos y tamaños distintos → NO es fuga.
        let dueno = obs(Papel::Dueno, 200, 500, 0xABCD);
        let par = obs(Papel::Par, 200, 640, 0x1234); // su propio perfil, más grande
        assert!(clasificar(&dueno, &par, None, UMBRAL_DEFECTO).is_none());
    }

    #[test]
    fn dueno_sin_acceso_no_hay_fuga() {
        // Si el propio dueño no vio el recurso (endpoint roto), no hay nada que
        // filtrar aunque el otro dé 200.
        let dueno = obs(Papel::Dueno, 404, 20, 0x0);
        let par = obs(Papel::Par, 200, 500, 0xABCD);
        assert!(clasificar(&dueno, &par, None, UMBRAL_DEFECTO).is_none());
    }

    #[test]
    fn dueno_consigo_mismo_no_es_costura() {
        let dueno = obs(Papel::Dueno, 200, 500, 0xABCD);
        let dueno2 = obs(Papel::Dueno, 200, 500, 0xABCD);
        assert!(clasificar(&dueno, &dueno2, None, UMBRAL_DEFECTO).is_none());
    }

    #[test]
    fn cuerpo_corto_no_dispara_por_longitud() {
        // Dos páginas de error de 20 bytes con 200: por debajo de MIN_LEN no
        // cuentan como "mismo recurso" aunque la longitud coincida.
        let dueno = obs(Papel::Dueno, 200, 20, 0xAAAA);
        let par = obs(Papel::Par, 200, 20, 0xBBBB);
        assert!(clasificar(&dueno, &par, None, UMBRAL_DEFECTO).is_none());
    }

    #[test]
    fn longitudes_muy_distintas_no_marcan() {
        let dueno = obs(Papel::Dueno, 200, 1000, 0xAAAA);
        let par = obs(Papel::Par, 200, 300, 0xBBBB); // 30% → por debajo de 0.98
        assert!(clasificar(&dueno, &par, None, UMBRAL_DEFECTO).is_none());
    }

    #[test]
    fn papel_desde_str_conocidos_y_typo() {
        assert_eq!(Papel::desde_str("dueno"), Some(Papel::Dueno));
        assert_eq!(Papel::desde_str("par"), Some(Papel::Par));
        assert_eq!(Papel::desde_str("menor"), Some(Papel::MenorPrivilegio));
        assert_eq!(Papel::desde_str("anonimo"), Some(Papel::Anonimo));
        assert_eq!(Papel::desde_str("Dueno"), None, "case-sensitive: un typo es None, no un default");
        assert_eq!(Papel::desde_str("admin"), None);
    }

    fn ident(papel: Papel) -> Identidad {
        Identidad { papel, cabeceras: vec![] }
    }

    #[test]
    fn juego_listo_exige_dueno_y_otro() {
        assert!(!juego_listo(&[]), "vacío no");
        assert!(!juego_listo(&[ident(Papel::Dueno)]), "solo dueño no");
        assert!(!juego_listo(&[ident(Papel::Par)]), "solo par (sin dueño) no");
        assert!(juego_listo(&[ident(Papel::Dueno), ident(Papel::Par)]), "dueño+par sí");
        assert!(juego_listo(&[ident(Papel::Dueno), ident(Papel::Anonimo)]), "dueño+anónimo sí (fuga sin auth)");
    }

    #[test]
    fn severidad_refleja_la_confianza() {
        let v = |c, conf| Veredicto { costura: c, confianza: conf };
        assert_eq!(v(Costura::IdorHorizontal, Confianza::Alta).severity(), "medium");
        assert_eq!(v(Costura::IdorHorizontal, Confianza::Media).severity(), "low", "Media baja un escalón");
        assert_eq!(v(Costura::FugaSinAuth, Confianza::Alta).severity(), "high");
        assert_eq!(v(Costura::FugaSinAuth, Confianza::Media).severity(), "medium");
        assert_eq!(v(Costura::PrivEscVertical, Confianza::Alta).severity(), "high");
    }

    #[test]
    fn nombre_y_cwe_estables_por_clase() {
        assert_eq!(Costura::IdorHorizontal.cwe(), "CWE-639");
        assert_eq!(Costura::FugaSinAuth.cwe(), "CWE-862");
        assert_eq!(Costura::IdorHorizontal.nombre(), "control-de-acceso-idor-horizontal");
    }

    fn id_con(cookie: &str) -> Identidad {
        Identidad { papel: Papel::Dueno, cabeceras: vec![("Cookie".into(), cookie.into())] }
    }

    #[test]
    fn firma_normalizada_neutraliza_la_credencial_reflejada() {
        // El MISMO recurso servido a dos identidades, pero cada cuerpo refleja el
        // token de quien pide. Crudo darían firmas distintas; normalizado, iguales.
        let dueno = id_con("session=ALICE_TOKEN_1234");
        let par = id_con("session=BOB_TOKEN_5678");
        let cuerpo_dueno = b"SECRETO-DEL-PEDIDO-42 (tu token: ALICE_TOKEN_1234)";
        let cuerpo_par = b"SECRETO-DEL-PEDIDO-42 (tu token: BOB_TOKEN_5678)";

        assert_ne!(
            firma_cuerpo(cuerpo_dueno), firma_cuerpo(cuerpo_par),
            "crudo: distintos por el token reflejado"
        );
        assert_eq!(
            firma_normalizada(cuerpo_dueno, &dueno),
            firma_normalizada(cuerpo_par, &par),
            "normalizado: el mismo recurso casa pese a la credencial reflejada"
        );
    }

    #[test]
    fn firma_normalizada_no_colisiona_recursos_distintos() {
        // Dos recursos GENUINAMENTE distintos no deben colisionar por normalizar.
        let dueno = id_con("session=ALICE_TOKEN_1234");
        let par = id_con("session=BOB_TOKEN_5678");
        let pedido = b"SECRETO-DEL-PEDIDO-42 (tu token: ALICE_TOKEN_1234)";
        let factura = b"FACTURA-DISTINTA-99-otros-campos (tu token: BOB_TOKEN_5678)";
        assert_ne!(
            firma_normalizada(pedido, &dueno),
            firma_normalizada(factura, &par),
            "recursos distintos siguen con firmas distintas"
        );
    }

    #[test]
    fn firma_normalizada_del_anonimo_es_la_cruda() {
        let anon = Identidad { papel: Papel::Anonimo, cabeceras: vec![] };
        let cuerpo = b"contenido cualquiera sin credencial";
        assert_eq!(firma_normalizada(cuerpo, &anon), firma_cuerpo(cuerpo));
    }

    // --- Evasión de control de acceso (bypass 403/401) ---

    #[test]
    fn bypass_403_a_200_con_contenido_es_bypass() {
        let base = obs(Papel::Anonimo, 403, 30, 0xE1); // protegido
        let variante = obs(Papel::Anonimo, 200, 800, 0xAA); // contenido real, distinto
        assert!(es_bypass(&base, &variante));
    }

    #[test]
    fn bypass_401_tambien_cuenta() {
        let base = obs(Papel::Anonimo, 401, 20, 0xE2);
        let variante = obs(Papel::Anonimo, 200, 500, 0xBB);
        assert!(es_bypass(&base, &variante));
    }

    #[test]
    fn bypass_espurio_si_el_baseline_se_abrio_a_mitad() {
        // DISCIPLINA DE ESTADO (D33, veta x64dbg-mcp #2): el `base` se muestrea en t0, antes del
        // bucle de técnicas. Si el endpoint se ABRE para todos a mitad (deploy que apaga el auth,
        // WAF caído), una técnica da 2xx-con-datos y `es_bypass` —el predicado viejo, el mutante—
        // lo marca como bypass. Pero al RE-OBSERVAR, el baseline ya no está protegido: no hubo
        // control que saltar → NO es bypass. La discriminación está en el mismo test: es_bypass
        // dice sí, bypass_confirmado dice no.
        let base_t0 = obs(Papel::Anonimo, 403, 30, 0x111); // protegido en t0
        let variante = obs(Papel::Anonimo, 200, 900, 0x222); // 2xx, cuerpo sustantivo y distinto

        // El predicado VIEJO (solo es_bypass) reportaría: el mutante da un falso positivo.
        assert!(es_bypass(&base_t0, &variante), "es_bypass solo marca bypass (el mutante reportaría)");

        // Re-observado: el baseline AHORA da 200 (el endpoint quedó abierto para todos).
        let base_abierto = obs(Papel::Anonimo, 200, 900, 0x222);
        assert!(
            !bypass_confirmado(&base_t0, &variante, None, &base_abierto),
            "baseline re-observado ABIERTO → no hubo control que saltar → no es bypass"
        );

        // Control POSITIVO: si el baseline re-observado SIGUE protegido (403), el bypass es real.
        let base_sigue_protegido = obs(Papel::Anonimo, 403, 30, 0x111);
        assert!(
            bypass_confirmado(&base_t0, &variante, None, &base_sigue_protegido),
            "baseline aún protegido tras re-observar → el bypass es genuino"
        );
    }

    #[test]
    fn endpoint_publico_no_es_bypass() {
        // baseline ya daba 2xx → no hay control que saltar.
        let base = obs(Papel::Anonimo, 200, 500, 0xCC);
        let variante = obs(Papel::Anonimo, 200, 500, 0xCC);
        assert!(!es_bypass(&base, &variante));
    }

    #[test]
    fn variante_sigue_bloqueada_no_es_bypass() {
        let base = obs(Papel::Anonimo, 403, 30, 0xE1);
        let variante = obs(Papel::Anonimo, 403, 30, 0xE1);
        assert!(!es_bypass(&base, &variante));
    }

    #[test]
    fn misma_pagina_de_error_con_200_no_es_bypass() {
        // Algunos sitios devuelven 200 con "acceso denegado": mismo cuerpo que el
        // baseline → no es un bypass real.
        let base = obs(Papel::Anonimo, 403, 200, 0xDEAD);
        let variante = obs(Papel::Anonimo, 200, 200, 0xDEAD); // misma firma
        assert!(!es_bypass(&base, &variante));
    }

    #[test]
    fn cuerpo_corto_no_es_bypass() {
        let base = obs(Papel::Anonimo, 403, 30, 0xE1);
        let variante = obs(Papel::Anonimo, 200, 10, 0xAA); // por debajo de MIN_BYPASS
        assert!(!es_bypass(&base, &variante));
    }

    #[test]
    fn baseline_404_no_dispara_evasion() {
        let base = obs(Papel::Anonimo, 404, 20, 0xE1);
        let variante = obs(Papel::Anonimo, 200, 500, 0xAA);
        assert!(!es_bypass(&base, &variante), "solo 401/403 son candidatos");
    }

    // ---- FP del shell del SPA (verificado en app.aikido.dev, 2026-08-21) ----
    // Caso ROJO real: baseline 401 JSON de API, la técnica de ruta devuelve 200
    // con el index.html del SPA (19 KB, distinto, sustancial). La regla vieja
    // —sin `es_html`— lo marcaba bypass; ahora NO. Corre la pareja contra la
    // versión anterior de `es_bypass` y este test se pone rojo (mutante = quitar
    // la última cláusula).
    #[test]
    fn shell_html_del_spa_no_es_bypass() {
        let base = obs(Papel::Anonimo, 401, 66, 0x401A); // {"...":"No auth"} JSON
        let variante = obs_html(Papel::Anonimo, 200, 19329, 0x5A0F); // index.html
        assert!(
            !es_bypass(&base, &variante),
            "un 2xx text/html sobre baseline no-HTML es el shell del SPA, no un bypass"
        );
    }

    // Control POSITIVO preservado: baseline 401 JSON → variante 200 con DATOS
    // (JSON, no-HTML, firma distinta) SÍ es bypass. La corrección no ciega el
    // detector.
    #[test]
    fn bypass_a_datos_json_sigue_contando() {
        let base = obs(Papel::Anonimo, 401, 66, 0x401A);
        let variante = obs(Papel::Anonimo, 200, 300, 0xDA7A); // datos, no-HTML
        assert!(es_bypass(&base, &variante));
    }

    // Falso negativo SIMÉTRICO evitado (directiva 23): si el recurso protegido YA
    // es una página HTML (baseline HTML), un bypass a OTRA página HTML sí cuenta —
    // la regla solo descarta el cambio no-HTML→HTML.
    #[test]
    fn bypass_de_pagina_html_protegida_sigue_contando() {
        let base = obs_html(Papel::Anonimo, 403, 200, 0xE770); // página de error HTML
        let variante = obs_html(Papel::Anonimo, 200, 800, 0xAD31); // panel HTML abierto
        assert!(es_bypass(&base, &variante));
    }

    // FP medido 2026-08-21 (platform.cloudways.com): el baseline 403 es un
    // CHALLENGE de Cloudflare ("Just a moment…"), no un endpoint protegido, y la
    // variante que lo "salta" es la página real (html→html, que `es_html` no
    // distingue). Mutante = quitar `!baseline.es_challenge` → este test se pone
    // rojo (sin la cláusula, 403→200 con html→html y firma distinta pasaría).
    #[test]
    fn challenge_de_waf_como_baseline_no_es_bypass() {
        let base = obs_challenge(Papel::Anonimo, 403, 5413, 0xC0FF); // "Just a moment…"
        let variante = obs_html(Papel::Anonimo, 200, 88076, 0xFEED); // página real
        assert!(!es_bypass(&base, &variante));
    }

    // Pareja discriminante: un 403 GENUINO (no challenge) a otra página HTML sigue
    // contando — la cláusula solo mata el challenge, no el bypass html→html real.
    #[test]
    fn cuerpo_es_challenge_detecta_y_no_falsea() {
        assert!(cuerpo_es_challenge(b"<!DOCTYPE html><title>Just a moment...</title>"));
        assert!(cuerpo_es_challenge(b"<html>Attention Required! | Cloudflare</html>"));
        // Una página HTML benigna NO es un challenge.
        assert!(!cuerpo_es_challenge(b"<!DOCTYPE html><html><body>Panel de admin</body></html>"));
        assert!(!cuerpo_es_challenge(b"{\"error\":\"forbidden\"}"));
    }

    // Gate del presupuesto del ciclo (fix del timeout de systemd, 2026-08-21):
    // un deadline en el PASADO para la fase; futuro o None la dejan seguir. Mutante
    // = invertir el `>=` o quitar el `is_some_and` → esta pareja se pone roja.
    #[test]
    fn deadline_vencido_discrimina() {
        use std::time::{Duration, Instant};
        let ahora = Instant::now();
        // PASADO → vencido (la fase debe parar)
        assert!(deadline_vencido(ahora.checked_sub(Duration::from_secs(5))));
        // FUTURO → NO vencido (la fase sigue)
        assert!(!deadline_vencido(Some(ahora + Duration::from_secs(300))));
        // SIN presupuesto (caza profunda) → nunca vence
        assert!(!deadline_vencido(None));
    }

    #[test]
    fn cuerpo_es_html_por_content_type_y_por_sniff() {
        // por cabecera
        assert!(cuerpo_es_html(Some("text/html; charset=utf-8"), b"x"));
        // por sniff del prefijo (cabecera ausente o mentida)
        assert!(cuerpo_es_html(None, b"  <!DOCTYPE html>\n<html>"));
        assert!(cuerpo_es_html(Some("application/octet-stream"), b"<html><body>"));
        // JSON NO es HTML, aunque un valor mencione <html>
        assert!(!cuerpo_es_html(Some("application/json"), b"{\"x\":\"<html>\"}"));
        assert!(!cuerpo_es_html(None, b"{\"status_code\":401}"));
    }

    // "Trae datos, no una página": una variante idéntica a la ruta-fantasma
    // pública (mismo cuerpo, 2xx) es el shell → NO cuenta; una distinta SÍ.
    #[test]
    fn es_pagina_publica_descarta_el_shell_pero_no_los_datos() {
        let publica = obs_html(Papel::Anonimo, 200, 19329, 0x5A0F); // ruta inexistente → 2xx shell
        let shell = obs_html(Papel::Anonimo, 200, 19329, 0x5A0F); // el bypass devolvió lo mismo
        assert!(es_pagina_publica(&shell, &publica), "mismo cuerpo que la pública");
        let datos = obs(Papel::Anonimo, 200, 300, 0xDA7A); // datos reales, otra firma
        assert!(!es_pagina_publica(&datos, &publica), "otra firma = no es la pública");
        // Si la ruta-fantasma NO dio 2xx (404 propio), no hay shell que descartar.
        let sin_shell = obs(Papel::Anonimo, 404, 20, 0x404E);
        assert!(!es_pagina_publica(&shell, &sin_shell), "sin 2xx no hay página pública");
    }

    #[test]
    fn repertorio_ampliado_y_sin_verbos_destructivos() {
        assert!(TECNICAS_EVASION.len() >= 20, "el repertorio creció");
        // Ninguna técnica de verbo es destructiva (mandato «sin daño»).
        for t in TECNICAS_EVASION {
            if let Tecnica::Verbo(m) = t {
                assert!(matches!(*m, "POST" | "GET"), "verbo no destructivo: {m}");
            }
        }
        // Alguna de las nuevas cabeceras de confianza está presente.
        assert!(
            TECNICAS_EVASION.iter().any(|t| matches!(t, Tecnica::Cabecera("CF-Connecting-IP", _))),
            "incluye cabeceras de proxies reales"
        );
    }

    #[test]
    fn forced_browsing_por_host_y_acotado() {
        let corpus = vec![
            "https://a.com/x".to_string(),
            "https://a.com/y".to_string(), // mismo host → dedup
            "https://b.com/z".to_string(),
        ];
        let s = semillas_forced_browsing(&corpus, 100);
        // 2 hosts únicos × rutas.
        assert_eq!(s.len(), 2 * RUTAS_FORCED_BROWSING.len());
        assert!(s.iter().any(|u| u == "https://a.com/admin"));
        assert!(s.iter().any(|u| u == "https://b.com/actuator"));
        // El cap protege la IP: nunca más de `max`.
        assert_eq!(semillas_forced_browsing(&corpus, 5).len(), 5);
        assert!(semillas_forced_browsing(&[], 50).is_empty());
    }

    // ---- ORÁCULO KEYLESS (fuga sin auth, sin cuentas) ----
    // Pareja discriminante (directiva 33): el ROJO tiene que disparar por la vía
    // real (dos objetos distintos, mismo molde, sin auth), y CADA verde ataca una
    // regla concreta del predicado. El control se valida contra el propio artefacto:
    // el mutante es cegar una regla y ver que un verde se vuelve rojo.

    /// ROJO: dos registros DISTINTOS del mismo molde, ambos 2xx no-HTML → dispara Media.
    #[test]
    fn keyless_dos_objetos_distintos_mismo_molde_dispara_media() {
        let orig = obs(Papel::Anonimo, 200, 800, 0xAAAA);
        let vecino = obs(Papel::Anonimo, 200, 790, 0xBBBB); // distinto, ~mismo tamaño
        assert_eq!(clasificar_fuga_keyless(&orig, &vecino, None), Some(Confianza::Media));
        // NUNCA Alta en keyless: sin dueño no hay verdad de terreno.
        assert_ne!(clasificar_fuga_keyless(&orig, &vecino, None), Some(Confianza::Alta));
    }

    /// VERDE (regla 5): firmas IGUALES = recurso estático servido para cualquier id
    /// (fuente, imagen) → NO es per-registro, no dispara.
    #[test]
    fn keyless_firma_igual_es_estatico_no_dispara() {
        let orig = obs(Papel::Anonimo, 200, 800, 0xCAFE);
        let vecino = obs(Papel::Anonimo, 200, 800, 0xCAFE); // misma firma
        assert_eq!(clasificar_fuga_keyless(&orig, &vecino, None), None);
    }

    /// VERDE (regla 1): un 2xx `text/html` es el shell del SPA del catch-all, no un
    /// registro de datos → no dispara aunque las firmas difieran.
    #[test]
    fn keyless_html_shell_no_dispara() {
        let orig = obs_html(Papel::Anonimo, 200, 800, 0x1111);
        let vecino = obs_html(Papel::Anonimo, 200, 790, 0x2222);
        assert_eq!(clasificar_fuga_keyless(&orig, &vecino, None), None);
    }

    /// VERDE (regla 0): un 404 en el vecino es el control FUNCIONANDO (solo existe
    /// un objeto) → no hay serie enumerable, no dispara.
    #[test]
    fn keyless_vecino_404_control_funcionando_no_dispara() {
        let orig = obs(Papel::Anonimo, 200, 800, 0x1111);
        let vecino = obs(Papel::Anonimo, 404, 120, 0x2222);
        assert_eq!(clasificar_fuga_keyless(&orig, &vecino, None), None);
    }

    /// VERDE (regla 4): si orig casa por firma con la página PÚBLICA del host (ruta
    /// fantasma del catch-all), es esa página, no datos propios → no dispara.
    #[test]
    fn keyless_es_pagina_publica_del_host_no_dispara() {
        let orig = obs(Papel::Anonimo, 200, 800, 0xF00D);
        let vecino = obs(Papel::Anonimo, 200, 790, 0xBEEF);
        let publica = obs(Papel::Anonimo, 200, 800, 0xF00D); // el shell del catch-all == orig
        assert_eq!(clasificar_fuga_keyless(&orig, &vecino, Some(&publica)), None);
    }

    /// VERDE (regla 6): objetos de tamaños DISPARES (uno el doble del otro) no son
    /// la misma colección enumerada → conservador, no dispara.
    #[test]
    fn keyless_tamanos_dispares_no_dispara() {
        let orig = obs(Papel::Anonimo, 200, 200, 0x1111);
        let vecino = obs(Papel::Anonimo, 200, 900, 0x2222); // ratio 0.22 < UMBRAL_KEYLESS
        assert_eq!(clasificar_fuga_keyless(&orig, &vecino, None), None);
    }

    /// CONTROL DEL CONTROL (directiva 33): si se CEGARA la regla 5 (firma igual),
    /// el verde `keyless_firma_igual...` se volvería rojo. Se comprueba aquí que la
    /// regla es la que discrimina: mismo input, pero con firmas distintas, SÍ dispara.
    #[test]
    fn keyless_regla_firma_es_la_que_discrimina() {
        let orig = obs(Papel::Anonimo, 200, 800, 0xCAFE);
        let igual = obs(Papel::Anonimo, 200, 800, 0xCAFE);
        let distinto = obs(Papel::Anonimo, 200, 800, 0xCAFF); // solo cambia la firma
        assert_eq!(clasificar_fuga_keyless(&orig, &igual, None), None);
        assert_eq!(clasificar_fuga_keyless(&orig, &distinto, None), Some(Confianza::Media));
    }

    // ---- MUTADOR DE ID (convierte el corpus en objeto-scoped) ----

    #[test]
    fn mutar_id_segmento_de_ruta_numerico() {
        let vs = mutar_id("https://api.x.com/v1/order/1001");
        assert!(vs.iter().any(|u| u == "https://api.x.com/v1/order/1000"));
        assert!(vs.iter().any(|u| u == "https://api.x.com/v1/order/1002"));
    }

    #[test]
    fn mutar_id_valor_de_query_numerico() {
        let vs = mutar_id("https://x.com/invoice?id=42&fmt=pdf");
        assert!(vs.iter().any(|u| u.contains("id=41")));
        assert!(vs.iter().any(|u| u.contains("id=43")));
        // preserva el otro par
        assert!(vs.iter().all(|u| u.contains("fmt=pdf")));
    }

    #[test]
    fn mutar_id_sin_id_no_produce_vecinos() {
        // sin id enumerable → no aplica el IDOR keyless, corpus se salta.
        assert!(mutar_id("https://x.com/about").is_empty());
        assert!(mutar_id("https://x.com/search?q=hola").is_empty());
    }

    #[test]
    fn mutar_id_cero_solo_sube() {
        let vs = mutar_id("https://x.com/u/0");
        // N=0 no baja a -1; solo N+1.
        assert_eq!(vs.len(), 1);
        assert!(vs[0].ends_with("/u/1"));
    }

    /// El FP estructural de la revisión (dir. 23): un `?page=` es navegación de
    /// lista, NO un objeto → no se muta, así no enumera páginas de una lista pública.
    #[test]
    fn mutar_id_no_muta_paginacion() {
        assert!(mutar_id("https://x.com/items?page=2").is_empty());
        assert!(mutar_id("https://x.com/items?offset=40&limit=20").is_empty());
        assert!(mutar_id("https://x.com/items?PageSize=50").is_empty()); // case-insensitive
    }

    /// Pero un id de objeto JUNTO a paginación sí se muta (el id, no la página):
    /// el falso negativo simétrico no ocurre (dir. 23).
    #[test]
    fn mutar_id_muta_el_objeto_no_la_pagina() {
        let vs = mutar_id("https://x.com/orders?page=2&id=1001");
        assert!(vs.iter().any(|u| u.contains("id=1000")));
        assert!(vs.iter().any(|u| u.contains("id=1002")));
        // la página queda intacta en todas.
        assert!(vs.iter().all(|u| u.contains("page=2")));
    }
}
