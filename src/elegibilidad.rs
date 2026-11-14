//! Gate de elegibilidad: mide un hallazgo contra las reglas PUBLICADAS del
//! programa en H1 (scope submittable + clase/CWE aceptada) ANTES del veredicto
//! humano. H1 no da oráculo de validez pre-envío; estos son los proxies
//! deterministas que su API SÍ expone.
//!
//! **Fail-open por diseño (directiva 30):** ante datos ausentes —scope no
//! obtenido, CWE del hallazgo vacío, lista de clases no obtenida— el veredicto es
//! `Elegible`. Un fallo de red es indistinguible de un rechazo real, así que
//! NUNCA se descarta un hallazgo por falta de datos; solo por una regla del
//! programa leída con éxito que lo excluye.
//!
//! El resultado NO envía ni borra nada: es una MEDIDA. Descartar (a INFORMATIONAL)
//! es una decisión de cableado aparte, que se activa tras validar estas medidas
//! contra hallazgos reales.

use crate::db;
use crate::error::Result;
use crate::h1::{H1Client, ScopeElegible};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Veredicto {
    /// El host no cae en ningún scope marcado `eligible_for_submission` → H1 lo
    /// cerraría como fuera de alcance / N-A.
    FueraDeScope,
    /// El programa NO acepta este CWE (lista de weaknesses obtenida, CWE ausente).
    ClaseRechazada(String),
    /// Clase INFORMATIVA/won't-fix según el clasificador que ya usa el pipeline
    /// (`verify::is_informational_class`): cabeceras, versiones, SRI, debug en host
    /// no productivo… H1 la cierra informativa. Se resuelve sola, no espera a un
    /// humano. NO es «no pagable» (eso incluiría IDOR/BAC reales del motor autz);
    /// es solo lo que el propio sistema ya declara sin impacto.
    Informativa,
    /// Pasa los gates duros, o no hay datos suficientes para juzgar (fail-open).
    Elegible,
}

impl Veredicto {
    /// ¿Es un rechazo DURO y determinista? Solo estos podrían auto-descartarse;
    /// `Elegible` nunca. Lo usa el futuro cableado de enforce; el subcomando de
    /// medida los cuenta.
    pub fn descartable(&self) -> bool {
        !matches!(self, Veredicto::Elegible)
    }

    pub fn motivo(&self) -> String {
        match self {
            Veredicto::FueraDeScope => "fuera de scope submittable".into(),
            Veredicto::ClaseRechazada(c) => format!("clase {c} no aceptada por el programa"),
            Veredicto::Informativa => "clase informativa/won't-fix (H1 la cierra informativa)".into(),
            Veredicto::Elegible => "elegible (o sin datos para juzgar)".into(),
        }
    }
}

/// ¿Es una IPv4 con forma de dirección (4 octetos 0-255)? Puro. Se usa para NO
/// tratar una IP como dominio: el gate de scope hace match por dominio/wildcard,
/// y una IP hay que evaluarla contra CIDR/rangos —que aquí no se hace—, así que
/// una IP se deja sin juzgar (fail-open) en vez de marcarla fuera de scope.
pub fn es_ipv4(h: &str) -> bool {
    let oct: Vec<&str> = h.split('.').collect();
    oct.len() == 4
        && oct.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
        })
}

/// Extrae el host de una URL, un `host:port` o un host pelado. Puro. Devuelve
/// `None` si no hay un host con punto (no juzgable como dominio) o si es una IPv4
/// (que necesita evaluación por rango, no por dominio → no se juzga aquí).
pub fn host_de_url(url: &str) -> Option<String> {
    let s = url.trim();
    let s = s.split("://").nth(1).unwrap_or(s); // quita esquema si lo hay
    let s = s.split('/').next()?; // quita path
    let s = s.rsplit('@').next()?; // quita userinfo (user:pass@host)
    let host = s.split(':').next()?; // quita puerto
    let host = host.trim().trim_end_matches('.').to_lowercase();
    if host.is_empty() || !host.contains('.') || es_ipv4(&host) {
        None
    } else {
        Some(host)
    }
}

/// ¿El identificador de scope es evaluable como DOMINIO (dominio, URL o wildcard)?
/// Los activos de app-store, código o ejecutable no son hosts; los de IP/CIDR se
/// tratan aparte (abstención). Puro.
pub fn es_scope_de_dominio(ident: &str) -> bool {
    ident.trim().starts_with("*.") || host_de_url(ident).is_some()
}

/// ¿El host cae dentro de un identificador de scope? Soporta el wildcard `*.dom`
/// (cubre el apex y cualquier subdominio) y el match exacto. El identificador de
/// scope puede venir como URL (`https://api.dom/x`); se compara por host. Puro.
pub fn host_encaja(host: &str, ident: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_lowercase();
    let ident = ident.trim().to_lowercase();
    if let Some(base) = ident.strip_prefix("*.") {
        host == base || host.ends_with(&format!(".{base}"))
    } else {
        let ident_host = host_de_url(&ident).unwrap_or(ident);
        host == ident_host
    }
}

/// Decide la elegibilidad de un hallazgo. PURO — su pareja verde/rojo va en tests
/// (directiva 33). No toca red: recibe los datos ya obtenidos.
///
/// - `host`: host del hallazgo (`None` = no juzgable → no se aplica el gate de scope).
/// - `scopes`: scopes del programa (`&[]` = no obtenidos → no se juzga scope).
/// - `cwe`: CWE del hallazgo (`None` = sin dato → no se juzga clase).
/// - `clases_aceptadas`: CWEs que el programa acepta; `None` = no obtenidas → no
///   se juzga clase (fail-open, directiva 30).
pub fn decidir(
    host: Option<&str>,
    scopes: &[ScopeElegible],
    cwe: Option<&str>,
    clases_aceptadas: Option<&HashSet<String>>,
) -> Veredicto {
    // Gate de scope. Solo descarta cuando se puede juzgar CON CONFIANZA: host de
    // dominio (no IP), sin activos IP/CIDR que enturbien, y con scopes de dominio
    // submittable contra los que medir. Cualquier otra cosa → abstención
    // (fail-open, directiva 30): más vale no descartar que descartar en falso.
    if let Some(h) = host {
        let sub: Vec<&ScopeElegible> = scopes.iter().filter(|s| s.eligible_for_submission).collect();
        // Un dominio podría resolver DENTRO de un CIDR/IP submittable que aquí no
        // se evalúa por rango: si los hay, no se juzga el scope.
        let hay_ip_cidr = sub
            .iter()
            .any(|s| matches!(s.asset_type.to_ascii_uppercase().as_str(), "CIDR" | "IP_ADDRESS"));
        // Solo los scopes de dominio deciden el match; los de app/código/ejecutable
        // no son hosts (un hallazgo web nunca cae en ellos).
        let dominios: Vec<&&ScopeElegible> = sub
            .iter()
            .filter(|s| es_scope_de_dominio(&s.asset_identifier))
            .collect();
        if !hay_ip_cidr
            && !dominios.is_empty()
            && !dominios.iter().any(|s| host_encaja(h, &s.asset_identifier))
        {
            return Veredicto::FueraDeScope;
        }
    }

    // Gate de clase: solo si hay CWE Y lista de clases obtenida. CWE ausente de la
    // lista LEÍDA CON ÉXITO → rechazada. Lista `None` o CWE `None` → no se juzga.
    // Además, solo se juzga un CWE con FORMA reconocible (`cwe-`/`capec-`, como los
    // external_id de H1); un formato raro (un número pelado) se abstiene en vez de
    // descartar en falso — misma regla de «solo descartar con confianza».
    if let (Some(c), Some(acc)) = (cwe, clases_aceptadas) {
        let norm = c.trim().to_lowercase().replace('_', "-");
        let forma_ok = norm.starts_with("cwe-") || norm.starts_with("capec-");
        if forma_ok && !acc.contains(&norm) {
            return Veredicto::ClaseRechazada(norm);
        }
    }

    Veredicto::Elegible
}

// ---- Orquestación: evalúa la cola MANUAL_READY contra H1 (compartida por la
//      MEDIDA `nexus elegibilidad` y el ENFORCE del ciclo) ----

/// Resultado de evaluar un hallazgo MANUAL_READY.
pub struct Resultado {
    pub id: i64,
    pub program: String,
    pub vuln: String,
    pub severity: String,
    pub cwe: Option<String>,
    pub veredicto: Veredicto,
    /// De otra plataforma (handle con ':', p.ej. intigriti:*): no se juzga.
    pub otra_plataforma: bool,
    /// Nº de clases aceptadas que se leyeron; `None` = no se pudo leer la lista
    /// (gate de clase inactivo por fail-open). Hace visible «juzgado» vs «no».
    pub clases_leidas: Option<usize>,
    /// Nº de scopes submittable del programa (contexto del gate de scope).
    pub scopes_submittable: usize,
}

/// Evalúa TODOS los hallazgos MANUAL_READY contra las reglas de su programa en H1.
/// Hace las llamadas (cacheadas por handle). **No cambia nada en la BD** — es la
/// pieza compartida; descartar es decisión de `enforce`, imprimir de la medida.
pub async fn evaluar_manual(pool: &sqlx::SqlitePool, client: &H1Client) -> Result<Vec<Resultado>> {
    let manual = db::fetch_manual_ready(pool).await?;
    let mut scopes_cache: HashMap<String, Vec<ScopeElegible>> = HashMap::new();
    let mut clases_cache: HashMap<String, Option<HashSet<String>>> = HashMap::new();
    let mut out = Vec::with_capacity(manual.len());
    for f in manual {
        // (0) Clase INFORMATIVA/won't-fix, según el clasificador que ya usa el
        // pipeline. Es local (sin H1) y vale para CUALQUIER plataforma: se resuelve
        // sola, no espera a un humano. Va primero: ahorra la llamada a H1 y no
        // depende del scope. NO toca lo que el clasificador no marca (IDOR/BAC del
        // motor autz, CVEs, etc. siguen su camino).
        if crate::verify::is_informational_class(&f.vuln_name, &f.url) {
            out.push(Resultado {
                id: f.id,
                program: f.program_name,
                vuln: f.vuln_name,
                severity: f.severity,
                cwe: f.cwe,
                veredicto: Veredicto::Informativa,
                otra_plataforma: false,
                clases_leidas: None,
                scopes_submittable: 0,
            });
            continue;
        }
        // El gate es de H1. Un handle con ':' (intigriti:*) es de otra plataforma:
        // no se juzga (directiva 30), pero se devuelve para que la medida lo diga.
        if f.program_name.is_empty() || f.program_name.contains(':') {
            out.push(Resultado {
                id: f.id,
                program: f.program_name,
                vuln: f.vuln_name,
                severity: f.severity,
                cwe: f.cwe,
                veredicto: Veredicto::Elegible,
                otra_plataforma: true,
                clases_leidas: None,
                scopes_submittable: 0,
            });
            continue;
        }
        let handle = f.program_name.clone();
        if !scopes_cache.contains_key(&handle) {
            let sc = client.get_structured_scopes(&handle).await.unwrap_or_default();
            let cl = client.get_weakness_ids(&handle).await;
            scopes_cache.insert(handle.clone(), sc);
            clases_cache.insert(handle.clone(), cl);
        }
        let scopes = &scopes_cache[&handle];
        let clases = clases_cache[&handle].as_ref();
        let host = host_de_url(&f.url);
        let veredicto = decidir(host.as_deref(), scopes, f.cwe.as_deref(), clases);
        out.push(Resultado {
            id: f.id,
            program: f.program_name,
            vuln: f.vuln_name,
            severity: f.severity,
            cwe: f.cwe,
            veredicto,
            otra_plataforma: false,
            clases_leidas: clases.map(|s| s.len()),
            scopes_submittable: scopes.iter().filter(|s| s.eligible_for_submission).count(),
        });
    }
    Ok(out)
}

/// ENFORCE: descarta a INFORMATIONAL los hallazgos con veredicto DURO (fuera de
/// scope / clase rechazada). Reversible (no borra: reclasifica) y visible (guarda
/// el motivo, directiva 20). Devuelve cuántos descartó. Solo se invoca si el flag
/// `h1_gate_enforce` está activo — opt-in explícito, como el auto-envío.
pub async fn enforce(pool: &sqlx::SqlitePool, client: &H1Client) -> Result<u64> {
    let resultados = evaluar_manual(pool, client).await?;
    let mut n = 0u64;
    for r in &resultados {
        if r.veredicto.descartable() {
            db::descartar_por_elegibilidad(pool, r.id, &r.veredicto.motivo()).await?;
            tracing::info!(
                "resolución autónoma: hallazgo {} ({} / {}) → INFORMATIONAL: {}",
                r.id,
                r.program,
                r.vuln,
                r.veredicto.motivo()
            );
            n += 1;
        }
    }
    Ok(n)
}

/// RELOJ TERMINAL: cierra a INFORMATIONAL los hallazgos que llevan en MANUAL_READY
/// más de `max_dias` sin resolverse. Es la red universal: en 24/7 nadie revisa, y
/// un estado que espera a un humano para siempre es una fuga. Reversible (no borra)
/// y con motivo (directiva 20). `max_dias == 0` = apagado (no toca nada). Devuelve
/// cuántos cerró.
pub async fn reloj_terminal(pool: &sqlx::SqlitePool, max_dias: u64) -> Result<u64> {
    if max_dias == 0 {
        return Ok(0);
    }
    let vencidos = db::fetch_manual_ready_vencidos(pool, max_dias).await?;
    let motivo = format!("sin resolver en {max_dias} días (reloj terminal: nadie lo revisará)");
    let mut n = 0u64;
    for (id, vuln) in &vencidos {
        db::descartar_por_elegibilidad(pool, *id, &motivo).await?;
        tracing::info!("reloj terminal: hallazgo {id} ({vuln}) → INFORMATIONAL tras {max_dias} días");
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope_tipo(ident: &str, tipo: &str, submittable: bool) -> ScopeElegible {
        ScopeElegible {
            asset_type: tipo.into(),
            asset_identifier: ident.into(),
            eligible_for_submission: submittable,
            eligible_for_bounty: submittable,
            max_severity: Some("critical".into()),
        }
    }
    fn scope(ident: &str, submittable: bool) -> ScopeElegible {
        scope_tipo(ident, "URL", submittable)
    }

    fn clases(cwes: &[&str]) -> HashSet<String> {
        cwes.iter().map(|c| c.to_lowercase()).collect()
    }

    #[test]
    fn host_de_url_extrae_y_descarta_lo_no_juzgable() {
        assert_eq!(host_de_url("https://www.truecaller.com/x?a=1").as_deref(), Some("www.truecaller.com"));
        assert_eq!(host_de_url("api.example.com:8443/v1").as_deref(), Some("api.example.com"));
        assert_eq!(host_de_url("http://u:p@host.dom/").as_deref(), Some("host.dom"));
        assert_eq!(host_de_url("localhost"), None, "sin punto no es dominio juzgable");
        assert_eq!(host_de_url(""), None);
    }

    #[test]
    fn host_encaja_wildcard_y_exacto_con_su_rojo() {
        // Wildcard: apex y subdominios sí; ajenos y falsos-sufijos no.
        assert!(host_encaja("a.example.com", "*.example.com"));
        assert!(host_encaja("example.com", "*.example.com"));
        assert!(!host_encaja("example.org", "*.example.com"));
        assert!(!host_encaja("notexample.com", "*.example.com"), "sufijo falso NO encaja");
        // Exacto (y scope dado como URL): compara por host.
        assert!(host_encaja("api.dom.com", "https://api.dom.com/graphql"));
        assert!(!host_encaja("otro.dom.com", "https://api.dom.com/graphql"));
    }

    #[test]
    fn descarta_fuera_de_scope_pero_no_lo_de_dentro() {
        let sc = [scope("*.good.com", true)];
        // ROJO: host ajeno a todo scope submittable → fuera.
        assert_eq!(decidir(Some("evil.com"), &sc, None, None), Veredicto::FueraDeScope);
        // VERDE: host dentro del wildcard → no se descarta por scope.
        assert_eq!(decidir(Some("a.good.com"), &sc, None, None), Veredicto::Elegible);
    }

    #[test]
    fn descarta_clase_rechazada_pero_no_la_aceptada() {
        let acc = clases(&["cwe-863", "cwe-200"]);
        // ROJO: XSS (cwe-79) no está en la lista aceptada → rechazada.
        match decidir(None, &[], Some("CWE-79"), Some(&acc)) {
            Veredicto::ClaseRechazada(c) => assert_eq!(c, "cwe-79"),
            v => panic!("esperaba ClaseRechazada, fue {v:?}"),
        }
        // VERDE: authz (cwe-863) sí está → elegible.
        assert_eq!(decidir(None, &[], Some("cwe_863"), Some(&acc)), Veredicto::Elegible);
        // ABSTENCIÓN: un CWE sin forma reconocible (número pelado) NO se descarta
        // aunque no esté en la lista — evita el falso descarte por formato raro.
        assert_eq!(decidir(None, &[], Some("79"), Some(&acc)), Veredicto::Elegible);
    }

    #[test]
    fn informativa_es_descartable_con_su_motivo() {
        let v = Veredicto::Informativa;
        assert!(v.descartable(), "una clase informativa se resuelve sola (no espera humano)");
        assert!(v.motivo().contains("informativa"));
        // Y no la produce `decidir` (se asigna aguas arriba con el clasificador del
        // pipeline, no aquí): decidir solo emite scope/clase/elegible.
        assert_ne!(decidir(Some("evil.com"), &[scope("*.good.com", true)], None, None), Veredicto::Informativa);
    }

    #[test]
    fn es_ipv4_discrimina() {
        assert!(es_ipv4("54.175.255.192"));
        assert!(es_ipv4("0.0.0.0"));
        assert!(!es_ipv4("54.175.255.256"), "256 fuera de rango");
        assert!(!es_ipv4("54.175.255"), "3 octetos no es IPv4");
        assert!(!es_ipv4("api.example.com"));
        assert!(!es_ipv4("1.2.3.4.5"));
    }

    /// Cazado auditando datos reales (coinbase tiene un scope CIDR): el gate de
    /// scope debe ABSTENERSE cuando no puede juzgar por dominio con confianza —una
    /// IP, un programa con CIDR/IP, o uno sin scopes de dominio—, en vez de
    /// descartar en falso. Su pareja: con scope de dominio y host ajeno, SÍ
    /// descarta (la abstención no puede tragarse el caso legítimo).
    #[test]
    fn el_gate_de_scope_se_abstiene_cuando_no_puede_juzgar_con_confianza() {
        let dom = [scope("*.good.com", true)];
        // Host IP → host_de_url es None → no se juzga scope aunque haya dominios.
        assert_eq!(host_de_url("http://54.1.2.3/x"), None);
        assert_eq!(decidir(host_de_url("http://54.1.2.3/x").as_deref(), &dom, None, None), Veredicto::Elegible);
        // Programa con un CIDR submittable: un dominio ajeno NO se descarta (podría
        // resolver dentro del rango, que aquí no se evalúa).
        let con_cidr = [scope("*.good.com", true), scope_tipo("54.175.255.192/27", "CIDR", true)];
        assert_eq!(decidir(Some("evil.com"), &con_cidr, None, None), Veredicto::Elegible);
        // Programa cuyos scopes submittable NO son de dominio (app/código): no se
        // juzga un hallazgo web contra ellos.
        let solo_app = [scope_tipo("288429040", "APPLE_STORE_APP_ID", true)];
        assert_eq!(decidir(Some("evil.com"), &solo_app, None, None), Veredicto::Elegible);
        // ROJO/pareja: scope de dominio normal + host ajeno → SÍ descarta.
        assert_eq!(decidir(Some("evil.com"), &dom, None, None), Veredicto::FueraDeScope);
    }

    /// El corazón del fail-open (directiva 30): con datos ausentes NUNCA se
    /// descarta. Sin este caso, un gate que descartara ante cualquier `None`
    /// pasaría los rojos de arriba igual, y silenciaría hallazgos reales por un
    /// fallo de red.
    #[test]
    fn fail_open_no_descarta_por_falta_de_datos() {
        let acc = clases(&["cwe-863"]);
        // Sin scopes (no obtenidos): no se juzga scope aunque el host sea ajeno.
        assert_eq!(decidir(Some("cualquiera.com"), &[], None, None), Veredicto::Elegible);
        // Lista de clases None (fetch falló): no se juzga clase aunque el CWE no esté.
        assert_eq!(decidir(None, &[], Some("CWE-79"), None), Veredicto::Elegible);
        // CWE None (hallazgo sin clase): no se juzga clase aunque haya lista.
        assert_eq!(decidir(None, &[], None, Some(&acc)), Veredicto::Elegible);
        // Host None (URL no juzgable): no se juzga scope aunque haya scopes.
        let sc = [scope("*.good.com", true)];
        assert_eq!(decidir(None, &sc, None, None), Veredicto::Elegible);
        // Programa sin scope submittable declarado: dato ambiguo, no se descarta.
        let no_sub = [scope("*.good.com", false)];
        assert_eq!(decidir(Some("evil.com"), &no_sub, None, None), Veredicto::Elegible);
    }
}
