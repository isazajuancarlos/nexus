// SPDX-License-Identifier: LicenseRef-Propietario
//! BRUTEFORCE DNS — descubrimiento de subdominios PROPIO, sin cuenta ni servicio de
//! terceros (directiva 38: Rust; directiva 9: poseer el alfa). Una lista de palabras
//! con resolución DNS: nadie te lo puede limitar ni cerrar, y encuentra lo que las
//! fuentes pasivas (Certificate Transparency, feeds) NO ven: los nombres internos sin
//! certificado emitido (por ejemplo `internal`, `admin-old`, `staging2`).
//!
//! Medido el 2026-08-24: subfinder SIN cuentas da 76 subs/objetivo (crt.sh + fuentes
//! CT libres); las 5 claves free sumaban un +40% OPCIONAL. El bruteforce es la
//! augmentación SOBERANA: 43 palabras de prueba ya resolvieron 8 hosts reales en
//! uphold.com. Ver memoria `nexus-bespoke-hybris-waf-inalcanzable` (hilo de recon).
//!
//! DISCIPLINA (directiva 33): el resolvedor es INYECTABLE, así que la lógica se prueba
//! sin tocar la red, con su pareja roja/verde. Y clasifica el **wildcard DNS** en tres:
//! sin wildcard (toda resolución es real), wildcard FIJO (pool pequeño: un candidato
//! con IP fuera del pool es real), y wildcard ROTATORIO/CDN (pool grande: real y eco
//! comparten el CDN, el DNS no discrimina → la base se OMITE en vez de emitir FPs).

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;

/// El resultado de resolver un nombre: sus IPs (vacío = NXDOMAIN / no resuelve).
pub type Resuelto = Vec<IpAddr>;

/// ¿El candidato es un HIT REAL y no un eco del comodín? Puro y testeable.
/// - Sin IPs → no resuelve → NO.
/// - Sin comodín → cualquier resolución es real → SÍ.
/// - Con comodín → solo es real si tiene ALGUNA IP que el comodín no da (si todas sus
///   IPs están en el set del comodín, es el comodín respondiendo, no un host propio).
pub fn es_hit_real(ips: &[IpAddr], comodin: &BTreeSet<IpAddr>) -> bool {
    if ips.is_empty() {
        return false;
    }
    if comodin.is_empty() {
        return true;
    }
    ips.iter().any(|ip| !comodin.contains(ip))
}

/// Deriva el set de IPs del COMODÍN a partir de resolver nombres-basura que no deberían
/// existir. Si varios nombres aleatorios resuelven, es wildcard DNS y sus IPs son el
/// eco a filtrar. Puro: recibe las resoluciones ya hechas (testeable sin red).
/// Unión de todas las IPs vistas en los señuelos: cubre el wildcard con varias IPs.
pub fn derivar_comodin(resoluciones_senuelo: &[Resuelto]) -> BTreeSet<IpAddr> {
    let mut set = BTreeSet::new();
    for r in resoluciones_senuelo {
        for ip in r {
            set.insert(*ip);
        }
    }
    set
}

/// Un getaddrinfo puede colgarse 15–40 s con un resolvedor lento o un SERVFAIL. El
/// tope por consulta acota el peor caso (M2 de la revisión): con él, el bruteforce
/// tarda como mucho `ceil(palabras/concurrencia) * TIMEOUT`, no minutos por un nombre.
const TIMEOUT_CONSULTA: std::time::Duration = std::time::Duration::from_secs(4);

/// Resuelve un host por el resolvedor del SISTEMA (getaddrinfo vía tokio), con tope
/// por consulta. Keyless: usa el DNS configurado en el VPS, que controlamos. `Vec`
/// vacío si no resuelve O si se agota el tope (un cuelgue no es un hit).
pub async fn resolver_sistema(host: &str) -> Resuelto {
    let fut = tokio::net::lookup_host(format!("{host}:80"));
    match tokio::time::timeout(TIMEOUT_CONSULTA, fut).await {
        Ok(Ok(addrs)) => {
            let mut ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            ips.sort();
            ips.dedup();
            ips
        }
        _ => Vec::new(), // NXDOMAIN, error de resolvedor, o tope agotado.
    }
}

/// La clasificación del wildcard DNS de un dominio, que decide SI se puede
/// bruteforce-ar por IP (M1 de la revisión).
#[derive(Debug, PartialEq, Eq)]
pub enum Wildcard {
    /// Los señuelos NO resuelven: no hay wildcard, cualquier resolución es un host real.
    Ninguno,
    /// Wildcard FIJO (pool pequeño y estable de IPs): un candidato con IP fuera del pool
    /// es real; se puede discriminar. Lleva el set de IPs del eco.
    Fijo(BTreeSet<IpAddr>),
    /// Wildcard ROTATORIO / CDN (pool grande): real y eco apuntan al mismo CDN, así que
    /// el DNS NO puede distinguirlos. La base NO es bruteforce-able por IP → se omite.
    Rotatorio,
}

/// Umbral: si los señuelos revelan MÁS de estas IPs distintas, es un pool CDN/rotatorio
/// y la discriminación por IP no es fiable (real y eco comparten el CDN).
pub const MAX_IPS_DISCRIMINABLE: usize = 3;

/// Clasifica el wildcard a partir de las resoluciones de los señuelos (puro, testeable).
pub fn clasificar_wildcard(resoluciones_senuelo: &[Resuelto]) -> Wildcard {
    let comodin = derivar_comodin(resoluciones_senuelo);
    if comodin.is_empty() {
        Wildcard::Ninguno
    } else if comodin.len() <= MAX_IPS_DISCRIMINABLE {
        Wildcard::Fijo(comodin)
    } else {
        Wildcard::Rotatorio
    }
}

/// Envoltura *owning* de `resolver_sistema` (toma `String`), para pasarla como closure
/// resolvedor a `bruteforce` en producción: `|h| Box::pin(resolver_sistema_owned(h))`.
pub async fn resolver_sistema_owned(host: String) -> Resuelto {
    resolver_sistema(&host).await
}

/// Etiquetas-señuelo (nombres que casi con certeza no existen) para detectar wildcard.
/// Cinco (no tres) para muestrear mejor el pool de un wildcard rotatorio (M1).
fn senuelos(dominio: &str) -> [String; 5] {
    [
        format!("zzq7x9k3-noexiste-a.{dominio}"),
        format!("qk2m8v4w-noexiste-b.{dominio}"),
        format!("x9p1r7t5-noexiste-c.{dominio}"),
        format!("m4n8b2v6-noexiste-d.{dominio}"),
        format!("w7e3r9t1-noexiste-e.{dominio}"),
    ]
}

/// BRUTEFORCE genérico sobre `dominio` con `palabras`, resolviendo por `resolver`
/// (inyectable). Concurrencia acotada (`concurrencia`) para no martillar el resolvedor.
/// Detecta wildcard primero y filtra su eco. Devuelve los subdominios REALES, ordenados.
///
/// `resolver` es `Fn(String) -> Future<Resuelto>`: en producción `resolver_sistema`, en
/// las pruebas un mapa determinista (por eso la lógica se valida sin red, directiva 33).
/// Tope duro de concurrencia: por encima se satura el pool de hilos *blocking* de
/// tokio (512, compartido con `fs`) y se disparan rate-limits del resolvedor (nota
/// LOW de la revisión).
pub const MAX_CONCURRENCIA: usize = 200;

pub async fn bruteforce<F, Fut>(
    dominio: &str,
    palabras: &[&str],
    concurrencia: usize,
    deadline: Option<std::time::Instant>,
    resolver: F,
) -> Vec<String>
where
    F: Fn(String) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Resuelto> + Send,
{
    let resolver = Arc::new(resolver);

    // 1) Clasificar el wildcard resolviendo los señuelos.
    let mut senuelo_res = Vec::new();
    for s in senuelos(dominio) {
        senuelo_res.push((resolver)(s).await);
    }
    let comodin = match clasificar_wildcard(&senuelo_res) {
        Wildcard::Ninguno => BTreeSet::new(),
        Wildcard::Fijo(set) => set,
        Wildcard::Rotatorio => {
            // Real y eco comparten el CDN: el DNS no discrimina. Omitir es honesto
            // (dir. 20/23), no emitir cientos de FPs. Se DICE por qué se calla (dir. 30).
            tracing::info!("bruteforce DNS: {dominio} tiene wildcard rotatorio/CDN — no discriminable por IP, omitido");
            return Vec::new();
        }
    };

    // 2) Resolver cada candidato con concurrencia acotada, respetando el deadline.
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrencia.clamp(1, MAX_CONCURRENCIA)));
    let mut tareas = tokio::task::JoinSet::new();
    for w in palabras {
        // Deadline (M2): dejar de lanzar candidatos al vencer; los ya lanzados acaban
        // acotados por el tope por consulta de `resolver_sistema`.
        if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
            break;
        }
        let w = w.trim().to_ascii_lowercase();
        if w.is_empty() {
            continue;
        }
        let host = format!("{w}.{dominio}");
        let resolver = Arc::clone(&resolver);
        let sem = Arc::clone(&sem);
        let comodin = comodin.clone();
        tareas.spawn(async move {
            let _permiso = sem.acquire().await.ok()?;
            let ips = (resolver)(host.clone()).await;
            if es_hit_real(&ips, &comodin) {
                Some(host)
            } else {
                None
            }
        });
    }

    let mut hits: BTreeSet<String> = BTreeSet::new();
    while let Some(res) = tareas.join_next().await {
        if let Ok(Some(host)) = res {
            hits.insert(host);
        }
    }
    hits.into_iter().collect()
}

/// El diccionario POR DEFECTO, curado, embebido en el binario (keyless, offline). Son
/// las etiquetas de subdominio más productivas: entornos, APIs, admin, infra. Se puede
/// ampliar o sustituir por un archivo vía config sin recompilar (directiva 19).
pub const PALABRAS_DEFECTO: &[&str] = &[
    // entornos
    "dev", "development", "test", "testing", "qa", "uat", "stage", "staging", "stg",
    "sandbox", "sbx", "demo", "preview", "preprod", "pre", "prod", "production", "live",
    "int", "integration", "internal", "intranet", "corp", "local", "lab",
    // apis y servicios
    "api", "api2", "api-dev", "apidev", "api-staging", "apis", "rest", "graphql", "gql",
    "gateway", "gw", "service", "services", "svc", "backend", "back", "app", "apps",
    "mobile", "m", "web", "www", "www2", "cdn", "static", "assets", "media", "img",
    "images", "files", "download", "downloads", "upload", "uploads",
    // admin y acceso
    "admin", "administrator", "adm", "manage", "management", "console", "panel",
    "dashboard", "portal", "login", "signin", "sso", "auth", "oauth", "identity", "idp",
    "account", "accounts", "user", "users", "my", "secure", "vpn", "remote", "access",
    // infra y devops
    "git", "gitlab", "github", "jenkins", "ci", "cd", "build", "deploy", "registry",
    "docker", "k8s", "kube", "grafana", "kibana", "prometheus", "monitor", "monitoring",
    "metrics", "status", "health", "logs", "logging", "elastic", "consul", "vault",
    "nexus", "artifactory", "sonar", "jira", "confluence", "wiki",
    // datos y correo
    "db", "database", "sql", "mysql", "postgres", "redis", "mongo", "data", "warehouse",
    "mail", "smtp", "imap", "pop", "webmail", "exchange", "ns1", "ns2", "mx", "dns",
    // negocio
    "shop", "store", "checkout", "cart", "pay", "payment", "payments", "billing",
    "invoice", "wallet", "crm", "erp", "hr", "support", "help", "helpdesk", "ticket",
    "docs", "documentation", "developer", "developers", "partner", "partners", "blog",
    "news", "events", "beta", "alpha", "old", "new", "legacy", "v1", "v2", "v3",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashMap};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn es_hit_real_discrimina() {
        let sin_comodin = BTreeSet::new();
        // VERDE: resuelve y no hay comodín → hit.
        assert!(es_hit_real(&[ip("1.2.3.4")], &sin_comodin));
        // ROJO (pareja, dir. 33): NO resuelve → NO es hit, por la vía real (vacío).
        assert!(!es_hit_real(&[], &sin_comodin));

        // Con comodín en 9.9.9.9:
        let comodin: BTreeSet<IpAddr> = [ip("9.9.9.9")].into_iter().collect();
        // VERDE: resuelve a una IP DISTINTA del comodín → host propio real.
        assert!(es_hit_real(&[ip("1.2.3.4")], &comodin));
        // ROJO: resuelve SOLO a la IP del comodín → es el eco del wildcard, NO es hit.
        assert!(!es_hit_real(&[ip("9.9.9.9")], &comodin));
        // Mixto: una propia + una del comodín → SÍ (tiene algo que el comodín no da).
        assert!(es_hit_real(&[ip("9.9.9.9"), ip("1.2.3.4")], &comodin));
    }

    #[test]
    fn derivar_comodin_une_las_ips_de_senuelos() {
        let senuelos = vec![vec![ip("9.9.9.9")], vec![ip("9.9.9.9"), ip("8.8.8.8")], vec![]];
        let c = derivar_comodin(&senuelos);
        assert_eq!(c.len(), 2);
        assert!(c.contains(&ip("9.9.9.9")) && c.contains(&ip("8.8.8.8")));
        // Sin señuelos que resuelvan → comodín vacío (no hay wildcard).
        assert!(derivar_comodin(&[vec![], vec![]]).is_empty());
    }

    #[test]
    fn clasificar_wildcard_distingue_ninguno_fijo_rotatorio() {
        // Ninguno: los señuelos no resuelven.
        assert_eq!(clasificar_wildcard(&[vec![], vec![], vec![]]), Wildcard::Ninguno);
        // Fijo: pool pequeño y estable (≤3 IPs) → discriminable.
        let fijo = clasificar_wildcard(&[vec![ip("9.9.9.9")], vec![ip("9.9.9.9")]]);
        assert!(matches!(fijo, Wildcard::Fijo(_)));
        // Rotatorio: pool grande (>3 IPs distintas) → CDN, NO discriminable.
        let rot = clasificar_wildcard(&[
            vec![ip("1.1.1.1"), ip("1.1.1.2")],
            vec![ip("1.1.1.3"), ip("1.1.1.4")],
            vec![ip("1.1.1.5")],
        ]);
        assert_eq!(rot, Wildcard::Rotatorio);
    }

    /// Resolvedor MOCK: cruza la frontera de la LÓGICA de bruteforce con datos
    /// deterministas, sin red (dir. 33/28). Un mapa nombre→IPs.
    fn mock(mapa: HashMap<String, Resuelto>) -> impl Fn(String) -> std::future::Ready<Resuelto> + Clone {
        move |host: String| std::future::ready(mapa.get(&host).cloned().unwrap_or_default())
    }

    #[tokio::test]
    async fn bruteforce_sin_wildcard_encuentra_los_que_resuelven() {
        let mut m = HashMap::new();
        m.insert("api.ejemplo.com".to_string(), vec![ip("1.1.1.1")]);
        m.insert("admin.ejemplo.com".to_string(), vec![ip("2.2.2.2")]);
        // 'noexiste' y los señuelos NO están en el mapa → no resuelven.
        let palabras = ["api", "admin", "noexiste"];
        let r = bruteforce("ejemplo.com", &palabras, 8, None, mock(m)).await;
        assert_eq!(r, vec!["admin.ejemplo.com".to_string(), "api.ejemplo.com".to_string()]);
    }

    #[tokio::test]
    async fn bruteforce_wildcard_rotatorio_cdn_se_omite() {
        // EL CASO QUE ROMPÍA (M1): wildcard rotatorio (CDN) — CADA nombre resuelve a una
        // IP distinta de un pool grande. Con la lógica ingenua de filtrar-por-IP, decenas
        // de ecos pasarían como FPs. Lo correcto es OMITIR la base (el DNS no discrimina).
        // Rojo por la vía real: la lógica vieja daría hits; la nueva, vacío.
        use std::sync::atomic::{AtomicU8, Ordering};
        let n = Arc::new(AtomicU8::new(0));
        let resolver = move |_host: String| {
            let k = n.fetch_add(1, Ordering::SeqCst);
            std::future::ready(vec![ip(&format!("10.0.0.{k}"))]) // IP siempre distinta
        };
        let palabras = ["api", "admin", "www", "cualquiera"];
        let r = bruteforce("cdn-wildcard.com", &palabras, 8, None, resolver).await;
        assert!(r.is_empty(), "un wildcard rotatorio/CDN se OMITE, no infla FPs");
    }

    /// CRUZA LA FRONTERA REAL (dir. 28): resuelve DNS de verdad con el resolvedor del
    /// sistema. `#[ignore]` porque necesita red; se corre a mano (`--ignored`).
    #[tokio::test]
    #[ignore]
    async fn resolucion_real_de_dns() {
        // Un host que SÍ existe.
        let ips = resolver_sistema("one.one.one.one").await;
        assert!(!ips.is_empty(), "one.one.one.one debe resolver");
        // Un host que NO existe → vacío (por la vía real, no inventado).
        let vacio = resolver_sistema("zzq7x9k3-noexiste-xyz.cloudflare.com").await;
        assert!(vacio.is_empty(), "un nombre inexistente no resuelve");
        // Bruteforce real de extremo a extremo sobre un dominio con subs conocidos.
        let r = bruteforce("cloudflare.com", &["www", "blog", "zzq7-noexiste"], 8, None, |h| Box::pin(resolver_sistema_owned(h))).await;
        assert!(r.iter().any(|h| h == "www.cloudflare.com"), "www.cloudflare.com debe salir");
        assert!(!r.iter().any(|h| h.starts_with("zzq7")), "el inexistente no");
    }

    #[tokio::test]
    async fn bruteforce_con_wildcard_filtra_el_eco() {
        // Wildcard: TODO resuelve a 9.9.9.9 (incluidos los señuelos).
        let comodin_ip = ip("9.9.9.9");
        let palabras = ["api", "admin", "cualquiercosa"];
        // Un host REAL (api) tiene además una IP propia; el resto solo el comodín.
        let resolver = move |host: String| {
            let ips = if host.starts_with("api.") {
                vec![ip("1.1.1.1"), comodin_ip] // real: IP propia + eco
            } else {
                vec![comodin_ip] // todo lo demás: solo el comodín
            };
            std::future::ready(ips)
        };
        let r = bruteforce("ejemplo.com", &palabras, 8, None, resolver).await;
        // Solo 'api' sobrevive el filtro de wildcard; 'admin'/'cualquiercosa' son eco.
        assert_eq!(r, vec!["api.ejemplo.com".to_string()], "el wildcard NO debe inflar hits");
    }
}
