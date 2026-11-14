//! BESPOKE — descubrimiento por-nicho, primera encarnación: SAP Commerce / Hybris.
//!
//! El cuello medido el 2026-08-24 en vivo: el recon GENÉRICO sale con `params 0`
//! sobre objetivos maduros (el crawler no ve superficie inyectable). El arsenal
//! entonces no tiene dónde inyectar y sale seco o bloqueado. El edge no es
//! optimizar el escaneo del arsenal —eso ya está—, es GENERAR lo que el genérico
//! no produce: la superficie que solo conoce quien razona sobre ESTE stack.
//!
//! Esta es la capa de DESCUBRIMIENTO BESPOKE que faltaba, con la disciplina que
//! separa un laboratorio de un `brain` (analogía de Juan): la generación es
//! GRAMÁTICA ESTRUCTURAL —endpoints y parámetros conocidos de la plataforma,
//! codificados como reglas—, NO texto libre de un LLM. Linaje ESTRECHO y profundo
//! (un stack bien hecho), no amplitud de escuadrones. El oráculo que confirma lo
//! que la superficie produzca es el que ya existe (OOB/contenido/IDOR): la
//! selección sigue seleccionando EDGE, no ruido.
//!
//! Dos capas aquí (0 y 1); la generación de la SONDA (capa 2) y el cableado a la
//! caza vienen después, medidos aparte.
//!   - Capa 0 — FINGERPRINT: ¿este host es Hybris? Pasivo (cookies/cabeceras) para
//!     SOSPECHAR, activo (la API OCC devuelve una forma JSON característica) para
//!     CONFIRMAR y de paso descubrir los `baseSites`.
//!   - Capa 1 — SUPERFICIE: dado Hybris + sus baseSites, las rutas OCC conocidas
//!     que aceptan entrada y que el crawler genérico no enumera. Varias son
//!     IDOR-prone (`/users/{id}/...`) → alimentan el motor autz con el oráculo ya
//!     endurecido (recurso público, 2026-08-24).

/// El stack identificado. Hoy solo Hybris; el enum deja sitio a los siguientes
/// nichos SIN que el llamante tenga que cambiar (cascada, directiva 19).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stack {
    Hybris,
}

/// Lo mínimo observado de un host para sospechar su stack de forma PASIVA (sin
/// una petición dedicada: son señales que una respuesta cualquiera ya trae).
#[derive(Debug, Clone, Default)]
pub struct SenalesPasivas {
    /// Valor de `Set-Cookie` concatenado (o los nombres de cookie), en minúsculas.
    pub cookies: String,
    /// Cabecera `x-powered-by` si la hay, en minúsculas.
    pub x_powered_by: String,
    /// Cabecera `server` si la hay, en minúsculas.
    pub server: String,
}

/// Capa 0 (pasiva) — ¿HAY SOSPECHA de Hybris? NO confirma: un JSESSIONID lo pone
/// cualquier app Java. Sospecha = Java (JSESSIONID) Y una segunda señal del
/// acelerador de SAP (la cookie de routing/afinidad, o rastros de storefront).
/// Falla del lado de SOSPECHAR de más: la confirmación activa descarta los falsos
/// (una sospecha barata que se confirma con una petición no hace daño; un falso
/// negativo aquí sí pierde el objetivo). Puro y testeable.
pub fn sospecha_hybris(s: &SenalesPasivas) -> bool {
    let java = s.cookies.contains("jsessionid");
    // Señales secundarias del acelerador Hybris/SAP Commerce (todas públicas):
    // la cookie de afinidad `ROUTE`/`acceleratorSecureGUID`, o el storefront.
    let acelerador = s.cookies.contains("route")
        || s.cookies.contains("acceleratorsecureguid")
        || s.cookies.contains("_ga_hybris")
        || s.x_powered_by.contains("hybris")
        || s.x_powered_by.contains("sap commerce");
    java && acelerador
}

/// Capa 0 (activa) — ¿esta respuesta ES la API OCC de Hybris? La confirmación
/// dura: la OCC (Omni Commerce Connect) devuelve, ante `/occ/v2/basesites` o una
/// petición mal formada, un JSON con la forma característica `{"errors":[{"type":
/// "...","message":"..."}]}` o `{"baseSites":[...]}`. Un 200/400 con ese esquema
/// es Hybris; un HTML, un 404 genérico o un JSON de otra forma, no. Puro.
///
/// Discrimina por el ESQUEMA, no por una palabra suelta: se exige la CLAVE
/// estructural (`baseSites` o un `errors` con `type`), porque «errors» a secas
/// aparece en mil APIs. Es el mismo rigor anti-substring que el oráculo SSRF.
pub fn es_api_occ(status: u16, cuerpo: &str) -> bool {
    // Debe oler a JSON (no un HTML de storefront ni un challenge de WAF).
    let c = cuerpo.trim_start();
    if !c.starts_with('{') {
        return false;
    }
    let cl = cuerpo.to_ascii_lowercase();
    // Señal fuerte 1: la lista de baseSites (respuesta de /occ/v2/basesites).
    let tiene_basesites = cl.contains("\"basesites\"") && cl.contains("\"uid\"");
    // Señal fuerte 2: el sobre de error OCC — un array `errors` con objetos que
    // llevan `type` (p. ej. "UnknownIdentifierError", "ValidationError").
    let tiene_error_occ = cl.contains("\"errors\"")
        && cl.contains("\"type\"")
        && (cl.contains("error")); // el type de OCC termina en "Error"
    // 2xx con baseSites, o 4xx con el sobre de error: ambos confirman OCC.
    (matches!(status, 200..=299) && tiene_basesites)
        || (matches!(status, 400..=404) && tiene_error_occ)
}

/// Extrae los `uid` de baseSite de la respuesta de `/occ/v2/basesites`. Sin un
/// parser de JSON completo (no metemos una dependencia por esto): busca los
/// valores de `"uid":"..."`, que es la clave que la OCC usa para cada baseSite.
/// Determinista, orden de aparición, deduplicado. Si no encuentra ninguno,
/// devuelve vacío y el llamante usará los baseSites por defecto conocidos.
pub fn parse_basesites(cuerpo: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let aguja = "\"uid\"";
    let bytes = cuerpo.as_bytes();
    let mut i = 0;
    while let Some(pos) = cuerpo[i..].find(aguja) {
        let mut j = i + pos + aguja.len();
        // Saltar espacios y los dos puntos hasta la comilla de apertura del valor.
        while j < bytes.len() && bytes[j] != b'"' {
            // Si topamos con algo que no sea `:`/espacio antes de la comilla, no es
            // un par `"uid":"valor"` bien formado; se corta.
            if bytes[j] != b':' && !bytes[j].is_ascii_whitespace() {
                break;
            }
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b'"' {
            let ini = j + 1;
            if let Some(rel) = cuerpo[ini..].find('"') {
                let val = &cuerpo[ini..ini + rel];
                // Un uid de baseSite es un identificador corto y sano.
                if !val.is_empty()
                    && val.len() <= 64
                    && val.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                    && !out.iter().any(|v| v == val)
                {
                    out.push(val.to_string());
                }
            }
        }
        i = i + pos + aguja.len();
    }
    out
}

/// Las plantillas de ruta OCC que aceptan ENTRADA (el genoma de superficie de
/// Hybris). `{host}` y `{site}` se rellenan; el resto son parámetros conocidos de
/// la OCC. Cada `{site}` viene de `parse_basesites` o de la lista por defecto.
/// Documentado y público (SAP Commerce OCC v2). Las marcadas IDOR van al motor
/// autz; las de `query`/`fields` al de inyección.
const RUTAS_OCC: &[&str] = &[
    // Búsqueda de productos: `query` y `fields` son superficie de inyección clásica
    // (el `fields` de respuesta parcial de SAP es un selector abusable).
    "/occ/v2/{site}/products/search?query=x&fields=FULL&currentPage=0",
    "/rest/v2/{site}/products/search?query=x&fields=FULL",
    // Producto por código: `{code}` y `fields`.
    "/occ/v2/{site}/products/1?fields=FULL",
    // Usuarios — IDOR-prone: el motor autz (oráculo endurecido) compara identidades.
    "/occ/v2/{site}/users/current?fields=FULL",
    "/occ/v2/{site}/users/1/carts?fields=FULL",
    "/occ/v2/{site}/users/1/orders?fields=FULL",
    // Catálogos y CMS: enumeración de contenido.
    "/occ/v2/{site}/catalogs?fields=FULL",
    "/occ/v2/{site}/cms/pages?fields=FULL&pageType=ContentPage",
];

/// baseSites por defecto de Hybris cuando `/occ/v2/basesites` no los entregó: los
/// dos nombres que el acelerador trae de fábrica. Mejor tener DÓNDE probar que no
/// probar (directiva 20: no se rellena un dato ausente con basura, pero estos son
/// los valores REALES por defecto de la plataforma, no un invento).
const BASESITES_DEFECTO: &[&str] = &["electronics", "apparel-uk"];

/// Capa 1 — la SUPERFICIE BESPOKE: dado el host y sus baseSites, las URLs OCC
/// conocidas que aceptan entrada. Es lo que el crawler genérico no enumera y que
/// alimenta las fases de inyección/IDOR. Puro, determinista, deduplicado.
pub fn superficie_occ(host: &str, base_sites: &[String]) -> Vec<String> {
    let sites: Vec<&str> = if base_sites.is_empty() {
        BASESITES_DEFECTO.to_vec()
    } else {
        base_sites.iter().map(String::as_str).collect()
    };
    let base = host.trim_end_matches('/');
    let mut out = Vec::new();
    for site in &sites {
        for ruta in RUTAS_OCC {
            let camino = ruta.replace("{site}", site);
            let url = format!("https://{base}{camino}");
            if !out.contains(&url) {
                out.push(url);
            }
        }
    }
    out
}

/// Funde la superficie bespoke descubierta en el corpus del hunt, sin duplicar.
/// Extraído del cableado de `cmd_hunt` para que la lógica de fusión —lo único con
/// decisión ahí— tenga prueba (el resto de ese bloque es orquestación de I/O).
/// Devuelve cuántas URLs NUEVAS se añadieron.
pub fn fundir_superficie(corpus: &mut Vec<String>, superficie: Vec<String>) -> usize {
    let mut nuevas = 0;
    for u in superficie {
        if !corpus.contains(&u) {
            corpus.push(u);
            nuevas += 1;
        }
    }
    nuevas
}

// ── CAPA 2 (primera clase de debilidad): SUPERFICIE ADMIN de Hybris expuesta ──
//
// Consolas de administración de Hybris que NO deberían ser alcanzables desde
// internet (van tras VPN/lista-blanca de IP). Alcanzarlas sin auth es un hallazgo
// por sí solo; la CONSOLA DE SCRIPTING alcanzable es ejecución de código (RCE).
// Esto SORTEA el cuello `params 0`: no necesita parámetros, solo rutas conocidas
// del stack que el crawler genérico no prueba. Detección GET, idempotente;
// la EXPLOTACIÓN (scripting → RCE por OOB) es un trozo aparte, agresivo.

/// La CLASE de consola admin: fija qué FIRMA se busca (anclada a la ruta, para que
/// el `vuln_name` no se cruce — obs. de la revisión).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaseAdmin {
    Hac,
    Backoffice,
    Scripting,
}

/// Una superficie admin de Hybris y la severidad SI la consola operativa está
/// expuesta sin auth. El caso «login alcanzable» (defensa en profundidad) se
/// clasifica aparte, siempre `low`.
pub struct AdminHybris {
    pub ruta: &'static str,
    pub clase: ClaseAdmin,
    pub vuln_name: &'static str,
    pub severidad: &'static str,
    pub cwe: &'static str,
    pub descripcion: &'static str,
}

pub const ADMIN_HYBRIS: &[AdminHybris] = &[
    AdminHybris {
        ruta: "/hac/console/scripting",
        clase: ClaseAdmin::Scripting,
        vuln_name: "hybris-consola-scripting-expuesta",
        severidad: "critical",
        cwe: "CWE-94", // Code Injection
        descripcion: "consola de scripting de la HAC (Groovy/BeanShell) alcanzable — ejecución de código",
    },
    AdminHybris {
        ruta: "/hac",
        clase: ClaseAdmin::Hac,
        vuln_name: "hybris-hac-expuesta",
        severidad: "high",
        cwe: "CWE-284", // Improper Access Control
        descripcion: "Hybris Administration Console alcanzable desde internet (debe ir tras VPN/lista-blanca)",
    },
    AdminHybris {
        ruta: "/backoffice",
        clase: ClaseAdmin::Backoffice,
        vuln_name: "hybris-backoffice-expuesto",
        severidad: "high",
        cwe: "CWE-284",
        descripcion: "backoffice de administración de Hybris alcanzable desde internet",
    },
];

/// ¿La firma de la UI admin de ESTA clase está en el cuerpo? Anclada a la ruta
/// probada (no se cruzan las tres firmas). Exige el token de ADMINISTRACIÓN —
/// «hybris» a secas NO basta (el storefront también lo lleva).
fn firma_admin(clase: ClaseAdmin, c: &str) -> bool {
    match clase {
        ClaseAdmin::Hac => {
            c.contains("administration console") && (c.contains("hybris") || c.contains("sap commerce"))
        }
        ClaseAdmin::Backoffice => {
            c.contains("backoffice")
                && (c.contains("zk") || c.contains("cockpit") || c.contains("hybris") || c.contains("sap commerce"))
        }
        ClaseAdmin::Scripting => {
            c.contains("script")
                && (c.contains("groovy") || c.contains("beanshell"))
                && (c.contains("execute") || c.contains("commit"))
        }
    }
}

/// ¿El cuerpo es una PÁGINA DE LOGIN (formulario de credenciales)? Un 200 con
/// login significa que la consola es alcanzable a nivel de RED pero EXIGE
/// credenciales — defensa en profundidad (bajo), NO una consola operativa expuesta
/// (obs. de la revisión: no marcar HIGH un login-page 200, que es el control
/// funcionando por otra vía que el 302).
fn es_pagina_login(c: &str) -> bool {
    c.contains("j_spring_security_check") // Spring Security (Hybris lo usa)
        || c.contains("type=\"password\"")
        || c.contains("type='password'")
        || (c.contains("password") && (c.contains("j_username") || c.contains("name=\"username\"")))
}

/// El resultado de clasificar una respuesta admin: qué reportar.
pub struct HallazgoAdmin {
    pub vuln_name: String,
    pub severidad: &'static str,
    pub evidencia: String,
}

/// EL ORÁCULO de la capa 2 (anclado a la ruta): clasifica la respuesta a UNA sonda
/// admin. `None` si no es 2xx (un 302→login / 401 / 403 es el control FUNCIONANDO)
/// o si no casa la firma de ESA consola. Si casa, distingue:
///  - CONSOLA EXPUESTA (UI operativa SIN login) → severidad de la consola (high/crit).
///  - LOGIN ALCANZABLE (200 con formulario de login) → `low`, evidencia honesta.
pub fn clasificar_admin(admin: &AdminHybris, status: u16, cuerpo: &str, url: &str) -> Option<HallazgoAdmin> {
    if !matches!(status, 200..=299) {
        return None;
    }
    let c = cuerpo.to_ascii_lowercase();
    if !firma_admin(admin.clase, &c) {
        return None;
    }
    if es_pagina_login(&c) {
        Some(HallazgoAdmin {
            vuln_name: "hybris-consola-admin-login-alcanzable".to_string(),
            severidad: "low",
            evidencia: format!(
                "{url} responde HTTP {status} con el LOGIN de una consola admin de Hybris ({}): \
                 alcanzable a nivel de RED pero EXIGE credenciales. Defensa en profundidad: debería \
                 ir tras VPN/lista-blanca de IP.",
                admin.descripcion
            ),
        })
    } else {
        Some(HallazgoAdmin {
            vuln_name: admin.vuln_name.to_string(),
            severidad: admin.severidad,
            evidencia: format!(
                "{url} responde HTTP {status} con la UI OPERATIVA de la consola admin de Hybris SIN \
                 login ({}). Confirmar manualmente el alcance; si es la consola de scripting, NO \
                 ejecutar sin autorización.",
                admin.descripcion
            ),
        })
    }
}

/// Deriva los HOSTS ÚNICOS de una lista de URLs de `targets.txt` (varias URLs por
/// host: esquemas, rutas, favicon). Orden de aparición, deduplicado, sin vacíos.
/// Es lo que evita el `https://https://…` que hacía la fase un no-op.
pub fn hosts_unicos(urls: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for u in urls {
        let h = crate::scope::host_of(u);
        if !h.is_empty() && !out.contains(&h) {
            out.push(h);
        }
    }
    out
}

/// Las rutas de la API OCC que confirman Hybris y descubren los baseSites. Se
/// prueban en orden; la primera que responda con la forma OCC confirma.
const RUTAS_CONFIRMACION: &[&str] = &["/occ/v2/basesites", "/rest/v2/basesites"];

/// LA FASE (capas 0+1 sobre la red real): fingerprint cada host y, para los que
/// confirman Hybris, emite la superficie OCC bespoke. Devuelve las URLs
/// descubiertas —lo que el crawler genérico no vio— para que las fases de
/// inyección/IDOR las consuman. Antibaneo: reusa el `Guard` compartido (429/503 →
/// backoff; si se acumulan, para y protege la IP compartida del VPS). Respeta el
/// deadline del ciclo. `cap` acota cuántos hosts se fingerprintean.
#[allow(clippy::too_many_arguments)]
pub async fn fase_bespoke(
    pool: &sqlx::SqlitePool,
    program: &str,
    hosts: &[String],
    cap: usize,
    ua: &str,
    deadline: Option<std::time::Instant>,
    webhook: Option<&str>,
) -> crate::error::Result<Vec<String>> {
    let cliente = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(12))
        .user_agent(ua)
        // NO seguir redirects: fingerprinteamos ESTE host. Un redirect que el
        // objetivo elija a otro host daría una huella equivocada y tocaría fuera de
        // scope (obs. de la revisión, 2026-08-24). Higiene de scope por defecto. Y
        // en la capa 2 es ESENCIAL: un 302→login NO debe seguirse (sería el control
        // funcionando; seguirlo confundiría la protección con exposición).
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let program_id = crate::db::upsert_program(pool, program).await?;
    // Guard propio de la fase (como arnm): protege la IP compartida del VPS; un
    // baneo acumulado fingerprinteando un host frena la fase entera.
    let mut guard = crate::protection::Guard::new(crate::protection::ProtectionConfig::default());
    let mut rng = {
        use rand::Rng;
        let mut r = rand::rng();
        move || r.random::<f64>()
    };
    let guard = &mut guard;
    // La entrada son URLs de `targets.txt` (httpx emite `https://host`,
    // `http://host/`, `https://host/favicon.ico`…): se derivan los HOSTS ÚNICOS
    // para fingerprintear cada uno UNA vez. Sin esto se hacía `https://{url}` y
    // salía `https://https://host` — reqwest fallaba y la fase era un NO-OP.
    let hosts_a_probar = hosts_unicos(hosts);
    let a_sondear = hosts_a_probar.len().min(cap);
    let mut hybris = 0usize;
    let mut superficie: Vec<String> = Vec::new();
    for host in hosts_a_probar.iter().take(cap) {
        if crate::autz::deadline_vencido(deadline) {
            tracing::info!("bespoke: presupuesto del ciclo agotado — paro ({} URLs)", superficie.len());
            break;
        }
        if guard.should_pause() {
            tracing::warn!("bespoke: PAUSA por rate-limit acumulado — protejo la IP compartida del VPS");
            break;
        }
        let base = format!("https://{host}");
        match procesar_host_hybris(&cliente, &base, pool, program, program_id, webhook, guard).await {
            Ok(urls) if !urls.is_empty() => {
                hybris += 1;
                tracing::info!("bespoke: {host} confirmado Hybris — +{} URLs OCC de superficie", urls.len());
                superficie.extend(urls);
            }
            Ok(_) => {} // no es Hybris (o no confirmó): nada que emitir.
            Err(_) => {
                guard.record_failure();
            }
        }
        tokio::time::sleep(guard.cooldown(1, rng())).await;
    }
    // POSITIVO DE CONTROL (dir. 30): la fase debe DECIR en cada ciclo que corrió,
    // aunque no encuentre Hybris — si no, «fingerprinteé N y ninguno era Hybris»
    // y «la fase es un no-op» se ven igual (fue exactamente el bug del no-op).
    tracing::info!(
        "bespoke: {a_sondear} host(s) fingerprinteados, {hybris} confirmado(s) Hybris, +{} URLs de superficie",
        superficie.len()
    );
    Ok(superficie)
}

/// CAPA 2 (núcleo, sin BD, testeable E2E) — sonda las consolas admin bajo `base`
/// (URL base con esquema: `https://host` en producción) y devuelve, por cada
/// EXPUESTA (según `clasificar_admin`), su `(admin, url, hallazgo)`. GET
/// idempotente. Cooldown entre sondas (higiene de la fase, obs. de la revisión).
/// Antibaneo por el `guard` compartido.
pub async fn detectar_admin_urls(
    cliente: &reqwest::Client,
    base: &str,
    guard: &mut crate::protection::Guard,
) -> Vec<(&'static AdminHybris, String, HallazgoAdmin)> {
    let base = base.trim_end_matches('/');
    let mut expuestas = Vec::new();
    for (i, admin) in ADMIN_HYBRIS.iter().enumerate() {
        if guard.should_pause() {
            break;
        }
        // Espaciado entre sondas del mismo host (no ráfaga de 3 GET seguidos).
        if i > 0 {
            tokio::time::sleep(guard.cooldown(1, 0.5)).await;
        }
        let url = format!("{base}{}", admin.ruta);
        let Ok(r) = cliente.get(&url).send().await else { continue };
        let status = r.status().as_u16();
        if crate::protection::es_senal_de_baneo(status) {
            let espera = guard.record_failure();
            tokio::time::sleep(guard.cooldown(espera, 0.5)).await;
            break;
        }
        let cuerpo = r.text().await.unwrap_or_default();
        if let Some(h) = clasificar_admin(admin, status, &cuerpo, &url) {
            expuestas.push((admin, url, h));
        }
    }
    expuestas
}

/// CAPA 2 — sonda las consolas admin de un host confirmado Hybris y PERSISTE las
/// expuestas como hallazgo. Un hallazgo aquí NO es execution_confirmed (es
/// detección, no explotación) → nunca se auto-envía; queda para revisión humana.
async fn detectar_admin(
    cliente: &reqwest::Client,
    base: &str,
    pool: &sqlx::SqlitePool,
    program: &str,
    program_id: i64,
    webhook: Option<&str>,
    guard: &mut crate::protection::Guard,
) -> crate::error::Result<()> {
    for (admin, url, hallazgo) in detectar_admin_urls(cliente, base, guard).await {
        let nf = crate::db::NewFinding {
            program_name: program.to_string(),
            vuln_name: hallazgo.vuln_name.clone(),
            severity: hallazgo.severidad.to_string(),
            url: url.clone(),
            cwe: Some(admin.cwe.to_string()),
            evidencia: Some(hallazgo.evidencia),
        };
        if crate::db::insert_finding_dedup(pool, &nf, program_id).await? {
            tracing::warn!("bespoke: {} en {url} ({})", hallazgo.vuln_name, hallazgo.severidad);
            let _ = crate::notify::notificar(
                webhook,
                &crate::notify::Evento::Hallazgos(vec![crate::notify::HallazgoBreve {
                    severity: hallazgo.severidad.to_string(),
                    vuln_type: hallazgo.vuln_name,
                    url,
                    program_name: program.to_string(),
                }]),
            )
            .await;
        }
    }
    Ok(())
}

/// PROCESA UN HOST (capas 0+1+2) sobre `base` (URL con esquema: `https://host` en
/// producción, `http://stub` en test). Fingerprint; si es Hybris, PERSISTE las
/// consolas admin expuestas (capa 2) y DEVUELVE la superficie OCC (capa 1). Si no
/// es Hybris, devuelve vacío. Al tomar `base` con esquema es E2E-testeable — lo
/// que habría cazado el bug del `https://https://` (fase no-op) antes de producción.
#[allow(clippy::too_many_arguments)]
pub async fn procesar_host_hybris(
    cliente: &reqwest::Client,
    base: &str,
    pool: &sqlx::SqlitePool,
    program: &str,
    program_id: i64,
    webhook: Option<&str>,
    guard: &mut crate::protection::Guard,
) -> crate::error::Result<Vec<String>> {
    let Some(surface) = fingerprint_y_superficie(cliente, base, guard).await? else {
        return Ok(Vec::new());
    };
    // Capa 2: consolas admin sobre el MISMO host confirmado Hybris.
    detectar_admin(cliente, base, pool, program, program_id, webhook, guard).await?;
    Ok(surface)
}

/// Fingerprint de UN host bajo `base` (URL con esquema) y, si es Hybris, su
/// superficie. `None` si no lo es. Pasivo (raíz) → sospecha; activo (OCC) → confirma.
async fn fingerprint_y_superficie(
    cliente: &reqwest::Client,
    base: &str,
    guard: &mut crate::protection::Guard,
) -> crate::error::Result<Option<Vec<String>>> {
    let base = base.trim_end_matches('/');
    // Pasivo: una petición a la raíz; leemos cabeceras y cookies.
    let resp = match cliente.get(format!("{base}/")).send().await {
        Ok(r) => r,
        Err(_) => return Ok(None), // host inalcanzable: no es trabajo de esta fase reintentar.
    };
    if crate::protection::es_senal_de_baneo(resp.status().as_u16()) {
        // Backoff exponencial ante 429/503, como arnm: proteger la IP compartida.
        let espera = guard.record_failure();
        tokio::time::sleep(guard.cooldown(espera, 0.5)).await;
        return Ok(None);
    }
    let señales = extraer_senales(&resp);
    if !sospecha_hybris(&señales) {
        return Ok(None);
    }
    // Activo: confirmar por la API OCC y descubrir baseSites.
    for ruta in RUTAS_CONFIRMACION {
        let Ok(r) = cliente.get(format!("{base}{ruta}")).send().await else { continue };
        let status = r.status().as_u16();
        if crate::protection::es_senal_de_baneo(status) {
            let espera = guard.record_failure();
            tokio::time::sleep(guard.cooldown(espera, 0.5)).await;
            return Ok(None);
        }
        let cuerpo = r.text().await.unwrap_or_default();
        if es_api_occ(status, &cuerpo) {
            guard.record_success();
            let base_sites = parse_basesites(&cuerpo);
            // El host para las URLs de superficie (siempre https:// en prod).
            let host = crate::scope::host_of(base);
            return Ok(Some(superficie_occ(&host, &base_sites)));
        }
    }
    Ok(None) // sospechoso pero no confirmado: NO se inventa superficie (dir. 20).
}

/// Las señales pasivas de una respuesta: cookies (todas las `Set-Cookie`) y las
/// cabeceras `x-powered-by`/`server`, en minúsculas para la comparación.
fn extraer_senales(resp: &reqwest::Response) -> SenalesPasivas {
    let h = resp.headers();
    let cookies = h
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ")
        .to_ascii_lowercase();
    let get = |k: reqwest::header::HeaderName| {
        h.get(k).and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase()
    };
    SenalesPasivas {
        cookies,
        x_powered_by: get(reqwest::header::HeaderName::from_static("x-powered-by")),
        server: get(reqwest::header::SERVER),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn senales(cookies: &str, xpb: &str) -> SenalesPasivas {
        SenalesPasivas {
            cookies: cookies.to_ascii_lowercase(),
            x_powered_by: xpb.to_ascii_lowercase(),
            server: String::new(),
        }
    }

    // ── Capa 0 pasiva: sospecha_hybris ──────────────────────────────────────

    #[test]
    fn sospecha_hybris_con_java_y_acelerador() {
        // ROJO (debe sospechar): JSESSIONID + cookie de routing del acelerador.
        assert!(sospecha_hybris(&senales("JSESSIONID=ABC; ROUTE=xyz", "")));
        assert!(sospecha_hybris(&senales("JSESSIONID=ABC; acceleratorSecureGUID=g", "")));
        assert!(sospecha_hybris(&senales("JSESSIONID=ABC", "SAP Commerce")));
    }

    #[test]
    fn no_sospecha_java_generico_ni_no_java() {
        // VERDE (NO debe sospechar): el falso positivo grande — un JSESSIONID SOLO
        // lo pone cualquier app Java (Tomcat, Spring), no es Hybris.
        assert!(!sospecha_hybris(&senales("JSESSIONID=ABC", "")));
        assert!(!sospecha_hybris(&senales("JSESSIONID=ABC; other=1", "")));
        // Ni una app sin Java aunque tenga una cookie "route" cualquiera.
        assert!(!sospecha_hybris(&senales("sessionid=ABC; route=1", "")));
        assert!(!sospecha_hybris(&senales("", "")));
    }

    // ── Capa 0 activa: es_api_occ ───────────────────────────────────────────

    #[test]
    fn reconoce_la_api_occ_por_esquema() {
        // ROJO: la respuesta de /occ/v2/basesites (2xx con baseSites+uid).
        assert!(es_api_occ(200, r#"{"baseSites":[{"uid":"electronics","channel":"B2C"}]}"#));
        // ROJO: el sobre de error OCC (4xx con errors+type).
        assert!(es_api_occ(400, r#"{"errors":[{"type":"ValidationError","message":"bad"}]}"#));
    }

    #[test]
    fn no_confunde_otras_apis_ni_html_con_occ() {
        // VERDE: un HTML de storefront NO es la API OCC.
        assert!(!es_api_occ(200, "<html><body>tienda</body></html>"));
        // VERDE: un JSON de OTRA API con `errors` pero sin la forma OCC (sin type).
        assert!(!es_api_occ(400, r#"{"errors":["algo salió mal"]}"#));
        // VERDE: un 200 con baseSites en TEXTO pero no JSON (empieza por '<').
        assert!(!es_api_occ(200, "<xml><baseSites uid='x'/></xml>"));
        // VERDE: un 500 con la forma de error no confirma (fuera del rango 400-404).
        assert!(!es_api_occ(500, r#"{"errors":[{"type":"ServerError"}]}"#));
    }

    // ── parse_basesites ─────────────────────────────────────────────────────

    #[test]
    fn extrae_los_basesites() {
        let cuerpo = r#"{"baseSites":[{"uid":"electronics","x":1},{"uid":"apparel-uk"}]}"#;
        assert_eq!(parse_basesites(cuerpo), vec!["electronics", "apparel-uk"]);
    }

    #[test]
    fn parse_basesites_deduplica_y_filtra_basura() {
        // Repetidos → uno; un uid con caracteres raros (inyección) → descartado.
        let cuerpo = r#"{"a":[{"uid":"site1"},{"uid":"site1"},{"uid":"a\"; DROP"}]}"#;
        assert_eq!(parse_basesites(cuerpo), vec!["site1"]);
        // Sin uids → vacío (el llamante usará los de defecto).
        assert!(parse_basesites(r#"{"vacio":true}"#).is_empty());
    }

    // ── Capa 1: superficie_occ ──────────────────────────────────────────────

    #[test]
    fn genera_superficie_por_basesite_descubierto() {
        let urls = superficie_occ("shop.example.com", &["electronics".to_string()]);
        // Todas las plantillas OCC, para el baseSite descubierto.
        assert_eq!(urls.len(), RUTAS_OCC.len());
        assert!(urls.iter().any(|u| u.contains("/occ/v2/electronics/products/search?query=")));
        assert!(urls.iter().any(|u| u.contains("/occ/v2/electronics/users/1/carts")));
        assert!(urls.iter().all(|u| u.starts_with("https://shop.example.com/")));
        // NO lleva el baseSite de defecto cuando se descubrió uno real.
        assert!(!urls.iter().any(|u| u.contains("apparel-uk")));
    }

    // ── Capa 2: es_admin_expuesto ───────────────────────────────────────────

    fn admin_de(clase: ClaseAdmin) -> &'static AdminHybris {
        ADMIN_HYBRIS.iter().find(|a| a.clase == clase).unwrap()
    }

    #[test]
    fn consola_operativa_sin_login_es_grave() {
        // ROJO: la consola de scripting alcanzable SIN login = crítico (RCE).
        let s = clasificar_admin(admin_de(ClaseAdmin::Scripting), 200,
            "<form>Script language: groovy <button>Execute</button></form>", "http://x/hac/console/scripting").unwrap();
        assert_eq!(s.severidad, "critical");
        assert_eq!(s.vuln_name, "hybris-consola-scripting-expuesta");
        // ROJO: la HAC operativa (UI de consola, sin formulario de login) = high.
        let h = clasificar_admin(admin_de(ClaseAdmin::Hac), 200,
            "<title>hybris administration console</title><div>system monitoring</div>", "http://x/hac").unwrap();
        assert_eq!(h.severidad, "high");
    }

    #[test]
    fn login_alcanzable_es_bajo_no_alto() {
        // EL FP DE LA REVISIÓN: la HAC devuelve 200 con su PÁGINA DE LOGIN — es
        // alcanzable a nivel de red pero EXIGE credenciales → low, no high.
        let h = clasificar_admin(admin_de(ClaseAdmin::Hac), 200,
            "<title>hybris administration console</title><form action='j_spring_security_check'><input type=\"password\"></form>",
            "http://x/hac").unwrap();
        assert_eq!(h.severidad, "low", "un login-page 200 NO es consola expuesta");
        assert_eq!(h.vuln_name, "hybris-consola-admin-login-alcanzable");
        assert!(h.evidencia.contains("EXIGE credenciales"));
    }

    #[test]
    fn no_marca_consola_protegida_ni_generico() {
        let hac = admin_de(ClaseAdmin::Hac);
        // VERDE: un 302 (redirect a login/SSO) es el control FUNCIONANDO.
        assert!(clasificar_admin(hac, 302, "<html>redirect to /login</html>", "u").is_none());
        // VERDE: 401/403 — acceso restringido.
        assert!(clasificar_admin(hac, 401, "hybris administration console", "u").is_none());
        assert!(clasificar_admin(hac, 403, "forbidden", "u").is_none());
        // VERDE: un catch-all 200 genérico (SPA) SIN el token de administración.
        assert!(clasificar_admin(hac, 200, "<html><body>tienda online</body></html>", "u").is_none());
        // VERDE: el storefront lleva «hybris» pero NO es la consola admin.
        assert!(clasificar_admin(hac, 200, "<html>Powered by hybris commerce storefront</html>", "u").is_none());
        // VERDE (anclaje a ruta): el cuerpo de backoffice NO dispara la clase Hac.
        assert!(clasificar_admin(hac, 200, "<html>SAP Commerce Backoffice (ZK)</html>", "u").is_none());
    }

    #[test]
    fn hosts_unicos_deriva_hosts_de_urls_de_targets() {
        // El bug que era no-op: targets.txt son URLs; se derivan hosts ÚNICOS.
        let urls = vec![
            "https://idp.example.be".to_string(),
            "http://idp.example.be/".to_string(),
            "https://idp.example.be/favicon.ico".to_string(),
            "https://shop.example.be:8443/path".to_string(),
        ];
        assert_eq!(hosts_unicos(&urls), vec!["idp.example.be", "shop.example.be"],
            "un host por objetivo, sin esquema ni puerto ni ruta");
    }

    #[test]
    fn fundir_superficie_deduplica_contra_el_corpus() {
        let mut corpus = vec!["https://a.com/x".to_string(), "https://a.com/occ/v2/e/products/search".to_string()];
        let superficie = vec![
            "https://a.com/occ/v2/e/products/search".to_string(), // ya está → no
            "https://a.com/occ/v2/e/users/1/carts".to_string(),   // nueva → sí
        ];
        let n = fundir_superficie(&mut corpus, superficie);
        assert_eq!(n, 1, "solo la URL nueva se añade");
        assert_eq!(corpus.len(), 3);
        assert!(corpus.iter().any(|u| u.ends_with("/users/1/carts")));
    }

    #[test]
    fn sin_basesites_usa_los_de_defecto_reales() {
        // Ausencia de dato → valores REALES por defecto de la plataforma, no vacío
        // (poder probar dónde la plataforma pone su superficie de fábrica).
        let urls = superficie_occ("shop.example.com", &[]);
        assert_eq!(urls.len(), RUTAS_OCC.len() * BASESITES_DEFECTO.len());
        assert!(urls.iter().any(|u| u.contains("/electronics/")));
        assert!(urls.iter().any(|u| u.contains("/apparel-uk/")));
    }
}
