// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
//! **Superficie RANKEADA: la capa de SELECCIÓN recon→hunt (característica #10).**
//!
//! Reimplementación propia (D9) del contrato `ranked_surface` de `Claude-BugHunter`
//! (MIT), cazado por mindalá el 2026-10-21. Ataca el cuello MEDIDO en la auditoría
//! de nexus ([[nexus-modelo-dast-equivocado-selec-es-el-cuello]]): **afinar es
//! SELECCIÓN, no recon**. Hoy el recon vuelca una lista PLANA de hosts vivos a
//! `targets_file` y el hunt los trata a todos igual; esto los ORDENA para que la
//! fase cara (nuclei/oráculos, con presupuesto anti-baneo) vaya primero a lo de
//! alto valor.
//!
//! **Embudo, no oráculo — y hay que decirlo (D16, igual que `candidatos`):** `P1`
//! = "mira esto PRIMERO", NUNCA "tiene un bug". El ranking es un hint de ORDEN
//! sobre señales públicas baratas (la URL); el discriminador real lo pone el
//! oráculo por ejecución, no esta capa.
//!
//! **Sesgo D21 INVERTIDO (como `candidatos::tipo_no_app`):** demotar a `Kill` un
//! objetivo real es un FALSO NEGATIVO = un hit perdido. Así que `Kill` es
//! CONSERVADOR: solo lo PROVABLEMENTE estático (cdn, /assets/, un archivo .css/.js).
//! Todo lo ambiguo se queda en `P2`; nunca se pierde un objetivo por duda.
//!
//! **D20:** `ranked_surface` y `assets` son campos SIEMPRE presentes —`[]` cuando
//! vacíos, nunca ausentes— y toda entrada lleva su `prioridad` (no hay "sin
//! prioridad"). El productor que no descubre una sección la deja `[]`.
//!
//! **MEDIDA, no enforce (como `elegibilidad`/`puerta_envio`):** este módulo rankea;
//! NO reescribe `targets_file` ni cambia el orden del hunt. Cablearlo en `recon`
//! (y enriquecer httpx a `-json` para llenar `status`/`title`/`tech`) es la
//! REBANADA 2, decisión aparte: hoy el recon solo captura la URL.

use serde::{Deserialize, Serialize};

/// Versión del contrato recon→hunt. Un consumidor comprueba esto antes de confiar
/// en la forma (el manifest de bughunter versiona su schema; lo conservamos).
pub const SCHEMA_VERSION: &str = "1.0";

/// Prioridad de un objetivo en la superficie. Serializa como `P1`/`P2`/`KILL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Prioridad {
    /// Alto valor: lógica sensible (api/auth/admin…) o entorno no-productivo.
    #[serde(rename = "P1")]
    P1,
    /// App genérica: se conserva y se caza, pero después de P1 (sesgo a no perder).
    #[serde(rename = "P2")]
    P2,
    /// Provablemente estático (cdn/assets/archivo): nada de lógica que cazar.
    #[serde(rename = "KILL")]
    Kill,
}

/// Un activo vivo tal como lo deja el recon. Hoy solo se conoce la `url` (httpx sin
/// `-json`); los campos ricos quedan listos para la rebanada 2 y, si están, afinan
/// el ranking. Opcionales/`Vec` por defecto para no fabricar datos (D20).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Activo {
    pub url: String,
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub tech: Vec<String>,
}

impl Activo {
    /// Constructor desde solo-URL (lo que el recon tiene hoy).
    pub fn de_url(url: impl Into<String>) -> Self {
        Self { url: url.into(), status: None, title: None, tech: Vec::new() }
    }
}

/// Un activo con su veredicto de prioridad y el porqué (para leer el ranking y
/// auditarlo). Serializable: es una entrada de `ranked_surface`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rankeado {
    pub activo: Activo,
    pub prioridad: Prioridad,
    pub rationale: String,
}

/// El manifest recon→hunt (rebanada 1: solo `ranked_surface`). `assets` queda `[]`
/// hasta que el recon enriquezca (rebanada 2); presente, nunca ausente (D20).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: String,
    pub target: String,
    pub ranked_surface: Vec<Rankeado>,
    #[serde(default)]
    pub assets: Vec<Activo>,
}

// ── Señales (puras, sobre la URL en minúsculas) ──────────────────────────────

/// Tokens de LÓGICA de alto valor: donde viven authz, cuentas, dinero, superficie
/// de API. Substring sobre la URL completa.
const ALTO_VALOR: &[&str] = &[
    "api.", "/api/", "/v1/", "/v2/", "/v3/", "graphql", "graphiql", "admin", "auth",
    "login", "oauth", "/sso", "saml", "token", "account", "dashboard", "console",
    "portal", "upload", "payment", "billing", "invoice", "checkout", "webhook",
    "internal", "password", "/reset", "user",
];

/// Tokens de entorno NO-PRODUCTIVO: alto valor porque el endurecimiento (auth,
/// rate-limit, WAF) suele estar más flojo que en producción.
const NO_PROD: &[&str] = &[
    "staging", "stage.", "dev.", "develop", "/dev", "qa.", "uat", "preprod",
    "pre-prod", "sandbox", "demo.", "beta.", "test.",
];

/// Sufijos de archivo PROVABLEMENTE estático: un recurso, no una app.
const EXT_ESTATICA: &[&str] = &[
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2",
    ".ico", ".ttf", ".map",
];

fn primer_token<'a>(url: &str, tokens: &[&'a str]) -> Option<&'a str> {
    tokens.iter().find(|t| url.contains(**t)).copied()
}

/// ¿Es PROVABLEMENTE estático? Conservador (D21): solo lo que no puede ser una app.
/// No incluye `media`/`img` (podrían ser servicios de subida = alto valor).
fn es_estatico(url: &str) -> Option<String> {
    // host cdn/static — SOLO en el HOST, no en toda la URL: `contains` sobre la URL
    // entera marcaba `KILL` un endpoint dinámico por un `cdn.`/`static.` en la ruta o el
    // query (`/report?preview=cdn.foo`, `/static.action`). Como esta capa REORDENA y no
    // filtra, el efecto era demotar un objetivo real por debajo de basura (sesgo
    // conservador roto; hallazgo del concilio 2026-11-06). Se acota al authority.
    let host = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    if host.contains("cdn.") || host.contains("static.") {
        return Some("host de CDN/estático".into());
    }
    // rutas de recursos
    for p in ["/assets/", "/static/", "/_next/static/"] {
        if url.contains(p) {
            return Some(format!("ruta de recursos estáticos ({p})"));
        }
    }
    // archivos conocidos
    for f in ["/robots.txt", "/sitemap.xml", "/favicon.ico"] {
        if url.ends_with(f) {
            return Some(format!("archivo estático ({f})"));
        }
    }
    // la URL ES un archivo estático (termina en extensión)
    let sin_query = url.split(['?', '#']).next().unwrap_or(url);
    if let Some(ext) = EXT_ESTATICA.iter().find(|e| sin_query.ends_with(**e)) {
        return Some(format!("archivo estático ({ext})"));
    }
    None
}

/// Rankea UN activo. Puro. El orden de los chequeos es el del sesgo invertido: el
/// ALTO VALOR gana primero (un `api.acme.com/static/x` sigue siendo la API), luego
/// NO-PROD, y solo si no hay señal de valor se considera `Kill` para lo estático;
/// cualquier otra cosa es `P2` (se conserva).
pub fn rankear(activo: &Activo) -> Rankeado {
    let url = activo.url.to_lowercase();
    let (prioridad, rationale) = if let Some(t) = primer_token(&url, ALTO_VALOR) {
        (Prioridad::P1, format!("superficie de alto valor ({t})"))
    } else if let Some(t) = primer_token(&url, NO_PROD) {
        (Prioridad::P1, format!("entorno no-productivo, auth suele ser más débil ({t})"))
    } else if let Some(motivo) = es_estatico(&url) {
        (Prioridad::Kill, motivo)
    } else {
        (Prioridad::P2, "app genérica; se conserva (sesgo a no perder objetivo, D21)".into())
    };
    Rankeado { activo: activo.clone(), prioridad, rationale }
}

/// Rankea y ORDENA una superficie: P1 primero, luego P2, luego Kill. El orden
/// dentro de cada grupo se conserva (estable) para ser reproducible. D20: entrada
/// vacía → salida vacía (nunca panic); toda entrada sale con prioridad.
pub fn superficie_rankeada(activos: &[Activo]) -> Vec<Rankeado> {
    let mut v: Vec<Rankeado> = activos.iter().map(rankear).collect();
    // clave de orden: P1=0, P2=1, Kill=2. sort_by_key es estable.
    v.sort_by_key(|r| match r.prioridad {
        Prioridad::P1 => 0u8,
        Prioridad::P2 => 1,
        Prioridad::Kill => 2,
    });
    v
}

/// Construye el manifest (rebanada 1). `assets` queda `[]` (D20) hasta la rebanada 2.
pub fn manifest(target: impl Into<String>, activos: &[Activo]) -> Manifest {
    Manifest {
        schema_version: SCHEMA_VERSION.to_string(),
        target: target.into(),
        ranked_surface: superficie_rankeada(activos),
        assets: Vec::new(),
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// **La pareja central (D33), por la vía real `rankear`:** alto valor → `P1`;
    /// su PAREJA estática → `Kill`; y lo ambiguo → `P2`. El mutante es el estado
    /// ACTUAL de nexus (lista plana, sin ranking): equivale a "todo P2", y con él
    /// las aserciones de P1 y Kill se caen — que es justo lo que este módulo aporta.
    #[test]
    fn rankea_alto_valor_estatico_y_generico() {
        let p1 = rankear(&Activo::de_url("https://api.acme.com/v1/users"));
        assert_eq!(p1.prioridad, Prioridad::P1, "{}", p1.rationale);

        let kill = rankear(&Activo::de_url("https://cdn.acme.com/app.bundle.js"));
        assert_eq!(kill.prioridad, Prioridad::Kill, "{}", kill.rationale);

        let p2 = rankear(&Activo::de_url("https://www.acme.com/about-us"));
        assert_eq!(p2.prioridad, Prioridad::P2, "{}", p2.rationale);
    }

    /// `cdn.`/`static.` solo matan en el HOST, no en la ruta/query (hallazgo del
    /// concilio 2026-11-06): demotar un endpoint dinámico por un `cdn.` en el query
    /// rompía el sesgo conservador. Pareja D33: host real → Kill; ruta/query → NO.
    #[test]
    fn cdn_estatico_solo_en_el_host_no_en_ruta_ni_query() {
        // Host CDN real → Kill (se conserva el comportamiento legítimo).
        assert_eq!(rankear(&Activo::de_url("https://cdn.acme.com/x")).prioridad, Prioridad::Kill);
        assert_eq!(rankear(&Activo::de_url("https://sub.static.acme.com/y")).prioridad, Prioridad::Kill);
        // `cdn.`/`static.` en la RUTA o el QUERY de un host dinámico → NO Kill (caso rojo:
        // con el `contains` sobre la URL entera, estos caían a Kill).
        let query = rankear(&Activo::de_url("https://acme.com/report?preview=cdn.foo"));
        assert_ne!(query.prioridad, Prioridad::Kill, "{}", query.rationale);
        let ruta = rankear(&Activo::de_url("https://acme.com/static.action"));
        assert_ne!(ruta.prioridad, Prioridad::Kill, "{}", ruta.rationale);
    }

    /// **Sesgo D21: el alto valor GANA sobre la pinta estática** (un `.js` servido
    /// por la API no mata la API) y lo DUDOSO nunca se mata.
    #[test]
    fn el_valor_gana_y_lo_dudoso_no_se_mata() {
        // api + ruta estática → sigue P1 (no se pierde la API).
        let api_static = rankear(&Activo::de_url("https://api.acme.com/static/swagger.js"));
        assert_eq!(api_static.prioridad, Prioridad::P1);
        // 'media.' es ambiguo (¿subida?) → NO se mata, queda P2 (falso-negativo evitado).
        let media = rankear(&Activo::de_url("https://media.acme.com/"));
        assert_eq!(media.prioridad, Prioridad::P2);
        // no-prod → P1 por auth más débil.
        let staging = rankear(&Activo::de_url("https://staging.acme.com/"));
        assert_eq!(staging.prioridad, Prioridad::P1);
    }

    /// `superficie_rankeada` ORDENA P1→P2→Kill (estable) y es D20-safe con vacío.
    #[test]
    fn ordena_p1_primero_y_vacio_no_panica() {
        let activos = vec![
            Activo::de_url("https://www.acme.com/"),         // P2
            Activo::de_url("https://cdn.acme.com/a.css"),    // Kill
            Activo::de_url("https://admin.acme.com/login"),  // P1
        ];
        let r = superficie_rankeada(&activos);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].prioridad, Prioridad::P1, "P1 va primero");
        assert_eq!(r[2].prioridad, Prioridad::Kill, "Kill va último");
        // D20: vacío → vacío, no panic.
        assert!(superficie_rankeada(&[]).is_empty());
    }

    /// **Cruza la frontera del programa (D28/D20): el manifest serializa a JSON con
    /// `ranked_surface` y `assets` PRESENTES —`[]` cuando vacíos, nunca ausentes—.**
    /// Es el contrato que un consumidor leería; si `assets` desapareciera del JSON
    /// al estar vacío, el consumidor no distinguiría "no descubierto" de "no existe".
    #[test]
    fn manifest_serializa_con_campos_presentes() {
        let m = manifest("acme.com", &[Activo::de_url("https://api.acme.com/v1")]);
        let j = serde_json::to_string(&m).unwrap();
        assert!(j.contains("\"schema_version\":\"1.0\""));
        assert!(j.contains("\"P1\""));
        assert!(j.contains("\"assets\":[]"), "assets presente y vacío (D20): {j}");
        // round-trip: se puede volver a leer.
        let m2: Manifest = serde_json::from_str(&j).unwrap();
        assert_eq!(m2.ranked_surface.len(), 1);
    }
}
