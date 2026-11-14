// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Juan Carlos Isaza
//! CANDIDATOS — selección y triaje de OSS joven para el carril whitebox de CÓDIGO-FUENTE.
//!
//! La capa que la auditoría del 2026-10-21 (`conocimiento/objetivos/AUDITORIA-NEXUS-METODOS-2026-10-21.md`)
//! encontró AUSENTE en nexus: todo nexus es live-DAST (programa→subfinder/httpx→nuclei), el modelo
//! medido como seco (efecto brain, 0). Los 6 hallazgos reales salieron de whitebox de código-fuente
//! sobre OSS joven, hecho A MANO con `curl` a la API de GitHub. Esto persiste ese método.
//!
//! **Es un EMBUDO, no un oráculo — y hay que decirlo (D16/D20).** El discriminador medido
//! hit-vs-seco es la COBERTURA del control (¿el check existe Y está cableado en TODA la superficie?),
//! y eso SOLO se ve leyendo el código (puerta 0 / razonador). Ningún metadato lo predice: libredesk
//! pasó todos los filtros baratos y solo salió seco TRAS la lectura. Lo que este módulo hace es
//! ESTRECHAR el pool con filtros públicos baratos para que la lectura cara vaya a mejores
//! probabilidades. `Perseguir` = "vale una lectura puerta-0", NUNCA "tiene un bug".
//!
//! **Guardrail (D37 / `no-repetir-el-cazador-autonomo`): SELECCIONA y TRÍA, nunca encuentra-y-envía.**
//! Solo lee metadatos PÚBLICOS (search API + advisories). No clona, no escanea, no ataca, no reporta.
//! Keyless (API de GitHub sin auth; rate-limit respetado con espera).

use anyhow::{Context, Result};
use serde::Deserialize;
use std::time::Duration;

const SEARCH_URL: &str = "https://api.github.com/search/repositories";
const API: &str = "https://api.github.com";

/// CWE de la clase AUTHZ (la que cazamos). 0 avisos AQUÍ = control de acceso nunca escrutado
/// (buen terreno), aunque el repo tenga avisos de OTRA clase (XSS/SSRF) — ese es el caso libredesk.
const CWE_AUTHZ: &[&str] = &[
    "cwe-862", "cwe-863", "cwe-639", "cwe-285", "cwe-284", "cwe-266", "cwe-269", "cwe-668",
    "cwe-732", "cwe-306", "cwe-640", "cwe-1220",
];
/// Palabras de authz en el summary, por si el aviso no trae CWE mapeado.
const KW_AUTHZ: &[&str] = &[
    "authorization", "authz", "access control", "broken access", "idor", "bola", "privilege",
    "permission", "unauthorized", "improper access", "cross-tenant", "cross tenant",
];
/// Señales de dominio con dato de DINERO/PII (impacto real → el vendor corrige, divulgación limpia).
const KW_NEGOCIO: &[&str] = &[
    "billing", "invoic", "payment", "subscription", "crm", "erp", "payroll", "patient",
    "clinic", "health", "medical", "booking", "appointment", "ticket", "helpdesk", "support desk",
    "ecommerce", "e-commerce", "commerce", "order", "customer", "tenant", "saas", "hrm",
    "human resource", "inventory", "pos", "lms", "learning", "scheduling",
];

/// Umbral de "sobre-auditado": tantos o más avisos totales = terreno quemado (p.ej. pelican/panel=10).
const SOBRE_AUDITADO: usize = 9;

/// Un repositorio tal como lo devuelve la search API (solo los campos que miramos).
#[derive(Debug, Clone, Deserialize)]
pub struct Repo {
    pub full_name: String,
    #[serde(default)]
    pub stargazers_count: u64,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub pushed_at: String,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub owner: Owner,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Owner {
    #[serde(default)]
    pub login: String,
    /// "User" | "Organization".
    #[serde(rename = "type", default)]
    pub tipo: String,
}

#[derive(Deserialize)]
struct SearchResp {
    #[serde(default)]
    items: Vec<Repo>,
    #[serde(default)]
    message: Option<String>,
}

/// Un aviso de seguridad publicado (security-advisories del repo).
#[derive(Deserialize)]
struct Advisory {
    #[serde(default)]
    cwes: Vec<Cwe>,
    #[serde(default)]
    summary: Option<String>,
}
#[derive(Deserialize)]
struct Cwe {
    #[serde(default)]
    cwe_id: String,
}

/// Veredicto de EMBUDO: prioridad para la lectura puerta-0, no predicción de hallazgo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Veredicto {
    /// Vale una lectura puerta-0 (mejores probabilidades por los filtros baratos).
    Perseguir,
    /// Marginal: léelo solo si no hay nada mejor en la cola.
    Mirar,
    /// Descartar sin leer (sobre-auditado / no-joven / sin dato de negocio / en lista negra).
    Evitar,
}

impl Veredicto {
    pub fn etiqueta(self) -> &'static str {
        match self {
            Veredicto::Perseguir => "PERSEGUIR",
            Veredicto::Mirar => "mirar",
            Veredicto::Evitar => "evitar",
        }
    }
}

/// Un candidato triado: el repo más los discriminadores baratos y el veredicto de embudo.
#[derive(Debug, Clone)]
pub struct Candidato {
    pub repo: Repo,
    pub ghsa_total: usize,
    pub ghsa_authz: usize,
    pub negocio: bool,
    pub joven: bool,
    pub sobre_auditado: bool,
    pub en_negra: bool,
    pub puntaje: i32,
    pub veredicto: Veredicto,
    pub motivos: Vec<String>,
}

/// ¿El aviso pertenece a la clase authz? Por CWE mapeado o, en su defecto, por palabra en el summary.
pub fn es_authz(cwe_ids: &[String], summary: &str) -> bool {
    for c in cwe_ids {
        if CWE_AUTHZ.contains(&c.to_ascii_lowercase().as_str()) {
            return true;
        }
    }
    let s = summary.to_ascii_lowercase();
    KW_AUTHZ.iter().any(|k| s.contains(k))
}

/// ¿La descripción señala un dominio con dato de dinero/PII?
pub fn senal_negocio(desc: &str) -> bool {
    let d = desc.to_ascii_lowercase();
    KW_NEGOCIO.iter().any(|k| d.contains(k))
}

/// Señales FUERTES de que el repo NO es una app web multi-tenant AUDITABLE: research de un paper,
/// librería/SDK/CLI, wrapper/scraper/automatización de pruebas, cliente de escritorio, o repo-demo.
/// Devuelve `Some(motivo)` solo con marcador fuerte.
///
/// **Sesgo D21 INVERTIDO, y es el punto**: aquí cerrar de más = EXCLUIR una app real = falso negativo
/// = perder un hit (los 6 hits eran apps). Por eso es CONSERVADOR: lo ambiguo (p.ej. "AI customer
/// support", "enterprise search") NO se marca y sigue al puntaje normal. **Medido contra la 1ª corrida
/// (2026-10-21)**: 11/23 PERSEGUIR no eran apps (research que casó "language models", SDKs, demos,
/// scripts); este filtro mata 9/11 con 0 falsos positivos sobre los hits/apps reales del corpus. Las 2
/// que sobreviven (nombres de modelo bespoke) caen del lado seguro: se leen, no se pierden.
pub fn tipo_no_app(repo: &Repo) -> Option<String> {
    let d = repo.description.as_deref().unwrap_or("").to_ascii_lowercase();
    let name = repo.full_name.rsplit('/').next().unwrap_or("").to_ascii_lowercase();

    if repo.language.as_deref().unwrap_or("").eq_ignore_ascii_case("Jupyter Notebook") {
        return Some("notebook de research, no app".into());
    }

    // (token-en-descripción, motivo). Marcadores FUERTES, no meras menciones de "AI".
    const DESC_NO_APP: &[(&str, &str)] = &[
        ("official implementation", "research (implementación de paper)"),
        ("official code", "research (código de paper)"),
        ("retrieval-augmented", "research (modelo/LM)"),
        ("[iclr", "research (paper ICLR)"),
        ("[cvpr", "research (paper CVPR)"),
        ("[neurips", "research (paper NeurIPS)"),
        ("[acl ", "research (paper ACL)"),
        ("[emnlp", "research (paper EMNLP)"),
        ("arxiv", "research (arXiv)"),
        ("diffusion model", "research (modelo)"),
        ("diffusion language", "research (modelo)"),
        ("language models", "research (modelos de lenguaje, no app)"),
        ("mcp server", "servidor MCP / SDK, no app"),
        ("agent skills", "pack de skills de agente, no app"),
        ("command-line", "CLI, no app web"),
        ("command line", "CLI, no app web"),
        (" cli", "CLI, no app web"),
        ("api wrapper", "wrapper de API, no app"),
        ("client library", "librería cliente, no app"),
        ("bindings for", "bindings, no app"),
        ("scraping", "scraper, no app"),
        ("scraper", "scraper, no app"),
        ("crawler", "crawler, no app"),
        ("cypress", "automatización de pruebas, no app"),
        ("selenium", "automatización de pruebas, no app"),
        ("test automation", "automatización de pruebas, no app"),
        ("automation in", "script de automatización, no app"),
        ("browser automation", "automatización de navegador, no app"),
        ("javafx", "app de escritorio, no web"),
        ("desktop app", "app de escritorio, no web"),
        ("desktop application", "app de escritorio, no web"),
        ("for managed macs", "cliente de dispositivo, no app web"),
        ("menu bar app", "app de escritorio, no web"),
        ("vertical slice", "repo-demo de arquitectura, no app real"),
        ("event sourcing", "repo-demo de arquitectura, no app real"),
        ("boilerplate", "boilerplate/plantilla, no app"),
        ("reference implementation", "implementación de referencia/demo"),
        ("showcase", "showcase/demo, no app real"),
    ];
    for (tok, motivo) in DESC_NO_APP {
        if d.contains(tok) {
            return Some((*motivo).to_string());
        }
    }

    // Marcadores en el NOMBRE (sufijos y subcadenas típicos de librería/SDK/CLI/demo).
    const NAME_SUFIJO: &[&str] = &["-sdk", "-cli", "-js", "-python", "-py", "-ts", "-bindings"];
    const NAME_SUB: &[&str] =
        &["cypress", "selenium", "-automation", "boilerplate", "-demo", "-example", "-sample"];
    if NAME_SUFIJO.iter().any(|s| name.ends_with(s)) || NAME_SUB.iter().any(|s| name.contains(s)) {
        return Some(format!("nombre de librería/SDK/demo (`{name}`)"));
    }
    None
}

/// ¿El repo es "joven" (creado dentro de los últimos `anios` respecto a `anio_hoy`)?
/// Lee el año del prefijo ISO de `created_at` ("2024-05-12T…"). Sin fecha parseable → NO joven
/// (fail-ruidoso, D20: un dato ausente no se sustituye por "sí").
pub fn es_joven(created_at: &str, anios: i64, anio_hoy: i64) -> bool {
    match created_at.get(0..4).and_then(|y| y.parse::<i64>().ok()) {
        Some(anio) => anio >= anio_hoy - anios,
        None => false,
    }
}

/// ¿`full_name`/owner aparece en el texto de la LISTA-NEGRA? (match crudo por substring, sin filtros:
/// la lección `grep-filtrado-oculta-el-positivo` — no ocultar el positivo con un `grep -v`.)
pub fn en_lista_negra(full_name: &str, owner: &str, negra: &str) -> bool {
    let n = negra.to_ascii_lowercase();
    let full = full_name.to_ascii_lowercase();
    if n.contains(&full) {
        return true;
    }
    // Para el repo y el owner, exige FRONTERA (backtick, **, espacios, barra) para no casar
    // subcadenas accidentales. Un miss solo re-ofrece un candidato; un FP lo oculta → sesgo a no-FP.
    let repo = full_name.rsplit('/').next().unwrap_or(full_name);
    for needle in [repo, owner] {
        let x = needle.to_ascii_lowercase();
        if x.is_empty() {
            continue;
        }
        if n.contains(&format!("`{x}`"))
            || n.contains(&format!("**{x}**"))
            || n.contains(&format!(" {x} "))
            || n.contains(&format!("{x}/"))
            || n.contains(&format!("/{x}"))
        {
            return true;
        }
    }
    false
}

/// Puntúa el candidato como EMBUDO (prioridad de lectura), con los pesos de los filtros MEDIDOS.
/// Devuelve (puntaje, veredicto, motivos). NO modela competencia del mantenedor desde metadatos:
/// está medido que no se puede (libredesk ⭐3063 user = seco; django-crm ⭐633 = hit).
pub fn puntuar(
    repo: &Repo,
    ghsa_total: usize,
    ghsa_authz: usize,
    negocio: bool,
    joven: bool,
    en_negra: bool,
) -> (i32, Veredicto, Vec<String>) {
    let mut motivos = Vec::new();

    // Puertas duras → Evitar sin leer.
    if en_negra {
        return (-100, Veredicto::Evitar, vec!["en LISTA-NEGRA".into()]);
    }
    if repo.archived {
        return (-100, Veredicto::Evitar, vec!["archivado".into()]);
    }
    if !joven {
        return (-100, Veredicto::Evitar, vec!["no joven (code-base viejo = authz ya endurecida)".into()]);
    }
    // Puerta de TIPO: un no-app (research/SDK/CLI/scraper/demo/escritorio) no tiene superficie de
    // authz multi-tenant que leer. Conservador (solo señal fuerte) para no excluir una app real.
    if let Some(motivo) = tipo_no_app(repo) {
        return (-100, Veredicto::Evitar, vec![format!("no es app web auditable: {motivo}")]);
    }

    let sobre_auditado = ghsa_total >= SOBRE_AUDITADO;
    let mut p: i32 = 0;

    if negocio {
        p += 3;
        motivos.push("dato de dinero/PII (impacto → vendor corrige)".into());
    } else {
        p -= 2;
        motivos.push("sin señal de dato de negocio".into());
    }

    if ghsa_authz == 0 {
        p += 2;
        motivos.push("0 avisos en la CLASE authz (control de acceso sin escrutar)".into());
    } else {
        p -= 4;
        motivos.push(format!("{ghsa_authz} aviso(s) authz previos (clase ya parcheada → endurecida)"));
    }

    if sobre_auditado {
        p -= 5;
        motivos.push(format!("sobre-auditado ({ghsa_total} avisos totales)"));
    } else if ghsa_total >= 1 {
        // Tiene canal/atención de seguridad PERO authz virgen = situación libredesk (buen terreno).
        p += 1;
        motivos.push(format!("{ghsa_total} aviso(s) NO-authz (canal activo, authz aún virgen)"));
    }

    // Estrellas: señal DÉBIL (medido), solo banda suave. Muy pocas = posible toy sin usuarios/impacto;
    // muchísimas = probablemente muy auditado.
    match repo.stargazers_count {
        0..=49 => {
            p -= 1;
            motivos.push("muy pocas estrellas (¿toy sin usuarios reales?)".into());
        }
        50..=6000 => p += 1,
        _ => {
            p -= 1;
            motivos.push("muchas estrellas (probable mayor escrutinio)".into());
        }
    }

    let v = if p >= 5 {
        Veredicto::Perseguir
    } else if p >= 1 {
        Veredicto::Mirar
    } else {
        Veredicto::Evitar
    };
    (p, v, motivos)
}

/// Busca repos jóvenes de un dominio en la search API (keyless). `lang` opcional.
pub async fn buscar(
    client: &reqwest::Client,
    dominio: &str,
    lang: Option<&str>,
    anios: i64,
    anio_hoy: i64,
    por_pagina: usize,
) -> Result<Vec<Repo>> {
    let desde = anio_hoy - anios;
    let mut q = format!("{dominio} stars:50..6000 created:>={desde}-01-01");
    if let Some(l) = lang {
        q.push_str(&format!(" language:{l}"));
    }
    let pp = por_pagina.to_string();
    let resp: SearchResp = client
        .get(SEARCH_URL)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .query(&[("q", q.as_str()), ("sort", "stars"), ("order", "desc"), ("per_page", pp.as_str())])
        .send()
        .await
        .with_context(|| format!("search `{dominio}`"))?
        .json()
        .await
        .with_context(|| format!("parseando search `{dominio}`"))?;
    if let Some(m) = resp.message {
        anyhow::bail!("GitHub search rechazó `{dominio}`: {m} (¿rate-limit? keyless = 10/min)");
    }
    Ok(resp.items)
}

/// Cuenta los avisos de seguridad de un repo: (total, de-la-clase-authz). Keyless.
/// 404/sin avisos = (0,0): un repo sin advisories es buen terreno, no un error.
pub async fn contar_avisos(client: &reqwest::Client, full_name: &str) -> Result<(usize, usize)> {
    let url = format!("{API}/repos/{full_name}/security-advisories?per_page=100");
    let r = client
        .get(&url)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .with_context(|| format!("advisories `{full_name}`"))?;
    if !r.status().is_success() {
        // 404 (sin advisories habilitados) u otro: trata como 0, pero DÍLO en el motivo aguas arriba.
        return Ok((0, 0));
    }
    let avisos: Vec<Advisory> = r.json().await.unwrap_or_default();
    let total = avisos.len();
    let authz = avisos
        .iter()
        .filter(|a| {
            let ids: Vec<String> = a.cwes.iter().map(|c| c.cwe_id.clone()).collect();
            es_authz(&ids, a.summary.as_deref().unwrap_or(""))
        })
        .count();
    Ok((total, authz))
}

/// Tría una tanda de repos: cuenta avisos (una llamada por repo), cruza lista negra, puntúa.
/// Espera `jitter` entre llamadas de avisos para no reventar el rate-limit core (60/h keyless).
pub async fn triar(
    client: &reqwest::Client,
    repos: Vec<Repo>,
    negra: &str,
    anios: i64,
    anio_hoy: i64,
    jitter: Duration,
) -> Vec<Candidato> {
    let mut out = Vec::with_capacity(repos.len());
    for repo in repos {
        let (ghsa_total, ghsa_authz) = contar_avisos(client, &repo.full_name).await.unwrap_or((0, 0));
        let negocio = senal_negocio(repo.description.as_deref().unwrap_or(""));
        let joven = es_joven(&repo.created_at, anios, anio_hoy);
        let en_negra = en_lista_negra(&repo.full_name, &repo.owner.login, negra);
        let (puntaje, veredicto, motivos) =
            puntuar(&repo, ghsa_total, ghsa_authz, negocio, joven, en_negra);
        out.push(Candidato {
            repo,
            ghsa_total,
            ghsa_authz,
            negocio,
            joven,
            sobre_auditado: ghsa_total >= SOBRE_AUDITADO,
            en_negra,
            puntaje,
            veredicto,
            motivos,
        });
        if !jitter.is_zero() {
            tokio::time::sleep(jitter).await;
        }
    }
    out.sort_by_key(|c| std::cmp::Reverse(c.puntaje));
    out
}

/// Informe markdown para el bucle razonador: tabla + por-candidato con sus motivos.
pub fn informe_md(candidatos: &[Candidato]) -> String {
    let mut d = String::new();
    d.push_str("# Candidatos OSS — carril whitebox de código-fuente\n\n");
    d.push_str(
        "> **Embudo, NO oráculo.** `PERSEGUIR` = vale una lectura puerta-0 (mejores probabilidades \
         por filtros baratos), NUNCA \"tiene un bug\". El discriminador real (cobertura del control) \
         solo se ve leyendo el código. Generado por `nexus candidatos` — keyless, selecciona y tría, \
         no encuentra-y-envía.\n\n",
    );
    d.push_str("| veredicto | repo | ⭐ | creado | lang | authz-GHSA / total | negocio |\n");
    d.push_str("|---|---|--:|---|---|---|:-:|\n");
    for c in candidatos {
        d.push_str(&format!(
            "| {} | {} | {} | {} | {} | {}/{} | {} |\n",
            c.veredicto.etiqueta(),
            c.repo.full_name,
            c.repo.stargazers_count,
            c.repo.created_at.get(0..7).unwrap_or(""),
            c.repo.language.as_deref().unwrap_or("?"),
            c.ghsa_authz,
            c.ghsa_total,
            if c.negocio { "sí" } else { "no" },
        ));
    }
    d.push_str("\n## Detalle\n\n");
    for c in candidatos {
        d.push_str(&format!(
            "### {} — {} (puntaje {})\n- {}\n- {}\n\n",
            c.veredicto.etiqueta(),
            c.repo.full_name,
            c.puntaje,
            c.repo.description.as_deref().unwrap_or("(sin descripción)"),
            c.motivos.join("\n- "),
        ));
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(full_name: &str, stars: u64, creado: &str, desc: &str, owner_tipo: &str) -> Repo {
        Repo {
            full_name: full_name.into(),
            stargazers_count: stars,
            created_at: creado.into(),
            pushed_at: creado.into(),
            language: Some("Go".into()),
            description: Some(desc.into()),
            archived: false,
            owner: Owner { login: full_name.split('/').next().unwrap().into(), tipo: owner_tipo.into() },
        }
    }

    // ---- es_authz: la pareja (D33) ----
    #[test]
    fn authz_por_cwe_y_palabra_si_no_canonico() {
        assert!(es_authz(&["CWE-862".into()], "whatever"), "CWE-862 es authz");
        assert!(es_authz(&["CWE-639".into()], ""), "IDOR/CWE-639 es authz");
        assert!(es_authz(&[], "Broken access control in reports"), "palabra authz");
        // el caso que TIENE que NO ver: XSS/SSRF NO son authz (el caso libredesk)
        assert!(!es_authz(&["CWE-80".into()], "HTML injection"), "XSS no es authz");
        assert!(!es_authz(&["CWE-918".into()], "SSRF in webhooks"), "SSRF no es authz");
    }

    #[test]
    fn negocio_discrimina() {
        assert!(senal_negocio("Open-source self-hosted customer support desk"));
        assert!(senal_negocio("usage-based billing platform"));
        // control: una utilidad sin dato de negocio
        assert!(!senal_negocio("ZFS management GUI for Linux"));
        assert!(!senal_negocio("terminal markdown renderer"));
    }

    #[test]
    fn joven_lee_el_anio_y_falla_ruidoso() {
        assert!(es_joven("2024-05-12T00:00:00Z", 3, 2026));
        assert!(!es_joven("2019-01-01T00:00:00Z", 3, 2026), "2019 no es joven en 2026 con ventana 3");
        assert!(!es_joven("", 3, 2026), "sin fecha → no joven (D20)");
        assert!(!es_joven("basura", 3, 2026), "fecha no parseable → no joven");
    }

    #[test]
    fn lista_negra_casa_sin_ocultar_positivo() {
        let negra = "## Descartados\n- **pelican** FUERA (10 advisories)\n- someorg/ancientthing AUTHZ-AGOTADO\n";
        assert!(en_lista_negra("pelican/panel", "pelican", negra));
        assert!(en_lista_negra("someorg/ancientthing", "someorg", negra));
        assert!(!en_lista_negra("abhinavxd/libredesk", "abhinavxd", negra), "no en negra");
    }

    // ---- puntuar: VERDAD-TERRENO del corpus (D33 — el embudo discrimina) ----
    // El embudo NO predice hit-vs-seco (eso es la lectura); valida que INCLUYE los hits y
    // EXCLUYE lo claramente no-candidato (sobre-auditado / no-negocio / no-joven / negra).

    #[test]
    fn positivo_los_hits_pasan_el_embudo() {
        // django-crm: CRM, ⭐633, joven, 0 GHSA → debe PERSEGUIR
        let r = repo("DjangoCRM/django-crm", 633, "2024-02-01T00:00:00Z", "CRM customer relationship management", "Organization");
        let (p, v, _) = puntuar(&r, 0, 0, senal_negocio(r.description.as_deref().unwrap()), true, false);
        assert_eq!(v, Veredicto::Perseguir, "django-crm (hit real) debe perseguirse, puntaje {p}");

        // TimeTracker: time-tracking+invoicing, joven, 0 GHSA → PERSEGUIR
        let r = repo("DRYTRIX/TimeTracker", 120, "2024-06-01T00:00:00Z", "time tracking and invoicing", "Organization");
        let (p, v, _) = puntuar(&r, 0, 0, senal_negocio(r.description.as_deref().unwrap()), true, false);
        assert_eq!(v, Veredicto::Perseguir, "TimeTracker (hit real) debe perseguirse, puntaje {p}");
    }

    #[test]
    fn el_caso_libredesk_pasa_el_embudo_aunque_sea_seco() {
        // libredesk: ⭐3063, joven, 2 GHSA NO-authz (XSS, SSRF), helpdesk → el embudo lo PERSIGUE
        // (correcto: tenía que leerse; salió seco SOLO tras la lectura — el embudo no adivina).
        let r = repo("abhinavxd/libredesk", 3063, "2024-05-12T00:00:00Z", "self-hosted customer support desk", "User");
        let (p, v, _) = puntuar(&r, 2, 0, senal_negocio(r.description.as_deref().unwrap()), true, false);
        assert_eq!(v, Veredicto::Perseguir, "libredesk debía entrar a lectura (no se predice seco), puntaje {p}");
    }

    #[test]
    fn negativo_sobre_auditado_se_evita() {
        // pelican/panel: 10 advisories = sobre-auditado → EVITAR aunque sea joven y de negocio
        let r = repo("pelican/panel", 2316, "2024-03-01T00:00:00Z", "game server management panel", "Organization");
        let (p, v, m) = puntuar(&r, 10, 1, senal_negocio(r.description.as_deref().unwrap()), true, false);
        assert_eq!(v, Veredicto::Evitar, "pelican (10 avisos) debe evitarse, puntaje {p}");
        assert!(m.iter().any(|x| x.contains("sobre-auditado")));
    }

    #[test]
    fn negativo_authz_previo_hunde() {
        // repo joven de negocio PERO con un CVE de authz previo = clase endurecida → no perseguir
        let r = repo("x/hardened", 500, "2024-01-01T00:00:00Z", "multi-tenant billing saas", "Organization");
        let (_, v, _) = puntuar(&r, 3, 2, true, true, false);
        assert_ne!(v, Veredicto::Perseguir, "authz ya parcheada no debe ser prioridad");
    }

    // ---- tipo_no_app: la pareja (D33), descripciones REALES de la corrida 2026-10-21 ----
    #[test]
    fn no_app_excluye_research_sdk_scraper_demo_desktop() {
        let casos = [
            ("AkariAsai/OpenScholar", "official implementation of OpenScholar: Synthesizing Scientific Literature with Retrieval-augmented LMs"),
            ("kuleshov-group/bd3lms", "[ICLR 2025 Oral] Block Diffusion: Interpolating Between Autoregressive and Diffusion Language Models"),
            ("LetsFG/LetsFG", "Agent-native flight & hotel search and booking — MCP server, CLI, and Python/JS SDKs"),
            ("evangelosvlachos96-dotcom/booking-microservices", "Flight booking system built as .NET microservices with Vertical Slice Architecture, DDD, CQRS, Event Sourcing"),
            ("ScrapingBee/google-hotels-api", "Automate scraping hotel data including pricing, availability, ratings"),
            ("shivamguys/irctc-cypress-automation", "Tatkal and Normal train Booking Automation in 1 Minute"),
            ("MUdevelops/SmartBiz-ERP", "A JavaFX-based desktop ERP system for managing employees, payroll"),
            ("lmstudio-ai/lmstudio-js", "LM Studio TypeScript SDK"),
        ];
        for (n, desc) in casos {
            let r = repo(n, 500, "2025-01-01T00:00:00Z", desc, "User");
            assert!(tipo_no_app(&r).is_some(), "{n} debe marcarse NO-app");
            // con dato de negocio, joven y 0 authz igual se EVITA por tipo (no hay superficie que leer)
            let (_, v, _) = puntuar(&r, 0, 0, true, true, false);
            assert_eq!(v, Veredicto::Evitar, "{n} (no-app) debe evitarse por la puerta de tipo");
        }
    }

    #[test]
    fn no_app_no_marca_apps_reales() {
        // CONTROL (D33): apps reales NO se excluyen — un falso negativo aquí = perder un hit.
        // Incluye los 2 hits (django-crm, TimeTracker) y el seco-tras-lectura (libredesk).
        let apps = [
            ("classroomio/classroomio", "Intelligent Customer Training Platform that helps SaaS companies use education to grow"),
            ("mirza-rizvi/ResolveHQ", "Self-hosted helpdesk on Cloudflare Workers. Shared inbox, email threading, AI assist"),
            ("nateherkai/snagtime", "Free self-hostable scheduling app with booking links and Stripe test payments"),
            ("Bytedesk/bytedesk", "Open source IM with AI powered live-chat, email, ticket support, omni-channel customer service"),
            ("huabeitech/agent-desk", "Open-source AI customer support system. AI-first support, human-ready operations"),
            ("GerevAI/gerev", "AI-powered enterprise search engine"),
            ("DjangoCRM/django-crm", "CRM customer relationship management"),
            ("DRYTRIX/TimeTracker", "time tracking and invoicing"),
            ("abhinavxd/libredesk", "self-hosted customer support desk"),
        ];
        for (n, desc) in apps {
            let r = repo(n, 500, "2025-01-01T00:00:00Z", desc, "User");
            assert!(tipo_no_app(&r).is_none(), "{n} es app real, NO debe marcarse no-app");
        }
    }

    #[test]
    fn no_app_por_lenguaje_notebook() {
        let mut r = repo("x/research", 500, "2025-01-01T00:00:00Z", "fancy pipeline", "User");
        r.language = Some("Jupyter Notebook".into());
        assert!(tipo_no_app(&r).is_some(), "Jupyter Notebook = research, no app");
    }

    #[test]
    fn puertas_duras() {
        let r = repo("x/viejo", 500, "2015-01-01T00:00:00Z", "billing saas", "Organization");
        // no joven
        assert_eq!(puntuar(&r, 0, 0, true, false, false).1, Veredicto::Evitar);
        // en negra
        assert_eq!(puntuar(&r, 0, 0, true, true, true).1, Veredicto::Evitar);
    }
}
