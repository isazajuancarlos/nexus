//! Submitter (F6): genera informes por hallazgo listos para pegar en HackerOne,
//! con justificación técnica, impacto y vector CVSS por tipo. Portado de
//! `submitter.py` (VULN_TECHNICAL_INFO + save_report_to_disk). No conecta a
//! ninguna API — solo escribe archivos a `manual_reports/`.

use crate::certificado::Certificado;

/// Construye el certificado anti-slop del grupo a partir de sus endpoints
/// verificados (2026-09-05). Toma el endpoint verificado como fuente de los
/// hechos discriminantes; la evidencia cuenta solo si es no vacía.
fn certificado_de(vuln_type: &str, verified: &[&Endpoint]) -> Certificado {
    let poc = verified.first();
    Certificado {
        execution_confirmed: verified.iter().any(|e| e.execution_confirmed),
        repro_ratio: verified.iter().find_map(|e| e.repro_ratio.clone()),
        // Confirmado por oráculo DIFERENCIAL (control +/− por construcción) cuando lo
        // verificó una de esas herramientas: `autz` (diferencial de identidad),
        // `oob` (callback = positivo por construcción), `content_check` (SSRF in-band
        // con control). Estas clases no dan `n/n` y su control es la confirmación
        // misma (directiva 32); sin esto el edge IDOR/BAC quedaría sin certificado.
        diferencial: verified
            .iter()
            .any(|e| es_oraculo_diferencial(e.tool.as_deref())),
        evidencia_presente: verified
            .iter()
            .any(|e| e.evidence.as_deref().map(|s| !s.trim().is_empty()).unwrap_or(false)),
        herramienta: poc.and_then(|e| e.tool.clone()),
        confianza: poc.and_then(|e| e.confidence.clone()),
        clase: vuln_type.to_string(),
        ancla: format!("nexus v{}", env!("CARGO_PKG_VERSION")),
    }
}

/// Herramientas cuya verificación ES un control diferencial (positivo Y negativo)
/// por construcción, no una repetición: no producen `n/n` y no deben exigirlo.
fn es_oraculo_diferencial(tool: Option<&str>) -> bool {
    matches!(
        tool.map(|t| t.trim().to_lowercase()).as_deref(),
        Some("autz") | Some("oob") | Some("content_check")
    )
}

/// Información técnica por tipo de vulnerabilidad.
pub struct TechInfo {
    pub justification: &'static str,
    pub impact: &'static str,
    pub cvss: &'static str,
}

/// Devuelve la ficha técnica del tipo (o el genérico si no se reconoce).
pub fn tech_info(vuln_type: &str) -> TechInfo {
    match vuln_type.to_lowercase().as_str() {
        "sqli" => TechInfo {
            justification: "La inyección SQL ocurre cuando entrada del usuario se incorpora a consultas SQL sin sanitización ni parametrización. Se detectaron parámetros inyectables por mensajes de error de base de datos, diferencias booleanas en la respuesta o retardos temporales.",
            impact: "- **Fuga de datos**: extracción de credenciales, PII y datos de negocio\n- **Bypass de autenticación**: acceso no autorizado saltando el login\n- **Manipulación de datos**: INSERT/UPDATE/DELETE no autorizados\n- **Escalada de privilegios**: funciones de administración de BD accesibles\n- **RCE**: en algunas configuraciones (xp_cmdshell, LOAD_FILE)",
            cvss: "CVSS 3.1: 9.8 (Critical) - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
        "xss" => TechInfo {
            justification: "Se confirmó XSS inyectando payloads JavaScript que se ejecutan en el contexto del navegador. La entrada se refleja o almacena sin codificación de entidades HTML ni CSP.",
            impact: "- **Secuestro de sesión**: robo de cookies e impersonación\n- **Robo de credenciales**: formularios de login falsos\n- **Distribución de malware**: redirección a sitios maliciosos\n- **Defacement**: modificación del contenido\n- **Keylogging**: captura de pulsaciones",
            cvss: "CVSS 3.1: 6.1 (Medium) - AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        },
        "cmdi" => TechInfo {
            justification: "Se verificó inyección de comandos inyectando separadores del SO (;, |, &&) seguidos de comandos de diagnóstico. La entrada llega a intérpretes de shell sin sanitización.",
            impact: "- **Compromiso total del sistema**: acceso shell al servidor\n- **Exfiltración de datos**: todos los archivos y BD accesibles\n- **Movimiento lateral**: ataque a la red interna\n- **Ransomware**: cifrado del sistema\n- **Cryptomining**: secuestro de recursos",
            cvss: "CVSS 3.1: 9.8 (Critical) - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
        "ssrf" => TechInfo {
            justification: "Se identificó SSRF cuando la aplicación solicita URLs controladas por el atacante desde el servidor, confirmado por peticiones a dominios canary o acceso a recursos internos.",
            impact: "- **Escaneo de red interna**: mapeo de infraestructura\n- **Acceso a metadatos cloud**: robo de credenciales AWS/GCP/Azure\n- **Bypass de firewall**: servicios internos accesibles\n- **Exfiltración**: consulta de BD/APIs internas",
            cvss: "CVSS 3.1: 9.1 (Critical) - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        },
        "lfi" => TechInfo {
            justification: "Se confirmó LFI/Path Traversal manipulando parámetros de ruta para acceder a archivos fuera del directorio previsto (p. ej. /etc/passwd) mediante secuencias de traversal.",
            impact: "- **Divulgación de código fuente**\n- **Exposición de configuración**: credenciales de BD, claves API\n- **Acceso a logs sensibles**\n- **RCE**: vía log poisoning o wrappers PHP\n- **Robo de credenciales**: /etc/shadow",
            cvss: "CVSS 3.1: 7.5 (High) - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        },
        "rce" => TechInfo {
            justification: "Se verificó RCE ejecutando código arbitrario en el servidor, confirmado por análisis de respuesta, retardos o callbacks out-of-band.",
            impact: "- **Toma total del sistema**\n- **Fuga de datos**: todo lo que procesa la aplicación\n- **Ataque a cadena de suministro**\n- **Persistencia**: instalación de backdoors\n- **Violaciones regulatorias**: GDPR, HIPAA, PCI-DSS",
            cvss: "CVSS 3.1: 9.8 (Critical) - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
        "redirect" => TechInfo {
            justification: "Se confirmó Open Redirect inyectando URLs externas en parámetros de redirección; la aplicación redirige sin validar el destino.",
            impact: "- **Amplificación de phishing**: enlaces con dominio de confianza\n- **Robo de tokens OAuth**\n- **Daño reputacional**\n- **Distribución de malware**\n- **Bypass de SSO**",
            cvss: "CVSS 3.1: 4.7 (Medium) - AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        },
        "exposure" => TechInfo {
            justification: "Se detectó exposición de información sensible accesible sin autenticación: credenciales, claves API, configuraciones internas o interfaces administrativas.",
            impact: "- **Compromiso de cuentas**\n- **Abuso de API**: claves filtradas, fraude de facturación\n- **Mapeo de infraestructura**\n- **Escalada de privilegios**: paneles admin\n- **Violación de cumplimiento**: exposición de PII",
            cvss: "CVSS 3.1: 7.5 (High) - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        },
        "idor" => TechInfo {
            justification: "Se confirmó IDOR (Insecure Direct Object Reference) comparando la MISMA petición desde dos identidades: la identidad que NO es dueña del recurso recibió 200 con el mismo cuerpo que la dueña, donde un control de acceso correcto devolvería 404. La referencia al objeto (id/UUID) es directa y no se valida contra la sesión.",
            impact: "- **Acceso horizontal**: lectura de datos de otros usuarios (PII, pedidos, mensajes)\n- **Fuga masiva**: enumeración del identificador recorre toda la base\n- **Violación de cumplimiento**: exposición de PII (GDPR, HIPAA)\n- **Escalada**: si el objeto controla permisos, toma de cuentas",
            cvss: "CVSS 3.1: 6.5 (Medium) - AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        },
        "bac" => TechInfo {
            justification: "Se confirmó Broken Access Control repitiendo la petición con una identidad de menor privilegio (o sin autenticar): obtuvo 200 con el recurso protegido donde debería recibir 401/403. La autorización se aplica en el cliente o falta en el endpoint.",
            impact: "- **Escalada vertical**: funciones de administración accesibles a un usuario normal\n- **Fuga sin autenticar**: datos o paneles protegidos servidos sin sesión\n- **Manipulación**: acciones privilegiadas ejecutadas sin autorización\n- **Violación de cumplimiento**: exposición de PII y de operaciones internas",
            cvss: "CVSS 3.1: 8.1 (High) - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        },
        _ => TechInfo {
            justification: "Vulnerabilidad detectada por escaneo automatizado y correlación de patrones, con indicadores consistentes con esta clase según análisis de respuesta y firmas conocidas.",
            impact: "- **Confidencialidad**: posible acceso no autorizado a información sensible\n- **Integridad**: posible modificación no autorizada\n- **Disponibilidad**: riesgo de interrupción del servicio",
            cvss: "CVSS 3.1: Varía - se recomienda evaluación manual",
        },
    }
}

/// Ficha técnica HONESTA del SSRF CIEGO out-of-band. Distinta de la de `ssrf`
/// (in-band metadata, Critical 9.1): un blind OOB solo prueba interacción EXTERNA
/// (el servidor trae una URL arbitraria); afirmar robo de metadata que NO se
/// demostró quema Signal ante el triager (revisión 2026-08-23, decisión de Juan).
fn tech_info_oob() -> TechInfo {
    TechInfo {
        justification: "Se confirmó SSRF CIEGO (out-of-band): el servidor del objetivo realizó una petición saliente a un recurso ÚNICO bajo control del investigador (token aleatorio irrepetible inyectado en un parámetro). Es prueba determinista de que el backend obtiene URLs arbitrarias controladas por el atacante. NO se demostró (aún) acceso a recursos internos ni a metadata de nube; eso elevaría la severidad y requiere confirmación adicional.",
        impact: "- **Peticiones salientes arbitrarias**: el servidor actúa como proxy hacia destinos que elige el atacante\n- **Potencial pivote a red interna** (RFC1918) y a metadata cloud (169.254.169.254) — REQUIERE confirmación con un destino interno\n- **Potencial bypass de firewall perimetral**\n- **Escaneo de infraestructura interna** por diferencias de respuesta/tiempo",
        cvss: "CVSS 3.1: 5.3 (Medium) - AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N — SSRF ciego con interacción EXTERNA confirmada. Escala a High/Critical al confirmar acceso a red interna o metadata cloud.",
    }
}

/// `tech_info` consciente del NOMBRE del hallazgo: el OOB blind tiene su ficha
/// propia (honesta); el resto cae en `tech_info(vuln_type)`.
pub fn tech_info_named(vuln_name: &str, vuln_type: &str) -> TechInfo {
    if vuln_name == "ssrf-oob-callback" {
        tech_info_oob()
    } else {
        tech_info(vuln_type)
    }
}

/// Pasos de reproducción CONCRETOS por tipo, sobre el endpoint confirmado. Es lo
/// que un triager de H1 necesita para reproducir en segundos y ACEPTAR el reporte
/// (no un texto genérico). Puro y testable.
pub fn repro_steps(vuln_type: &str, ep: &Endpoint) -> String {
    let url = &ep.url;
    let ev = ep.evidence.as_deref().unwrap_or("");
    match vuln_type.to_lowercase().as_str() {
        "xss" => format!(
            "1. Abrir en un navegador la URL de prueba:\n   `{url}`\n\
             2. El JavaScript inyectado se EJECUTA en el contexto de la página \
             (confirmado en navegador headless real: {ev}). La prueba usa un marcador \
             inofensivo (`document.domain` / un atributo computado); NO altera datos.\n\
             3. Para demostrar impacto, sustituir el payload de prueba por uno de robo \
             de sesión — no realizado por responsabilidad.\n"
        ),
        "sqli" => format!(
            "1. Objetivo:\n   `{url}`\n\
             2. Ejecutar:\n   `sqlmap -u '{url}' --batch --level=1 --risk=1`\n\
             3. sqlmap confirma la inyección ({ev}) mediante análisis diferencial \
             (respuesta/tiempo). No se extrajeron datos más allá de la prueba de existencia.\n"
        ),
        "cmdi" => format!(
            "1. Objetivo:\n   `{url}`\n\
             2. Ejecutar:\n   `commix -u '{url}' --batch`\n\
             3. commix confirma la inyección de comandos ejecutando un comando de \
             diagnóstico inofensivo en el servidor.\n"
        ),
        "exposure" => format!(
            "1. Petición sin autenticación:\n   `curl -s '{url}'`\n\
             2. La respuesta expone contenido sensible ({ev}) accesible sin credenciales.\n"
        ),
        _ => format!(
            "1. Abrir/consultar el endpoint:\n   `{url}`\n\
             2. Observar el indicador de la vulnerabilidad ({ev}).\n"
        ),
    }
}

/// `repro_steps` consciente del NOMBRE: el OOB blind se reproduce del lado del
/// TRIAGER (con SU propio callback, no el nuestro — el colector es infra privada).
pub fn repro_steps_named(vuln_name: &str, vuln_type: &str, ep: &Endpoint) -> String {
    if vuln_name == "ssrf-oob-callback" {
        let url = &ep.url;
        let ev = ep.evidence.as_deref().map(|e| format!(" Evidencia de esta corrida: {}.", e.trim_end_matches('.'))).unwrap_or_default();
        return format!(
            "1. Preparar un recurso de callback propio (Burp Collaborator, interactsh, o un servidor bajo tu control) que registre peticiones entrantes con un token único.\n\
             2. Inyectar la URL del callback en el parámetro afectado, sustituyendo su valor por `http://<TU-CALLBACK>/<token>`:\n   `{url}`\n\
             3. Observar en tu callback una petición ENTRANTE con ese token exacto → prueba de que el servidor del objetivo obtuvo la URL (SSRF).{ev}\n\
             4. Para evaluar impacto, apuntar el parámetro a un recurso interno (p. ej. `http://169.254.169.254/latest/meta-data/` o un host RFC1918) y comparar la respuesta — no realizado aquí por responsabilidad.\n"
        );
    }
    repro_steps(vuln_type, ep)
}

/// Remediación ESPECÍFICA por tipo (no el genérico de antes). Puro.
pub fn remediation(vuln_type: &str) -> &'static str {
    match vuln_type.to_lowercase().as_str() {
        "sqli" => "Usar consultas parametrizadas / sentencias preparadas en TODOS los accesos a BD. No concatenar entrada del usuario en SQL. Aplicar principio de mínimo privilegio a la cuenta de BD.",
        "xss" => "Codificar la salida según el contexto (HTML/atributo/JS/URL). Aplicar una Content-Security-Policy restrictiva (sin `unsafe-inline`). Validar y sanear la entrada reflejada en la respuesta.",
        "cmdi" => "No pasar entrada del usuario a intérpretes de shell. Usar APIs que separen comando de argumentos (execve sin shell). Lista blanca estricta de valores permitidos.",
        "ssrf" => "Lista blanca de destinos permitidos. Bloquear rangos internos/metadata (169.254.169.254, RFC1918). Resolver y validar el host antes de la petición.",
        "lfi" => "Canonicalizar y validar rutas contra un directorio base. Rechazar secuencias de traversal. No pasar entrada del usuario a funciones de sistema de archivos.",
        "exposure" => "Retirar el recurso expuesto o exigir autenticación. Rotar de inmediato toda credencial/clave filtrada. Restringir el acceso a paneles e interfaces internas.",
        "redirect" => "Validar el destino de la redirección contra una lista blanca. Evitar redirecciones basadas en parámetros controlables por el usuario.",
        _ => "Aplicar validación de entrada, codificación de salida y controles de acceso adecuados al tipo. Rotar credenciales/software expuesto.",
    }
}

/// Datos de un endpoint afectado para el informe.
#[derive(Debug, Clone, Default)]
pub struct Endpoint {
    pub url: String,
    pub verified: bool,
    pub tool: Option<String>,
    pub confidence: Option<String>,
    pub exploitable: bool,
    pub evidence: Option<String>,
    pub raw: Option<String>,
    /// NEXUS lo vio ejecutar/reproducir (no la palabra de la herramienta).
    pub execution_confirmed: bool,
    /// Control diferencial reproducible ("aciertos/intentos", p. ej. "3/3").
    pub repro_ratio: Option<String>,
}

/// Construye el informe (markdown) para un grupo (programa, vuln) con sus
/// endpoints. Puro y testable.
pub fn build_submission(program: &str, vuln_name: &str, vuln_type: &str, severity: &str, endpoints: &[Endpoint]) -> String {
    let ti = tech_info_named(vuln_name, vuln_type);
    let mut s = String::new();
    s.push_str(&format!("# {vuln_name} — {program}\n\n"));
    s.push_str(&format!("## Título\n[{vuln_name}] detectado en {} endpoint(s)\n\n", endpoints.len()));
    s.push_str(&format!("## Severidad\n{}\n{}\n\n", severity.to_uppercase(), ti.cvss));

    let verified: Vec<&Endpoint> = endpoints.iter().filter(|e| e.verified && e.tool.is_some()).collect();

    // CERTIFICADO ANTI-SLOP, AL FRENTE (2026-09-05). Es la primera cosa que lee un
    // triador saturado: o exhibe el rigor (control diferencial reproducible +
    // ejecución + evidencia) o lleva el banner «NO ENVIAR». La MISMA puerta
    // (`Certificado::es_valido`) decide si el reporte puede afirmar «CONFIRMADO».
    let cert = certificado_de(vuln_type, &verified);
    s.push_str(&cert.render());

    // Resumen específico: dice que se CONFIRMÓ y con qué, no un genérico. Solo se
    // afirma la confirmación si el hallazgo cruzó la puerta anti-slop; si no, es
    // «posible», no «CONFIRMADO» (no se le regala rigor a un candidato sin sello).
    let resumen = if cert.es_valido() {
        format!("Se ha CONFIRMADO una vulnerabilidad **{vuln_name}** ({}) en la infraestructura de {program}, verificada por ejecución con control diferencial reproducible (ver Certificado, Pasos para reproducir y Evidencia).", vuln_type.to_uppercase())
    } else {
        format!("Se ha detectado una posible vulnerabilidad **{vuln_name}** ({}) en {program}. NO cruzó la puerta anti-slop (ver banner arriba): no enviar sin completar la verificación.", vuln_type.to_uppercase())
    };
    s.push_str(&format!("## Resumen\n{resumen}\n\n"));

    // Pasos para reproducir: sobre el PRIMER endpoint confirmado (o el primero).
    let poc_ep = verified.first().copied().or_else(|| endpoints.first());
    if let Some(ep) = poc_ep {
        s.push_str("## Pasos para reproducir\n");
        s.push_str(&repro_steps_named(vuln_name, vuln_type, ep));
        s.push('\n');
    }

    s.push_str(&format!("## Detalles\n**Tipo:** {vuln_name}\n**Clase:** {}\n**Severidad:** {}\n\n", vuln_type.to_uppercase(), severity.to_uppercase()));

    s.push_str("## Endpoints afectados\n");
    for e in endpoints {
        s.push_str(&format!("- {}\n", e.url));
    }
    s.push('\n');
    if !verified.is_empty() {
        s.push_str("## Evidencia de verificación\n");
        for e in &verified {
            s.push_str(&format!("- **{}**\n", e.url));
            s.push_str(&format!("  - Herramienta: {}\n", e.tool.as_deref().unwrap_or("-")));
            s.push_str(&format!("  - Confianza: {}\n", e.confidence.as_deref().unwrap_or("N/A")));
            if e.exploitable {
                s.push_str("  - Explotable: SÍ\n");
            }
            if let Some(ev) = &e.evidence {
                s.push_str(&format!("  - Evidencia: {ev}\n"));
            }
        }
        s.push('\n');

        // PoC crudo de la herramienta (S6): prueba directa para el triager. El
        // `raw` puede contener cuerpo de respuesta que el OBJETIVO controla (salida
        // de sqlmap/commix/navegador), así que se cerca con una valla de backticks
        // más larga que cualquier racha del propio contenido — una línea ``` del PoC
        // no puede cerrar la valla e inyectar markdown en el reporte que va a H1.
        if let Some(raw) = verified.iter().find_map(|e| e.raw.as_ref()) {
            s.push_str("## Prueba (PoC)\n");
            s.push_str(&cercar_poc(raw));
            s.push_str("\n\n");
        }
    }

    s.push_str(&format!("## Justificación técnica\n{}\n\n", ti.justification));
    s.push_str(&format!("## Impacto de seguridad\n{}\n\n", ti.impact));
    s.push_str(&format!("## Remediación\n{}\n\n", remediation(vuln_type)));
    s.push_str("---\n*Informe generado por NEXUS.*\n");
    s
}

/// Cerca un PoC en un bloque de código markdown con una valla de backticks MÁS
/// LARGA que cualquier racha de backticks del propio contenido. CommonMark: un
/// bloque cercado solo se cierra con una valla de ≥ tantos backticks como la
/// abrió, así que una línea ``` dentro del PoC —que el objetivo puede controlar
/// vía el cuerpo capturado por sqlmap/commix/navegador— no puede cerrar la valla
/// ni inyectar markdown en el reporte que se publica en H1. Preserva el contenido
/// (no lo mutila): solo alarga la valla.
fn cercar_poc(contenido: &str) -> String {
    let recortado = contenido.trim();
    let racha_max = recortado
        .as_bytes()
        .split(|&b| b != b'`')
        .map(<[u8]>::len)
        .max()
        .unwrap_or(0);
    let valla = "`".repeat(racha_max.saturating_add(1).max(3));
    format!("{valla}\n{recortado}\n{valla}")
}

/// Traduce la severidad de nexus al `severity_rating` que acepta H1.
pub fn h1_severity(sev: &str) -> &'static str {
    match sev.to_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "none",
    }
}

/// Nombre de archivo seguro (sin separadores ni caracteres raros).
pub fn sanitize_filename(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

/// Genera un informe por cada grupo (programa, vuln) de hallazgos verificados y
/// los escribe en `reports_dir`. Devuelve cuántos informes se escribieron.
pub async fn generate_all(cfg: &crate::config::Config, pool: &sqlx::SqlitePool) -> crate::error::Result<usize> {
    use std::collections::BTreeMap;
    let rows = crate::db::verified_findings(pool).await?;
    tokio::fs::create_dir_all(&cfg.reports_dir).await.ok();

    // Agrupa por (programa, vuln_name).
    let mut groups: BTreeMap<(String, String), Vec<crate::db::VerifiedRow>> = BTreeMap::new();
    for r in rows {
        let prog = r.program_name.clone().unwrap_or_else(|| "GLOBAL_FEED".into());
        groups.entry((prog, r.vuln_name.clone())).or_default().push(r);
    }

    let mut written = 0usize;
    for ((program, vuln_name), rows) in groups {
        let vuln_type = rows.first().and_then(|r| r.vuln_type.clone()).unwrap_or_else(|| "other".into());
        let severity = rows.first().map(|r| r.severity.clone()).unwrap_or_else(|| "unknown".into());
        let endpoints: Vec<Endpoint> = rows.iter().map(|r| Endpoint {
            url: r.url.clone(),
            verified: r.verified != 0,
            tool: r.verification_tool.clone(),
            confidence: r.verification_confidence.clone(),
            exploitable: r.exploitable != 0,
            evidence: r.verification_evidence.clone(),
            raw: r.raw_evidence.clone(),
            execution_confirmed: r.execution_confirmed != 0,
            repro_ratio: r.repro_ratio.clone(),
        }).collect();

        let report = build_submission(&program, &vuln_name, &vuln_type, &severity, &endpoints);
        let fname = format!("{}_{}.md", sanitize_filename(&program), sanitize_filename(&vuln_name));
        tokio::fs::write(cfg.reports_dir.join(fname), report).await?;
        written += 1;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tech_info_conocido_y_generico() {
        assert!(tech_info("sqli").cvss.contains("9.8"));
        assert!(tech_info("xss").cvss.contains("6.1"));
        assert!(tech_info("desconocido").cvss.contains("Varía"));
    }

    #[test]
    fn informe_incluye_secciones_y_evidencia() {
        let eps = vec![Endpoint {
            url: "https://x.example.com/?id=1".into(),
            verified: true,
            tool: Some("sqlmap".into()),
            confidence: Some("high".into()),
            exploitable: true,
            evidence: Some("UNION-based".into()),
            raw: Some("Parameter: id (GET) is vulnerable".into()),
            execution_confirmed: true,
            repro_ratio: Some("3/3".into()),
        }];
        let r = build_submission("acme", "sql-injection", "sqli", "critical", &eps);
        assert!(r.contains("## Severidad"));
        assert!(r.contains("9.8 (Critical)"));
        assert!(r.contains("## Evidencia de verificación"));
        assert!(r.contains("Explotable: SÍ"));
        assert!(r.contains("## Impacto de seguridad"));
        assert!(r.contains("Fuga de datos"));
        // Certificado anti-slop al frente (2026-09-05): con ejecución + 3/3 + evidencia.
        assert!(r.contains("Certificado de verificación"));
        assert!(!r.contains("NO ENVIAR"));
    }

    #[test]
    fn idor_confirmado_por_autz_certifica_sin_ratio_de_repeticion() {
        // EL EDGE (2026-09-05): un IDOR/BAC confirmado por el diferencial de autz
        // (execution_confirmed, evidencia, tool=autz) NO da `n/n` — su control es el
        // diferencial de identidad. Antes el certificado lo bloqueaba; ahora certifica.
        let eps = vec![Endpoint {
            url: "https://x.example.com/api/invoices/1002".into(),
            verified: true,
            tool: Some("autz".into()),
            confidence: Some("high".into()),
            exploitable: true,
            evidence: Some("dueño 2xx (512B) vs otra identidad 2xx (512B), firma exacta".into()),
            raw: Some("diferencial de identidad: mismo recurso 2xx del dueño".into()),
            execution_confirmed: true,
            repro_ratio: None, // authz no produce n/n
        }];
        let r = build_submission("acme", "idor-broken-authz", "bac", "high", &eps);
        assert!(r.contains("Certificado de verificación"), "el edge sí certifica");
        assert!(r.contains("Control (diferencial)"), "muestra el control diferencial, no un n/n falso");
        assert!(!r.contains("NO ENVIAR"));
        assert!(r.contains("Se ha CONFIRMADO"));
    }

    #[test]
    fn sin_certificado_el_reporte_lleva_banner_no_enviar_y_no_dice_confirmado() {
        // PAREJA (directiva 33) del test de arriba: el MISMO hallazgo sin las patas
        // del certificado (no ejecución, sin repro) NO debe afirmar CONFIRMADO y SÍ
        // debe llevar el banner que frena el envío. Espeja el gate SQL en el reporte.
        let eps = vec![Endpoint {
            url: "https://x.example.com/?id=1".into(),
            verified: true,
            tool: Some("nuclei".into()),           // no es verificador de ejecución…
            confidence: Some("low".into()),
            exploitable: false,
            evidence: None,                          // …y sin evidencia capturada
            raw: None,
            execution_confirmed: false,
            repro_ratio: None,
        }];
        let r = build_submission("acme", "sql-injection", "sqli", "critical", &eps);
        assert!(r.contains("SIN CERTIFICADO — NO ENVIAR"), "sin sello va el banner");
        assert!(!r.contains("Se ha CONFIRMADO"), "no se afirma confirmación sin certificado");
        assert!(r.contains("posible vulnerabilidad"), "se degrada a 'posible'");
    }

    #[test]
    fn reporte_oob_es_honesto_y_no_sobrevende() {
        // El SSRF CIEGO out-of-band lleva ficha PROPIA: Medium, sin afirmar
        // metadata que no se probó, y con repro del lado del triager. Antes heredaba
        // la ficha de `ssrf` (Critical 9.1, «robo de credenciales AWS») → sobre-venta
        // que el triager baja y quema Signal (decisión de Juan 2026-08-23).
        let ep = Endpoint {
            url: "https://x.com/api?url=1".into(), verified: true, tool: Some("oob".into()),
            confidence: Some("high".into()), exploitable: false,
            evidence: Some("callback del token abc reproducido".into()), raw: None,
            execution_confirmed: false, repro_ratio: None,
        };
        let r = build_submission("acme", "ssrf-oob-callback", "ssrf", "medium", &[ep]);
        assert!(r.contains("5.3 (Medium)"), "el blind OOB no se vende como Critical");
        assert!(!r.contains("9.1 (Critical)") && !r.contains("9.8"), "sin CVSS de SSRF in-band");
        assert!(!r.contains("robo de credenciales AWS/GCP/Azure"), "no afirma metadata no probada");
        assert!(r.to_lowercase().contains("ciego"), "enmarca como SSRF ciego");
        assert!(r.contains("TU-CALLBACK"), "repro reproducible por el triager con su propio callback");
        // PAREJA (directiva 33): un SSRF IN-BAND real SÍ lleva la ficha crítica.
        let ep2 = Endpoint {
            url: "https://x.com/f?u=1".into(), verified: true, tool: Some("content_check".into()),
            confidence: Some("high".into()), exploitable: true,
            evidence: Some("AccessKeyId".into()), raw: None,
            execution_confirmed: true, repro_ratio: Some("3/3".into()),
        };
        let r2 = build_submission("acme", "ssrf-metadata-aws", "ssrf", "critical", &[ep2]);
        assert!(r2.contains("9.1 (Critical)"), "el SSRF in-band sí es Critical");
        assert!(r2.contains("robo de credenciales AWS/GCP/Azure"));
    }

    #[test]
    fn informe_lleva_pasos_de_reproduccion_y_poc_url() {
        // XSS confirmado por ejecución en navegador.
        let eps = vec![Endpoint {
            url: "https://app.example.com/?q=INJECT".into(),
            verified: true,
            tool: Some("browser".into()),
            confidence: Some("high".into()),
            exploitable: true,
            evidence: Some("ejecución reproducible 3/3".into()),
            raw: None,
            execution_confirmed: true,
            repro_ratio: Some("3/3".into()),
        }];
        let r = build_submission("acme", "reflected-xss", "xss", "high", &eps);
        assert!(r.contains("## Pasos para reproducir"), "el reporte necesita pasos para que H1 acepte");
        assert!(r.contains("https://app.example.com/?q=INJECT"), "incluye la URL-PoC exacta");
        assert!(r.contains("navegador"), "explica la ejecución en navegador");
        assert!(r.contains("3/3"), "muestra la reproducibilidad");
        assert!(r.contains("CONFIRMADO"), "el resumen dice que se confirmó");
        // Remediación específica de XSS (CSP), no el genérico de antes.
        assert!(r.contains("Content-Security-Policy"));
    }

    #[test]
    fn pasos_de_reproduccion_por_tipo() {
        let ep = Endpoint { url: "https://x/a?id=1".into(), verified: true, tool: Some("sqlmap".into()),
            confidence: Some("high".into()), exploitable: true, evidence: Some("UNION-based".into()), raw: None,
            execution_confirmed: true, repro_ratio: Some("3/3".into()) };
        assert!(repro_steps("sqli", &ep).contains("sqlmap -u"));
        assert!(repro_steps("cmdi", &ep).contains("commix -u"));
        assert!(repro_steps("exposure", &ep).contains("curl -s"));
        assert!(remediation("sqli").contains("parametrizadas"));
        assert!(remediation("xss").contains("Content-Security-Policy"));
    }

    #[test]
    fn sanitiza_nombre() {
        assert_eq!(sanitize_filename("acme/../corp:1"), "acme____corp_1");
    }

    #[test]
    fn cercar_poc_no_lo_cierra_un_backtick_del_contenido() {
        // GREEN: un PoC normal usa la valla mínima de 3.
        let normal = cercar_poc("respuesta: 200 OK");
        assert!(normal.starts_with("```\n") && normal.ends_with("\n```"));

        // RED del ataque: un PoC con una línea ``` (cuerpo controlado por el
        // objetivo) obtiene una valla MÁS LARGA, así que su ``` no la cierra.
        let malicioso = "línea uno\n```\n# markdown inyectado\n[click](http://malo)";
        let cercado = cercar_poc(malicioso);
        assert!(cercado.starts_with("````\n"), "valla de 4 backticks ante un ``` interno");
        assert!(cercado.ends_with("\n````"));
        // El contenido íntegro sigue dentro (no se mutila la evidencia).
        assert!(cercado.contains("# markdown inyectado"));
        // Y la valla de apertura (4) no aparece como línea suelta en el contenido:
        // ninguna racha del contenido llega a 4, así que no puede cerrar la valla.
        assert!(!malicioso.contains("````"));

        // Racha larga: 5 backticks dentro → valla de 6.
        let cinco = cercar_poc("a `````b");
        assert!(cinco.starts_with("``````\n"));
    }
}
