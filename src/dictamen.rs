// SPDX-License-Identifier: LicenseRef-Propietario
//! Ensamblador del DICTAMEN técnico-jurídico de protección de datos.
//!
//! Jala los `findings` REALES de un programa y autollena las secciones técnicas
//! del dictamen (§1 resumen, §3 metodología, §4 hallazgos, §6 mapeo), dejando el
//! §5 (organizacional/documental) y el §8 (firma legal) para la persona. La mitad
//! técnica ya la produce nexus; esto la convierte en documento con UN comando.
//!
//! El núcleo es PURO y testeable: `mapear_obligacion` (la IP central: hallazgo ->
//! obligación de la Ley 1581) y `generar` (findings -> Markdown). El fetch es la
//! única parte con I/O. Ver la plantilla en
//! `conocimiento/comercial/dictamen-proteccion-datos-PLANTILLA.md`.

use sqlx::SqlitePool;
use std::fmt::Write as _;

/// Una fila de `findings` con los campos que el dictamen necesita.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FilaDictamen {
    pub vuln_name: String,
    pub severity: String,
    pub url: String,
    pub status: String,
    pub verification_evidence: Option<String>,
    pub cwe: Option<String>,
}

/// Metadatos del dictamen que NO vienen de la BD (los pone el llamante).
pub struct Meta<'a> {
    pub programa: &'a str,
    pub fecha: &'a str,   // fecha del dictamen; el CLI pasa la de hoy (UTC)
    pub binario: &'a str, // versión/md5 de nexus, para el anclaje al artefacto (directiva 31)
}

/// Mapea un hallazgo técnico a la OBLIGACIÓN legal que incumple (Ley 1581 /
/// Decreto 1377). Es la IP central del producto, en código.
///
/// Todo fallo de seguridad aterriza AL MENOS en el principio de seguridad
/// (Art. 4 g); el tipo concreto añade artículos y el agravante. Directiva 20/23:
/// un tipo DESCONOCIDO no se inventa un mapeo específico — cae al principio
/// general marcado para clasificar a mano, nunca a un artículo falso.
pub fn mapear_obligacion(vuln_name: &str) -> &'static str {
    let v = vuln_name.to_ascii_lowercase();
    // El orden importa: lo más específico primero.
    if v.contains("idor")
        || v.contains("bola")
        || (v.contains("control-de-acceso") && !v.contains("evasion"))
    {
        "Art. 4(g) seguridad + 4(h) confidencialidad + 17(d) — acceso no autorizado a datos de OTRO titular"
    } else if v.contains("evasion") || v.contains("bypass") {
        "Art. 4(g) seguridad + 17(d) — recurso protegido accesible sin autorización"
    } else if v.contains("sql") {
        "Art. 4(g) seguridad + 17(d) — riesgo de exfiltración MASIVA de la base de datos"
    } else if v.contains("ssrf") {
        "Art. 4(g) seguridad + 17(d) — compromiso del servidor y exposición masiva"
    } else if v.contains("xss") {
        "Art. 4(g) seguridad + 4(h) confidencialidad — secuestro de sesión del titular"
    } else if v.contains("secret")
        || v.contains("disclosure")
        || v.contains("credential")
        || v.contains("clientid")
        || v.contains("token")
    {
        "Art. 4(g) seguridad + 17(d) — credencial/dato expuesto: puerta a acceso no autorizado"
    } else if v.contains("takeover") {
        "Art. 17(d) — subdominio secuestrable: uso fraudulento e interceptación de datos"
    } else if v.contains("mass-assignment") {
        "Art. 4(g) seguridad + 17(d) — escalada de privilegios sobre el objeto"
    } else if v.contains("graphql") || v.contains("introspection") {
        "Art. 4(g) seguridad — esquema de la API expuesto: debilita la seguridad y facilita el ataque"
    } else if v.contains("cache") {
        "Art. 4(g) seguridad — manipulación de caché sin autenticación (integridad/disponibilidad)"
    } else if v.contains("cifrado") {
        "Art. 4(g) seguridad — suite de cifrado débil aceptada: el canal no protege los datos en tránsito"
    } else if v.contains("certificado") {
        "Art. 4(g) seguridad — certificado TLS inválido/vencido: el canal cifrado no es confiable (datos en tránsito)"
    } else if v.contains("hsts") || v.contains("https-redirect") || v.contains("tls") {
        "Art. 4(g) seguridad — datos personales en tránsito sin protección (TLS obsoleto, canal no forzado a HTTPS o sin HSTS)"
    } else if v.contains("cookie") {
        "Art. 4(g) seguridad + 4(h) confidencialidad — cookie de sesión sin protección: robo de sesión = acceso no autorizado"
    } else if v.contains("header") {
        "Art. 4(g) seguridad — cabecera de seguridad ausente (defensa en profundidad)"
    } else if v.contains("banner") {
        "Art. 4(g) seguridad — divulgación de versión del software: facilita el ataque dirigido"
    } else if v.contains("cve") {
        "Art. 4(g) seguridad + 17(d) — vulnerabilidad CONOCIDA sin remediar (incumple el deber de diligencia)"
    } else {
        "Art. 4(g) seguridad — [clasificar el agravante y los artículos específicos a mano]"
    }
}

/// Genera el §2 (marco normativo) pasando cada cita por el ORÁCULO jurídico.
///
/// Es LA INVERSIÓN aplicada al dictamen: en vez de afirmar los artículos «de
/// memoria», cada uno se coteja contra la publicación oficial poblada en
/// `oraculo::corpus_proteccion_datos`. La marca ✓ solo aparece si el texto está
/// cotejado; lo demás sale como **SIN VERIFICAR** (directiva 20) — nunca se afirma
/// una cita sin respaldo. La Ley 1581 y el Decreto 1377 están cotejados; solo la
/// circular de la SIC queda SIN VERIFICAR (sin fuente oficial cargada).
fn marco_normativo() -> String {
    use crate::oraculo::{corpus_proteccion_datos, verificar_cita, Veredicto};
    let corpus = corpus_proteccion_datos();
    let mut s = String::new();
    let _ = writeln!(s, "## 2. Marco normativo aplicable\n");
    let _ = writeln!(
        s,
        "> Cada cita se coteja contra su publicación oficial con el oráculo \
         jurídico (`oraculo::verificar_cita`). ✓ = texto cotejado con la fuente; \
         **SIN VERIFICAR** = pendiente de cotejo o de fuente oficial (no se afirma).\n"
    );
    for cita in crate::oraculo::citas_base_dictamen() {
        match verificar_cita(&cita, &corpus) {
            Veredicto::Existe { sumilla, fuente } => {
                let _ = writeln!(s, "- ✓ **{}** — {} · _cotejado: {}_", cita.referencia(), sumilla, fuente);
            }
            Veredicto::SinVerificar { sumilla } => {
                let _ = writeln!(s, "- ⚠ **SIN VERIFICAR** {} — {} (catalogado, texto sin cotejar)", cita.referencia(), sumilla);
            }
            Veredicto::NoExiste => {
                let _ = writeln!(s, "- ⚠ **SIN VERIFICAR** {} — cita fuera del corpus oficial; revisar numeración antes de firmar", cita.referencia());
            }
        }
    }
    // No cotejable aún: sin artículo concreto ni fuente oficial cargada.
    let _ = writeln!(s, "- ⚠ **SIN VERIFICAR** circular/guía vigente de la Superintendencia de Industria y Comercio (a confirmar; la responsabilidad demostrada ya se coteja en el Decreto 1377 Art. 26-27)\n");
    s
}

/// ¿Este hallazgo entra en el dictamen? Se excluyen los FALSE_POSITIVE — y la
/// regla vive AQUÍ, en un solo sitio testeado (directiva 23), no en la consulta.
fn cuenta(f: &FilaDictamen) -> bool {
    !f.status.eq_ignore_ascii_case("FALSE_POSITIVE")
}

/// Rango de severidad para ordenar y contar: 0 crítica … 3 baja. Cubre las
/// etiquetas técnicas (inglés/español) y las organizacionales (español).
fn rango_sev(s: &str) -> u8 {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" | "crítica" | "critica" => 0,
        "high" | "alta" => 1,
        "medium" | "media" => 2,
        _ => 3, // low/info/informational/baja
    }
}

/// Genera el dictamen en Markdown a partir de los findings. PURO (sin I/O): el
/// llamante pasa las filas y los metadatos. Excluye los FALSE_POSITIVE.
///
/// `seccion5`: si el auditor llenó el checklist de cumplimiento, se pasan los
/// `Resultado` YA evaluados (por `cumplimiento::evaluar`) — no un string opaco,
/// para que §1/§6/§7/§8 puedan CONTAR y MAPEAR los incumplimientos
/// organizacionales, no solo pegarlos. Si es `None`, el §5 queda en BLANCO (el
/// hueco a llenar por entrevista) y el dictamen es solo técnico.
pub fn generar(
    meta: &Meta,
    filas: &[FilaDictamen],
    seccion5: Option<&[crate::cumplimiento::Resultado]>,
) -> String {
    use crate::cumplimiento::Respuesta;
    let reales: Vec<&FilaDictamen> = filas.iter().filter(|f| cuenta(f)).collect();
    let sev = |rank: u8| -> usize { reales.iter().filter(|f| rango_sev(&f.severity) == rank).count() };
    let (crit, alta, media, baja) = (sev(0), sev(1), sev(2), sev(3));
    let total = reales.len();

    // Incumplimientos organizacionales del §5 (NoCumple), por severidad. El
    // catálogo no tiene severidad crítica (su máximo es alta), pero se cuenta la
    // fila crítica por simetría de la tabla.
    let org: Vec<&crate::cumplimiento::Resultado> = seccion5
        .map(|rs| rs.iter().filter(|r| r.respuesta == Respuesta::NoCumple).collect())
        .unwrap_or_default();
    let sin_verificar = seccion5
        .map(|rs| rs.iter().filter(|r| r.respuesta == Respuesta::SinVerificar).count())
        .unwrap_or(0);
    let osev = |rank: u8| -> usize { org.iter().filter(|r| rango_sev(r.item.severidad) == rank).count() };
    let (o_crit, o_alta, o_media, o_baja) = (osev(0), osev(1), osev(2), osev(3));
    let o_total = org.len();

    // El veredicto ya NO mira solo lo técnico: un incumplimiento organizacional
    // ALTO (p. ej. cifrado en reposo o Habeas Data) también vulnera el principio
    // de seguridad. Antes §1 decía «SIN HALLAZGOS» con el §5 lleno de incumplimientos.
    let veredicto = if crit > 0 || alta > 0 || o_alta > 0 {
        "NO CUMPLE — hay hallazgos que vulneran el principio de seguridad (Art. 4 g)"
    } else if total + o_total > 0 {
        "CUMPLE CON RESERVAS — hallazgos menores a subsanar"
    } else if sin_verificar > 0 {
        "SIN HALLAZGOS EN LO VERIFICADO — pero quedan ítems SIN VERIFICAR que impiden un dictamen definitivo"
    } else if seccion5.is_none() {
        "SIN HALLAZGOS TÉCNICOS en el alcance auditado (no exime del §5 organizacional, no evaluado en esta pasada)"
    } else {
        "SIN HALLAZGOS en el alcance auditado (técnico y organizacional)"
    };

    let mut d = String::new();
    let _ = writeln!(d, "# DICTAMEN TÉCNICO-JURÍDICO DE PROTECCIÓN DE DATOS PERSONALES\n");
    let _ = writeln!(d, "**Responsable del tratamiento auditado:** {{razón social}} — NIT {{nit}}  ");
    let _ = writeln!(d, "**Alcance auditado (programa):** `{}`  ", meta.programa);
    let _ = writeln!(d, "**Fecha del dictamen:** {}  ", meta.fecha);
    let _ = writeln!(d, "**Perito:** {{nombre}}, abogado y programador — T.P. {{tarjeta}}  ");
    let _ = writeln!(d, "**Motor / anclaje al artefacto (directiva 31):** nexus `{}`\n", meta.binario);

    // §1 — tabla combinada: técnicos Y organizacionales, con veredicto que mira ambos.
    let _ = writeln!(d, "## 1. Resumen ejecutivo\n");
    let _ = writeln!(d, "**Veredicto:** {veredicto}.\n");
    let _ = writeln!(d, "| Severidad | Técnicos (§4) | Organizacionales (§5) |");
    let _ = writeln!(d, "|---|---|---|");
    let _ = writeln!(d, "| Crítica | {crit} | {o_crit} |");
    let _ = writeln!(d, "| Alta | {alta} | {o_alta} |");
    let _ = writeln!(d, "| Media | {media} | {o_media} |");
    let _ = writeln!(d, "| Baja / informativa | {baja} | {o_baja} |");
    let _ = writeln!(d, "| **Total (sin falsos positivos)** | **{total}** | **{o_total}** |\n");
    if sin_verificar > 0 {
        let _ = writeln!(
            d,
            "> ⚠️ {sin_verificar} ítem(s) organizacional(es) quedan **SIN VERIFICAR** \
             (directiva 20): no se asumen cumplidos y deben cerrarse antes de firmar el dictamen definitivo.\n"
        );
    }
    let _ = writeln!(
        d,
        "> Exposición sancionatoria: Art. 23 Ley 1581 — multas hasta 2.000 SMLMV, \
         suspensión o cierre; agravada si el dato es sensible (salud, Art. 5) o el \
         volumen de titulares es alto.\n"
    );

    // §2: cada cita de la base normativa pasa por el ORÁCULO (verificar_cita)
    // antes de imprimirse; lo no cotejable queda SIN VERIFICAR, nunca afirmado.
    // El §4/§6 (`mapear_obligacion`) emite citas como texto, protegidas por el test
    // `todo_articulo_del_mapeo_esta_cotejado`; el §5 (`cumplimiento`) también rutea
    // cada cita por `verificar_cita` (ver `Item::obligacion_cotejada`).
    d.push_str(&marco_normativo());

    // §3
    let _ = writeln!(d, "## 3. Metodología y limitaciones\n");
    let _ = writeln!(d, "- Auditoría de caja negra con `nexus`/`autz` (recon, IDOR/BOLA, evasión de control de acceso, secretos, takeover, GraphQL, SSRF, escaneo de vulnerabilidades) sobre el programa `{}`.", meta.programa);
    let _ = writeln!(d, "- Cada hallazgo trae la evidencia que lo produjo (reproducibilidad).");
    let _ = writeln!(d, "- **LIMITACIÓN:** este documento cubre lo TÉCNICO externo. Lo organizacional/documental y lo de caja blanca (§5) requiere acceso o entrevista y NO está en esta pasada.\n");

    // §4
    let _ = writeln!(d, "## 4. Hallazgos técnicos\n");
    if reales.is_empty() {
        let _ = writeln!(d, "_Sin hallazgos técnicos en el alcance._\n");
    } else {
        for (i, f) in reales.iter().enumerate() {
            let _ = writeln!(d, "### H-{} · `{}` · Severidad: {}\n", i + 1, f.vuln_name, f.severity);
            let _ = writeln!(d, "- **URL / activo:** {}", f.url);
            if let Some(c) = &f.cwe {
                let _ = writeln!(d, "- **CWE:** {c}");
            }
            let _ = writeln!(d, "- **Estado de verificación:** {}", f.status);
            let ev = f.verification_evidence.as_deref().unwrap_or("[pendiente de adjuntar evidencia]");
            let _ = writeln!(d, "- **Evidencia / reproducción:** {ev}");
            let _ = writeln!(d, "- **Obligación legal incumplida:** {}", mapear_obligacion(&f.vuln_name));
            let _ = writeln!(d, "- **Remediación:** {{el arreglo en la regla, no en el caso}}\n");
        }
    }

    // §5: si el colector de cumplimiento lo llenó, se renderiza desde los
    // `Resultado`; si no, el checklist en blanco (el hueco a llenar por entrevista).
    if let Some(rs) = seccion5 {
        let s5 = crate::cumplimiento::generar_seccion5(rs);
        d.push_str(&s5);
        if !s5.ends_with('\n') {
            d.push('\n');
        }
    } else {
        let _ = writeln!(d, "## 5. Hallazgos organizacionales y de cumplimiento documental\n");
        let _ = writeln!(d, "> Recogido por checklist/entrevista — NO detectable por escaneo. \
                              Genera y llena la plantilla con `nexus cumplimiento --plantilla`.\n");
        for item in [
            "RNBD — bases de datos registradas y actualizadas",
            "Política de Tratamiento publicada y vigente",
            "Aviso de privacidad y AUTORIZACIÓN del titular (con prueba)",
            "Procedimiento de Habeas Data operativo y con tiempos",
            "Contratos de transmisión/transferencia (Encargados, país destino)",
            "Cifrado en reposo y gestión de llaves",
            "Retención y supresión al cesar la finalidad",
            "Registro de auditoría de accesos a datos sensibles",
            "Oficial/responsable de protección de datos designado",
            "Evaluación de impacto (tratamiento de alto riesgo)",
        ] {
            let _ = writeln!(d, "- [ ] {item}");
        }
        let _ = writeln!(d);
    }

    // §6 — mapeo hallazgo ↔ obligación. Incluye lo técnico (por tipo) Y los
    // incumplimientos organizacionales del §5, que antes no se mapeaban aquí.
    let corpus = crate::oraculo::corpus_proteccion_datos();
    let _ = writeln!(d, "## 6. Mapeo hallazgo ↔ obligación legal (de esta auditoría)\n");
    if reales.is_empty() && org.is_empty() {
        let _ = writeln!(d, "_Sin hallazgos que mapear._\n");
    } else {
        let _ = writeln!(d, "| Origen | Hallazgo | Severidad | Obligación incumplida |");
        let _ = writeln!(d, "|---|---|---|---|");
        let mut vistos: Vec<&str> = Vec::new();
        for f in &reales {
            if vistos.contains(&f.vuln_name.as_str()) {
                continue; // una fila por TIPO de hallazgo técnico
            }
            vistos.push(&f.vuln_name);
            let _ = writeln!(d, "| Técnico (§4) | `{}` | {} | {} |", f.vuln_name, f.severity, mapear_obligacion(&f.vuln_name));
        }
        for r in &org {
            let _ = writeln!(
                d, "| Organizacional (§5) | {} | {} | {} |",
                r.item.pregunta, r.item.severidad, r.item.obligacion_cotejada(&corpus)
            );
        }
        let _ = writeln!(d);
    }

    // §7 — plan de remediación REAL, ordenado por severidad (crítica → baja),
    // uniendo hallazgos técnicos e incumplimientos organizacionales. Ya no es
    // una plantilla `{...}`: sale de los hallazgos concretos.
    let _ = writeln!(d, "## 7. Plan de remediación priorizado\n");
    if reales.is_empty() && org.is_empty() {
        let _ = writeln!(d, "_Sin hallazgos que remediar en esta pasada._\n");
    } else {
        // (rango, severidad-etiqueta, qué, acción)
        let mut items: Vec<(u8, String, String, String)> = Vec::new();
        let mut vistos: Vec<String> = Vec::new();
        for f in &reales {
            if vistos.contains(&f.vuln_name) {
                continue;
            }
            vistos.push(f.vuln_name.clone());
            items.push((
                rango_sev(&f.severity),
                f.severity.clone(),
                format!("`{}` en {}", f.vuln_name, f.url),
                "corregir en la REGLA/código (no solo el caso), re-verificar por ejecución y adjuntar el diferencial".to_string(),
            ));
        }
        for r in &org {
            items.push((
                rango_sev(r.item.severidad),
                r.item.severidad.to_string(),
                r.item.pregunta.to_string(),
                if r.nota.is_empty() { "subsanar y dejar prueba documental para el Responsable".to_string() }
                else { format!("subsanar ({})", r.nota) },
            ));
        }
        items.sort_by_key(|(rango, _, _, _)| *rango);
        let _ = writeln!(d, "| # | Prioridad | Hallazgo | Acción | Plazo sugerido |");
        let _ = writeln!(d, "|---|---|---|---|---|");
        for (i, (rango, etiqueta, que, accion)) in items.iter().enumerate() {
            // plazo orientativo por severidad; el perito lo ajusta al pactar.
            let plazo = ["inmediato (≤72 h)", "≤15 días", "≤30 días", "≤90 días"][*rango as usize];
            let _ = writeln!(d, "| {} | {} | {} | {} | {} |", i + 1, etiqueta, que, accion, plazo);
        }
        let _ = writeln!(d);
    }

    // §8 — determinación SUSTANTIVA (ya no un `{...}`): resume el veredicto anclado
    // al artefacto y la fecha; la firma y los datos del perito quedan a la persona.
    let _ = writeln!(d, "## 8. Conclusión y dictamen del perito\n");
    let pendiente = if sin_verificar > 0 {
        format!(
            " Quedan **{sin_verificar} ítem(s) organizacional(es) SIN VERIFICAR** que deben cerrarse \
             (acceso/entrevista) antes de considerar este dictamen definitivo."
        )
    } else {
        String::new()
    };
    let _ = writeln!(
        d,
        "Con base en la auditoría de caja negra sobre el alcance `{}`, anclada al artefacto nexus \
         `{}` con fecha {}, y en la evaluación de cumplimiento organizacional (§5), el suscrito \
         perito **dictamina** que el tratamiento de datos personales del Responsable se encuentra en \
         la situación: _{}_. Se verificaron **{} hallazgo(s) técnico(s)** ({} crítico(s)/alto(s)) y \
         **{} incumplimiento(s) organizacional(es)** ({} alto(s)).{}\n",
        meta.programa, meta.binario, meta.fecha, veredicto,
        total, crit + alta, o_total, o_alta, pendiente
    );
    let _ = writeln!(
        d,
        "El presente dictamen se sostiene sobre el artefacto y la fecha declarados (directiva 31); \
         un cambio posterior en el sistema exige nueva verificación. Las citas normativas del §2 \
         están cotejadas contra su fuente oficial salvo las marcadas SIN VERIFICAR.\n"
    );
    let _ = writeln!(d, "**Firma del perito:** ______________________________  ");
    let _ = writeln!(d, "{{nombre}}, abogado y programador — T.P. {{tarjeta}} — {}  ", meta.fecha);

    d
}

/// Lee de la BD los findings de un programa (todos los estados; `generar`
/// excluye los FALSE_POSITIVE). Única parte con I/O.
pub async fn fetch(pool: &SqlitePool, programa: &str) -> anyhow::Result<Vec<FilaDictamen>> {
    let filas = sqlx::query_as::<_, FilaDictamen>(
        "SELECT vuln_name, severity, url, status, verification_evidence, cwe
         FROM findings
         WHERE program_name = ?1
         ORDER BY CASE lower(severity)
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2 ELSE 3 END, id",
    )
    .bind(programa)
    .fetch_all(pool)
    .await?;
    Ok(filas)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fila(vuln: &str, sev: &str, status: &str) -> FilaDictamen {
        FilaDictamen {
            vuln_name: vuln.into(),
            severity: sev.into(),
            url: "https://app.cliente.com/api/x".into(),
            status: status.into(),
            verification_evidence: Some("diferencial que lo produjo".into()),
            cwe: Some("CWE-284".into()),
        }
    }

    // El mapeo DISCRIMINA por tipo, y un tipo desconocido NO inventa artículo
    // específico (directiva 20): cae al principio de seguridad marcado a mano.
    #[test]
    fn mapear_obligacion_discrimina_y_no_inventa() {
        assert!(mapear_obligacion("control-de-acceso").contains("4(h)")); // IDOR: confidencialidad
        assert!(mapear_obligacion("control-de-acceso-evasion-403").contains("sin autorización"));
        assert!(mapear_obligacion("sql-injection").contains("MASIVA"));
        assert!(mapear_obligacion("subdomain-takeover").contains("17(d)"));
        assert!(mapear_obligacion("graphql-introspection-enabled").contains("esquema"));
        assert!(mapear_obligacion("ssrf-metadata-aws").contains("servidor"));
        // add-ons de datos en tránsito (TLS/cabeceras/cookies)
        assert!(mapear_obligacion("tls-no-https-redirect").contains("tránsito"));
        assert!(mapear_obligacion("tls-hsts-missing").contains("tránsito"));
        assert!(mapear_obligacion("cookie-sin-secure").contains("sesión"));
        assert!(mapear_obligacion("header-csp-missing").contains("defensa en profundidad"));
        assert!(mapear_obligacion("version-banner-expuesto").contains("versión"));
        // TLS profundo: protocolo obsoleto vs certificado (mapeos distintos)
        assert!(mapear_obligacion("tls-protocolo-1.0").contains("tránsito"));
        assert!(mapear_obligacion("tls-certificado-vencido").contains("certificado"));
        assert!(mapear_obligacion("tls-cifrado-rc4").contains("cifrado débil"));
        assert_ne!(
            mapear_obligacion("tls-protocolo-1.0"),
            mapear_obligacion("tls-certificado-vencido")
        );
        // IDOR y evasión NO comparten mapeo (discriminan)
        assert_ne!(
            mapear_obligacion("control-de-acceso"),
            mapear_obligacion("control-de-acceso-evasion-403")
        );
        // Desconocido → principio general marcado, jamás un artículo falso concreto.
        let desconocido = mapear_obligacion("algo-nunca-visto-2026");
        assert!(desconocido.contains("clasificar"));
        assert!(!desconocido.contains("17(d)"));
    }

    /// Extrae las referencias `N` y `N(l)` de un texto de `mapear_obligacion`.
    fn articulos_citados(s: &str) -> Vec<(u32, Option<char>)> {
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i].is_ascii_digit() {
                let ini = i;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                let num: u32 = s[ini..i].parse().unwrap();
                let lit = if i + 2 < b.len() && b[i] == b'(' && b[i + 1].is_ascii_alphabetic() && b[i + 2] == b')' {
                    Some(b[i + 1] as char)
                } else {
                    None
                };
                out.push((num, lit));
            } else {
                i += 1;
            }
        }
        out
    }

    // ACOPLAMIENTO §2↔cuerpo (hallazgo Obs 3 de la revisión 2026-08-26): el §2 lo
    // coteja el oráculo, pero §4/§6 emiten citas por `mapear_obligacion` como texto
    // crudo. Este candado exige que TODO artículo que ese mapeo emita esté cotejado
    // en el corpus: una rama futura que cite un artículo nuevo sin poblar rompe aquí,
    // en vez de afirmarse sin marca en un documento firmado.
    #[test]
    fn todo_articulo_del_mapeo_esta_cotejado() {
        use crate::oraculo::{corpus_proteccion_datos, verificar_cita, Cita, Veredicto};
        let corpus = corpus_proteccion_datos();
        // Un vuln_name por CADA rama de mapear_obligacion (más el desconocido).
        let tipos = [
            "control-de-acceso-idor", "control-de-acceso-evasion-403", "sql-injection",
            "ssrf-metadata-aws", "reflected-xss", "aws-secret-key", "subdomain-takeover",
            "mass-assignment", "graphql-introspection-enabled", "varnish-cache-purge",
            "tls-cifrado-3des", "tls-certificado-vencido", "tls-protocolo-1.0",
            "cookie-sin-secure", "header-csp-missing", "version-banner", "CVE-2021-44228",
            "algo-nunca-visto-2026",
        ];
        for t in tipos {
            for (art, lit) in articulos_citados(mapear_obligacion(t)) {
                let cita = Cita { norma: "Ley 1581 de 2012".to_string(), articulo: art, literal: lit };
                assert!(
                    matches!(verificar_cita(&cita, &corpus), Veredicto::Existe { .. }),
                    "mapear_obligacion({t}) cita Art.{art}{} — NO está cotejado en el corpus",
                    lit.map(|c| format!("({c})")).unwrap_or_default()
                );
            }
        }
    }

    // Control de la exclusión (directiva 33): un FALSE_POSITIVE NO entra en el
    // dictamen, y su severidad no infla el resumen. El caso rojo comparte causa
    // con el positivo (un high real SÍ entra).
    #[test]
    fn generar_excluye_falsos_positivos_y_cuenta_bien() {
        let meta = Meta { programa: "acme", fecha: "2026-08-21", binario: "test" };
        let filas = vec![
            fila("control-de-acceso", "critical", "VERIFIED"),   // entra
            fila("subdomain-takeover", "high", "NEW"),           // entra
            fila("control-de-acceso-evasion-403", "medium", "FALSE_POSITIVE"), // NO entra
        ];
        let doc = generar(&meta, &filas, None);
        // el FP no aparece por ningún lado
        assert!(!doc.contains("evasion-403"), "el FALSE_POSITIVE no debe aparecer");
        // los reales sí
        assert!(doc.contains("control-de-acceso"));
        assert!(doc.contains("subdomain-takeover"));
        // conteo: 1 crítica, 1 alta, 0 media (el medium era FP), total 2
        assert!(doc.contains("| Crítica | 1 |"));
        assert!(doc.contains("| Alta | 1 |"));
        assert!(doc.contains("| Media | 0 |"));
        assert!(doc.contains("**Total (sin falsos positivos)** | **2**"));
        // veredicto NO CUMPLE porque hay crítica/alta
        assert!(doc.contains("NO CUMPLE"));
        // trae el §5 (el hueco) y el anclaje
        assert!(doc.contains("RNBD"));
        assert!(doc.contains("nexus `test`"));
    }

    // El §2 lo genera el ORÁCULO: las citas cotejadas salen con ✓ y su fuente
    // oficial; lo no cotejable (Decreto/SIC) sale SIN VERIFICAR, nunca afirmado.
    #[test]
    fn seccion2_la_respalda_el_oraculo() {
        let meta = Meta { programa: "acme", fecha: "2026-08-26", binario: "t" };
        let doc = generar(&meta, &[], None);
        // las 7 citas cotejadas de la Ley 1581 aparecen con ✓ y su fuente
        assert!(doc.contains("✓ **Ley 1581 de 2012 Art. 4(g)**"), "4(g) debe salir cotejado");
        assert!(doc.contains("✓ **Ley 1581 de 2012 Art. 17(d)**"), "17(d) debe salir cotejado");
        assert!(doc.contains("secretariasenado.gov.co"), "debe declarar la fuente cotejada");
        // el Decreto 1377 ahora está cotejado (funcionpublica): sale con ✓, no SIN VERIFICAR
        assert!(doc.contains("✓ **Decreto 1377 de 2013 Art. 13**"), "el Decreto Art. 13 cotejado");
        assert!(doc.contains("funcionpublica.gov.co"), "declara la fuente del Decreto");
        assert!(!doc.contains("SIN VERIFICAR** Decreto"), "el Decreto ya NO va SIN VERIFICAR");
        // ya NO quedan los antiguos marcadores "[verificar arts.]"
        assert!(!doc.contains("[verificar arts.]"), "el hueco [verificar] debe estar cerrado");
        // la circular/guía de la SIC (sin fuente) sigue SIN VERIFICAR
        assert!(doc.contains("SIN VERIFICAR** circular/guía vigente de la Superintendencia"),
            "la circular SIC sigue sin cotejar");
    }

    #[test]
    fn generar_sin_hallazgos_no_dice_no_cumple() {
        let meta = Meta { programa: "limpio", fecha: "2026-08-21", binario: "t" };
        let doc = generar(&meta, &[], None);
        assert!(doc.contains("SIN HALLAZGOS TÉCNICOS"));
        assert!(!doc.contains("NO CUMPLE"));
        // el §5 organizacional SIGUE apareciendo (no exime)
        assert!(doc.contains("Habeas Data"));
    }

    // Cuando el colector de cumplimiento llenó el §5, se INSERTA en vez del
    // checklist en blanco (integración con `cumplimiento`).
    #[test]
    fn generar_inserta_el_seccion5_llenado() {
        let meta = Meta { programa: "acme", fecha: "2026-08-21", binario: "t" };
        let rs = crate::cumplimiento::evaluar("autorizacion: no_cumple\nrnbd: cumple\n");
        let doc = generar(&meta, &[], Some(&rs));
        assert!(doc.contains("**Resumen:**"), "usa el §5 llenado");
        // y NO deja el checklist en blanco cuando se pasó uno lleno
        assert!(!doc.contains("- [ ] RNBD"), "no debe quedar el checklist vacío");
    }

    // ARREGLO 1 (§1 cuenta lo organizacional): un incumplimiento ALTO del §5, con
    // CERO hallazgos técnicos, debe volcar el veredicto a NO CUMPLE y contar en la
    // columna organizacional. Antes §1 decía «SIN HALLAZGOS» ignorando el §5.
    // Control (D33): el MISMO documento sin ese incumplimiento NO dice NO CUMPLE.
    #[test]
    fn seccion1_cuenta_incumplimientos_organizacionales() {
        let meta = Meta { programa: "acme", fecha: "2026-09-20", binario: "t" };
        // rojo: cifrado_reposo (severidad alta) NO cumple, 0 técnicos
        let rojo = generar(&meta, &[], Some(&crate::cumplimiento::evaluar("cifrado_reposo: no_cumple\n")));
        assert!(rojo.contains("NO CUMPLE"), "un incumplimiento organizacional ALTO vuelca el veredicto");
        assert!(rojo.contains("| Alta | 0 | 1 |"), "el alto organizacional cuenta en §1 (téc 0, org 1)");
        // verde/control: el mismo ítem CUMPLE → no hay NO CUMPLE por esta vía
        let verde = generar(&meta, &[], Some(&crate::cumplimiento::evaluar("cifrado_reposo: cumple\n")));
        assert!(!verde.contains("NO CUMPLE"), "sin incumplimiento no debe decir NO CUMPLE");
    }

    // ARREGLO 2 (§6 mapea el §5): los incumplimientos organizacionales aparecen en
    // la tabla de mapeo con su obligación, no solo los técnicos.
    #[test]
    fn seccion6_mapea_los_incumplimientos_del_seccion5() {
        let meta = Meta { programa: "acme", fecha: "2026-09-20", binario: "t" };
        let rs = crate::cumplimiento::evaluar("habeas_data: no_cumple\n");
        let doc = generar(&meta, &[], Some(&rs));
        let s6 = doc.split("## 6.").nth(1).unwrap_or("").split("## 7.").next().unwrap_or("");
        assert!(s6.contains("Organizacional (§5)"), "§6 marca el origen organizacional");
        assert!(s6.contains("Habeas Data") || s6.contains("consultas y reclamos"), "§6 nombra el incumplimiento");
    }

    // ARREGLO 3 (§7 plan real): ya NO es la plantilla `{...}`; lista los hallazgos
    // ordenados por severidad, con acción y plazo.
    #[test]
    fn seccion7_es_plan_real_no_plantilla() {
        let meta = Meta { programa: "acme", fecha: "2026-09-20", binario: "t" };
        let doc = generar(&meta, &[fila("sql-injection", "critical", "VERIFIED")],
            Some(&crate::cumplimiento::evaluar("oficial_datos: no_cumple\n")));
        let s7 = doc.split("## 7.").nth(1).unwrap_or("").split("## 8.").next().unwrap_or("");
        assert!(!s7.contains("{ordenar"), "el §7 ya no es plantilla");
        assert!(s7.contains("Plazo sugerido"), "el §7 trae plazos");
        // la crítica técnica va ANTES que la baja organizacional (orden por severidad)
        let pos_sql = s7.find("sql-injection").unwrap();
        let pos_oficial = s7.find("responsable de la protección").unwrap_or(usize::MAX);
        assert!(pos_sql < pos_oficial, "la crítica se prioriza sobre la baja");
    }

    // ARREGLO 4 (§8 determinación real): ya NO es `{...}`; emite la determinación
    // con el veredicto, el anclaje al artefacto y la línea de firma.
    #[test]
    fn seccion8_emite_determinacion_no_plantilla() {
        let meta = Meta { programa: "medico", fecha: "2026-09-20", binario: "9.9" };
        let doc = generar(&meta, &[fila("control-de-acceso", "high", "VERIFIED")], None);
        let s8 = doc.split("## 8.").nth(1).unwrap_or("");
        assert!(!s8.contains("{determinación"), "el §8 ya no es plantilla");
        assert!(s8.contains("dictamina"), "el §8 emite una determinación");
        assert!(s8.contains("medico") && s8.contains("9.9"), "ancla al alcance y al artefacto (D31)");
        assert!(s8.contains("Firma del perito"), "trae la línea de firma");
    }

    // Los SIN VERIFICAR impiden el veredicto limpio y se avisan en §1 (D20).
    #[test]
    fn sin_verificar_bloquea_el_veredicto_limpio() {
        let meta = Meta { programa: "acme", fecha: "2026-09-20", binario: "t" };
        // solo un ítem respondido cumple; los demás quedan SIN VERIFICAR
        let doc = generar(&meta, &[], Some(&crate::cumplimiento::evaluar("rnbd: cumple\n")));
        assert!(doc.contains("SIN VERIFICAR"), "avisa de los no verificados");
        assert!(!doc.contains("SIN HALLAZGOS en el alcance auditado (técnico y organizacional)"),
            "no puede declarar limpio total con ítems sin verificar");
    }
}
