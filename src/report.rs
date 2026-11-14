//! Generación de informes. Portado de `reporting.py` (agrupar por vuln, ordenar
//! por severidad) y las plantillas CVSS de `submitter.py`.

use crate::db::Finding;
use std::collections::BTreeMap;

/// Orden canónico de severidades (menor = más grave).
pub fn severity_rank(sev: &str) -> u8 {
    match sev.to_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}

/// CVSS base por tipo de vulnerabilidad (de submitter.py).
pub fn cvss_for(vuln_type: &str) -> (f32, &'static str) {
    match vuln_type.to_lowercase().as_str() {
        "sqli" | "cmdi" | "rce" => (9.8, "Critical"),
        "ssrf" => (9.1, "Critical"),
        "lfi" => (7.5, "High"),
        "xss" => (6.1, "Medium"),
        _ => (0.0, "Unknown"),
    }
}

/// Construye el informe markdown a partir de los hallazgos.
pub fn build_markdown(findings: &[Finding], targets_scanned: &str) -> String {
    let mut by_sev: BTreeMap<u8, usize> = BTreeMap::new();
    // Agrupar por vuln_name → (severidad, urls)
    let mut grouped: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    for f in findings {
        *by_sev.entry(severity_rank(&f.severity)).or_insert(0) += 1;
        let e = grouped.entry(f.vuln_name.clone()).or_insert((f.severity.clone(), Vec::new()));
        e.1.push(f.url.clone());
    }

    // Orden de vulnerabilidades por severidad.
    let mut vulns: Vec<(&String, &(String, Vec<String>))> = grouped.iter().collect();
    vulns.sort_by_key(|(_, (sev, _))| severity_rank(sev));

    let mut out = String::new();
    out.push_str("# Informe de escaneo de vulnerabilidades\n\n");
    out.push_str(&format!("**Generado (UTC):** {}\n\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")));
    out.push_str("## Resumen\n\n");
    out.push_str(&format!("- **Objetivos escaneados:** {targets_scanned}\n"));
    out.push_str(&format!("- **Hallazgos totales:** {}\n", findings.len()));
    if !by_sev.is_empty() {
        out.push_str("- **Por severidad:**\n");
        for (rank, count) in &by_sev {
            let name = ["Critical", "High", "Medium", "Low", "Info", "Unknown"][*rank as usize];
            out.push_str(&format!("  - **{name}:** {count}\n"));
        }
    }
    out.push('\n');

    if !findings.is_empty() {
        out.push_str("## Hallazgos detallados\n\n");
        out.push_str("Agrupados por vulnerabilidad y activos afectados.\n");
        for (vuln, (sev, urls)) in vulns {
            out.push_str(&format!("\n### {vuln} ({})\n", capitalize(sev)));
            out.push_str(&format!("**Activos afectados:** {}\n\n", urls.len()));
            out.push_str("```\n");
            let mut sorted = urls.clone();
            sorted.sort();
            for u in sorted {
                out.push_str(&u);
                out.push('\n');
            }
            out.push_str("```\n");
        }
    }
    out
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severidad_ordena_bien() {
        assert!(severity_rank("critical") < severity_rank("high"));
        assert!(severity_rank("high") < severity_rank("low"));
        assert_eq!(severity_rank("desconocida"), 5);
    }

    #[test]
    fn cvss_conocido() {
        assert_eq!(cvss_for("sqli"), (9.8, "Critical"));
        assert_eq!(cvss_for("xss").1, "Medium");
    }
}
