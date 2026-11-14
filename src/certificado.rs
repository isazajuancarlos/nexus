//! Certificado de verificación anti-«scanner-slop».
//!
//! Contexto (2026-09-05): el mercado de bug bounty está saturado de reportes
//! generados por IA sin impacto real («AI slop»); curl reporta ~20% de envíos
//! slop y ~5% reales, y programas como CycloneDX cerraron su bounty por la
//! avalancha. Las plataformas responden con gating por reputación. En ese mundo
//! el activo escaso no es el volumen sino la SEÑAL VERIFICADA legible al triaje.
//!
//! Este módulo hace DOS cosas con una sola pieza compartida (directiva 9):
//!   1. **Renderiza** un bloque que pone el rigor AL FRENTE del reporte —control
//!      diferencial reproducible, evidencia capturada, herramienta, ancla de
//!      versión y qué lo invalidaría— para que un triador saturado distinga
//!      nuestro reporte del slop en el primer vistazo.
//!   2. **Es la PUERTA** (`es_valido`): el mismo predicado que decide si un
//!      hallazgo puede salir. Espeja en Rust puro (testable sin BD) el gate SQL
//!      de `db::fetch_autosubmit`, y además cubre el camino de reporte MANUAL,
//!      que no tenía tal sello. Sin certificado válido, el cuerpo del reporte
//!      lleva un banner «NO ENVIAR» en vez de afirmar «CONFIRMADO».
//!
//! Puro y sin dependencias: se prueba con parejas discriminantes (directiva 33).

/// El certificado de un hallazgo: los hechos que lo separan del slop.
#[derive(Debug, Clone, Default)]
pub struct Certificado {
    /// NEXUS lo VIO ejecutar/reproducir de verdad (no la palabra de la herramienta).
    pub execution_confirmed: bool,
    /// Control diferencial reproducible: «aciertos/intentos», p. ej. "3/3". Un
    /// hallazgo intermitente ("1/3") lo cierra el triager como "not reproducible".
    pub repro_ratio: Option<String>,
    /// Hay evidencia CAPTURADA no vacía (no la promesa de que existe).
    pub evidencia_presente: bool,
    /// Con qué se verificó (sqlmap, navegador real, re-fetch…). No vale
    /// none/manual/batch/vacío: eso es «lo dijo el catálogo», no ejecución.
    pub herramienta: Option<String>,
    /// Confianza declarada por el verificador (high/medium/low), informativa.
    pub confianza: Option<String>,
    /// El hallazgo se confirmó por un ORÁCULO DIFERENCIAL (control positivo Y
    /// negativo por construcción), no por repetición. Es la OTRA forma de probar
    /// "no es slop" (directiva 32: reproducibilidad-por-repetición y
    /// discriminación-por-diferencial son dos magnitudes, no una). La produce autz
    /// (una identidad ve el 2xx del dueño y otra/anónimo no), el OOB (callback =
    /// control positivo por construcción) y el content-check de SSRF in-band. Para
    /// estas clases el CONTROL es la confirmación misma; no hay un `n/n` que dar, y
    /// exigir uno bloquearía el edge (IDOR/BAC como Liberapay/Zitadel).
    pub diferencial: bool,
    /// Clase de vulnerabilidad (para nombrar el control que aplicaría).
    pub clase: String,
    /// Ancla de versión de NEXUS que produjo el certificado (directiva 31: un
    /// veredicto sin ancla caduca sin avisar).
    pub ancla: String,
}

impl Certificado {
    /// ¿El control diferencial es POSITIVO y reproducible? Exige `n/n` con n≥1:
    /// todos los intentos aciertan. Un `1/3` (intermitente) o un `0/x` NO pasan.
    ///
    /// Espeja la intención del gate SQL (`repro_ratio` se registra justo para no
    /// auto-enviar lo intermitente). Formato tolerante: espacios alrededor de `/`.
    pub fn repro_positivo(&self) -> bool {
        let Some(r) = self.repro_ratio.as_deref() else { return false };
        let Some((a, b)) = r.split_once('/') else { return false };
        match (a.trim().parse::<u32>(), b.trim().parse::<u32>()) {
            (Ok(aciertos), Ok(intentos)) => intentos >= 1 && aciertos == intentos,
            _ => false,
        }
    }

    /// ¿La herramienta es un verificador REAL y no un sello de catálogo? Espeja el
    /// `NOT IN ('none','','batch','manual')` del gate SQL de `fetch_autosubmit`.
    pub fn herramienta_real(&self) -> bool {
        match self.herramienta.as_deref() {
            Some(t) => !matches!(t.trim().to_lowercase().as_str(), "" | "none" | "batch" | "manual"),
            None => false,
        }
    }

    /// ¿Hay un CONTROL válido? O bien un ratio reproducible `n/n` (clases por
    /// repetición: XSS/SQLi/cmdi) O bien un oráculo diferencial confirmado (clases
    /// por discriminación: authz/SSRF). Uno de los dos basta; los dos prueban lo
    /// mismo —que no es slop— por vías distintas (directiva 32).
    pub fn control_valido(&self) -> bool {
        self.repro_positivo() || self.diferencial
    }

    /// LA PUERTA. Un hallazgo solo cuenta como certificado —y solo puede salir—
    /// si se vio EJECUTAR, tiene un CONTROL válido (ratio reproducible o diferencial
    /// confirmado), hay evidencia capturada y la verificó una herramienta real. Es
    /// un AND: quitar cualquier pata lo tumba (probado con la pareja discriminante).
    /// Es el mismo listón que el gate SQL, pero en Rust puro y aplicado también al
    /// reporte manual.
    pub fn es_valido(&self) -> bool {
        self.execution_confirmed
            && self.control_valido()
            && self.evidencia_presente
            && self.herramienta_real()
    }

    /// El bloque markdown, para ir AL FRENTE del reporte (tras el título/severidad).
    /// Válido → sello verde con el control diferencial legible. Inválido → banner
    /// «NO ENVIAR» que nombra QUÉ falta, para que el hueco no pase por confirmado.
    pub fn render(&self) -> String {
        let mut s = String::new();
        if self.es_valido() {
            s.push_str("## ✅ Certificado de verificación (no es «scanner-slop»)\n");
            s.push_str("Este hallazgo NO es salida cruda de un escáner: se confirmó por ejecución con un control diferencial reproducible.\n\n");
            s.push_str(&format!(
                "- **Confirmado por ejecución:** sí — {}\n",
                self.herramienta.as_deref().unwrap_or("verificador real")
            ));
            if self.repro_positivo() {
                s.push_str(&format!(
                    "- **Control (reproducibilidad):** {} — todos los intentos aciertan\n",
                    self.repro_ratio.as_deref().unwrap_or("n/n")
                ));
            } else {
                s.push_str(
                    "- **Control (diferencial):** confirmado por oráculo diferencial \
                     (control positivo Y negativo por construcción: el sujeto autorizado \
                     ve el recurso y el no autorizado/anónimo no)\n",
                );
            }
            s.push_str("- **Evidencia capturada:** sí (ver «Evidencia de verificación» y «Prueba»)\n");
            if let Some(c) = &self.confianza {
                s.push_str(&format!("- **Confianza del verificador:** {c}\n"));
            }
            s.push_str(&format!("- **Ancla:** {}\n", self.ancla));
            s.push_str(&format!(
                "- **Qué invalidaría esto:** que el control diferencial deje de ser reproducible \
                 (un `{}` que baje a intermitente), o que el parche cierre la clase {} en el \
                 recurso probado.\n\n",
                self.repro_ratio.as_deref().unwrap_or("n/n"),
                self.clase.to_uppercase()
            ));
        } else {
            s.push_str("## ⚠️ SIN CERTIFICADO — NO ENVIAR\n");
            s.push_str("Este hallazgo NO cruzó la puerta anti-slop. Enviarlo quema reputación en un mercado que ya filtra por señal. Falta:\n\n");
            if !self.execution_confirmed {
                s.push_str("- **Confirmación por ejecución:** NO se vio ejecutar/reproducir (solo la palabra de la herramienta).\n");
            }
            if !self.control_valido() {
                s.push_str(&format!(
                    "- **Control:** falta. Se exige O un ratio reproducible `n/n` con n≥1 \
                     (repetición: XSS/SQLi) O un oráculo diferencial confirmado \
                     (authz/SSRF). Ratio actual: {}.\n",
                    self.repro_ratio.as_deref().unwrap_or("ausente")
                ));
            }
            if !self.evidencia_presente {
                s.push_str("- **Evidencia capturada:** ausente o vacía (directiva 30: sin evidencia no es auditable).\n");
            }
            if !self.herramienta_real() {
                s.push_str("- **Verificador real:** la «verificación» es none/manual/batch/vacío, no ejecución.\n");
            }
            s.push('\n');
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_valido() -> Certificado {
        Certificado {
            execution_confirmed: true,
            repro_ratio: Some("3/3".into()),
            evidencia_presente: true,
            herramienta: Some("sqlmap".into()),
            confianza: Some("high".into()),
            diferencial: false,
            clase: "sqli".into(),
            ancla: "nexus v0.1.0".into(),
        }
    }

    /// Un authz confirmado por diferencial: SIN `n/n` pero con control diferencial.
    /// Es el edge (IDOR/BAC como Liberapay/Zitadel) — DEBE certificar.
    fn base_diferencial() -> Certificado {
        Certificado {
            execution_confirmed: true,
            repro_ratio: None,          // authz no da n/n…
            diferencial: true,          // …da control positivo/negativo por construcción
            evidencia_presente: true,
            herramienta: Some("autz".into()),
            confianza: Some("high".into()),
            clase: "bac".into(),
            ancla: "nexus v0.1.0".into(),
        }
    }

    #[test]
    fn authz_confirmado_por_diferencial_certifica_sin_ratio() {
        let c = base_diferencial();
        assert!(c.control_valido());
        assert!(c.es_valido(), "el edge (IDOR/BAC) no debe bloquearse por no dar n/n");
        let r = c.render();
        assert!(r.contains("Certificado de verificación"));
        assert!(r.contains("Control (diferencial)"));
        assert!(!r.contains("NO ENVIAR"));
    }

    #[test]
    fn diferencial_sin_ejecucion_confirmada_sigue_cayendo() {
        // Pareja (directiva 33): el diferencial NO es un pase libre — sin ejecución
        // confirmada (p. ej. keyless MANUAL_READY, execution_confirmed=0) cae igual.
        let mut c = base_diferencial();
        c.execution_confirmed = false;
        assert!(!c.es_valido());
        assert!(c.render().contains("NO ENVIAR"));
    }

    #[test]
    fn sin_ratio_ni_diferencial_no_hay_control() {
        let mut c = base_diferencial();
        c.diferencial = false; // ni n/n ni diferencial
        assert!(!c.control_valido());
        assert!(!c.es_valido());
        assert!(c.render().contains("Control:"));
    }

    #[test]
    fn certificado_completo_es_valido_y_rinde_sello_verde() {
        let c = base_valido();
        assert!(c.es_valido());
        let r = c.render();
        assert!(r.contains("Certificado de verificación"));
        assert!(r.contains("3/3"));
        assert!(r.contains("Qué invalidaría esto"));
        assert!(!r.contains("NO ENVIAR"));
    }

    // Pareja discriminante (directiva 33): cada pata quitada DEBE tumbar la puerta
    // por la vía real, y el banner DEBE nombrar justo lo que falta.

    #[test]
    fn sin_ejecucion_confirmada_cae_la_puerta() {
        let mut c = base_valido();
        c.execution_confirmed = false;
        assert!(!c.es_valido());
        let r = c.render();
        assert!(r.contains("NO ENVIAR"));
        assert!(r.contains("Confirmación por ejecución"));
    }

    #[test]
    fn repro_intermitente_cae_la_puerta() {
        // El mutante clásico: aceptar "1/3" como positivo. Debe FALLAR aquí.
        let mut c = base_valido();
        c.repro_ratio = Some("1/3".into());
        assert!(!c.repro_positivo(), "1/3 NO es control positivo");
        assert!(!c.es_valido());
        assert!(c.render().contains("Control:"));
    }

    #[test]
    fn repro_ausente_o_malformado_cae() {
        let mut c = base_valido();
        c.repro_ratio = None;
        assert!(!c.es_valido());
        c.repro_ratio = Some("basura".into());
        assert!(!c.repro_positivo());
        c.repro_ratio = Some("3/0".into()); // intentos=0 no vale
        assert!(!c.repro_positivo());
    }

    #[test]
    fn sin_evidencia_cae_la_puerta() {
        let mut c = base_valido();
        c.evidencia_presente = false;
        assert!(!c.es_valido());
        assert!(c.render().contains("Evidencia capturada"));
    }

    #[test]
    fn herramienta_de_catalogo_no_es_verificador() {
        for falsa in ["", "none", "manual", "batch", "MANUAL", " None "] {
            let mut c = base_valido();
            c.herramienta = Some(falsa.into());
            assert!(!c.herramienta_real(), "{falsa:?} no debe contar como verificador");
            assert!(!c.es_valido());
        }
        // control positivo: una real sí pasa
        let mut c = base_valido();
        c.herramienta = Some("navegador-real".into());
        assert!(c.herramienta_real());
    }

    #[test]
    fn repro_positivo_tolera_espacios() {
        let mut c = base_valido();
        c.repro_ratio = Some(" 5 / 5 ".into());
        assert!(c.repro_positivo());
    }
}
