// SPDX-License-Identifier: LicenseRef-Propietario
//! Colector del §5 del dictamen: lo ORGANIZACIONAL/DOCUMENTAL que un escáner de
//! caja negra NO ve (RNBD, política, autorización, Habeas Data, cifrado en reposo,
//! retención, logs de acceso, oficial de datos, DPIA). El auditor llena un archivo
//! de respuestas (checklist) durante el encargo; esto lo evalúa y produce el §5,
//! mapeando cada incumplimiento a su obligación de la Ley 1581.
//!
//! Directiva 20: lo NO respondido se marca **SIN VERIFICAR**, jamás se asume
//! cumplido — un checklist que rellena huecos con "cumple" es peor que uno que
//! falta, porque firma un dictamen falso.
//!
//! Nota legal: las citas de artículos son un primer paso del ingeniero; el abogado
//! verifica la numeración exacta (marcadas `[verificar]`).

use std::collections::HashMap;
use std::fmt::Write as _;

/// Un ítem del catálogo de cumplimiento organizacional.
///
/// Las citas a la Ley 1581 son ESTRUCTURADAS (`citas`), no prosa: el §5 las rutea
/// por `oraculo::verificar_cita` y las marca ✓/SIN VERIFICAR igual que el §2. Lo
/// que el oráculo NO puede cotejar hoy —Decreto 1377, circular SIC— va en `extra`
/// como texto libre marcado `[verificar]` (dir. 20: no se afirma sin cotejo).
pub struct Item {
    pub id: &'static str,
    pub pregunta: &'static str,
    /// Citas `(norma, artículo, literal)` que el oráculo coteja (Ley 1581 o
    /// Decreto 1377). La norma es la cadena EXACTA del corpus.
    pub citas: &'static [(&'static str, u32, Option<char>)],
    /// Base normativa NO cotejable por el oráculo (p. ej. circular SIC): texto libre.
    pub extra: &'static str,
    /// Severidad si el ítem NO se cumple.
    pub severidad: &'static str,
}

/// Nombres de norma, para no repetir la cadena en cada ítem del catálogo.
const L: &str = "Ley 1581 de 2012";
const D: &str = "Decreto 1377 de 2013";

/// El catálogo del §5. Es contenido jurídico, curado; crece con la práctica.
pub const CATALOGO: &[Item] = &[
    Item {
        id: "rnbd",
        pregunta: "¿Bases de datos registradas y actualizadas en el RNBD?",
        citas: &[(L, 25, None)],
        extra: "",
        severidad: "media",
    },
    Item {
        id: "politica",
        pregunta: "¿Política de Tratamiento de la Información publicada y vigente?",
        citas: &[(D, 13, None)],
        extra: "",
        severidad: "media",
    },
    Item {
        id: "aviso",
        pregunta: "¿Aviso de privacidad conforme y disponible al titular?",
        citas: &[(D, 14, None), (D, 15, None)],
        extra: "",
        severidad: "media",
    },
    Item {
        id: "autorizacion",
        pregunta: "¿Autorización previa, expresa e informada del titular, con PRUEBA conservada?",
        // D8 = Prueba de la autorización, que es literalmente lo que pregunta el ítem.
        citas: &[(L, 9, None), (D, 4, None), (D, 5, None), (D, 6, None), (D, 8, None)],
        extra: "",
        severidad: "alta",
    },
    Item {
        id: "habeas_data",
        pregunta: "¿Procedimiento de consultas y reclamos (Habeas Data) operativo y con tiempos?",
        citas: &[(L, 8, None), (L, 14, None), (L, 15, None)],
        extra: "",
        severidad: "alta",
    },
    Item {
        id: "transferencias",
        pregunta: "¿Contratos de transmisión (Encargados) y control de transferencia internacional?",
        citas: &[(L, 26, None)],
        extra: "+ Decreto 1377 (transmisión) [verificar]",
        severidad: "alta",
    },
    Item {
        id: "cifrado_reposo",
        pregunta: "¿Datos personales cifrados en reposo, con gestión de llaves?",
        citas: &[(L, 4, Some('g')), (L, 17, Some('d'))],
        extra: "",
        severidad: "alta",
    },
    Item {
        id: "retencion",
        pregunta: "¿Supresión de datos al cesar la finalidad (no conservación indefinida)?",
        // «finalidad» es Art. 4(b) (cotejado). La base de temporalidad/supresión la
        // precisa el abogado (el Art. 11 NO es temporalidad — cotejado 2026-08-26).
        citas: &[(L, 4, Some('b'))],
        extra: "+ base de temporalidad/supresión a precisar (el Art. 11 NO es temporalidad) [verificar]",
        severidad: "media",
    },
    Item {
        id: "auditoria_accesos",
        pregunta: "¿Registro/trazabilidad de accesos a datos sensibles?",
        citas: &[(L, 4, Some('g')), (L, 17, Some('d'))],
        extra: "",
        severidad: "media",
    },
    Item {
        id: "oficial_datos",
        pregunta: "¿Área o persona responsable de la protección de datos designada?",
        citas: &[(D, 23, None)],
        extra: "",
        severidad: "baja",
    },
    Item {
        id: "dpia",
        pregunta: "¿Evaluación de impacto para tratamiento de alto riesgo o datos sensibles?",
        // Base normativa = responsabilidad demostrada (D26 Demostración + D27
        // políticas internas efectivas): medidas proporcionales al riesgo y al tipo
        // de dato — el hogar del deber de evaluar el impacto de alto riesgo.
        citas: &[(D, 26, None), (D, 27, None)],
        // El deber de EVALUAR el impacto de alto riesgo no es un artículo explícito
        // en Colombia: deriva de la Guía de responsabilidad demostrada de la SIC.
        extra: "+ Guía de responsabilidad demostrada de la SIC (evaluación de impacto para alto riesgo) [verificar]",
        severidad: "media",
    },
];

impl Item {
    /// Renderiza la obligación pasando cada cita por el ORÁCULO: `Art. N(l)
    /// sumilla ✓` si está cotejada, `SIN VERIFICAR` si no; luego el texto `extra`
    /// (Decreto/SIC). Es la misma inversión que el §2 aplicada al §5 — ninguna
    /// cita de Ley se afirma sin respaldo (dir. 20/25).
    pub fn obligacion_cotejada(&self, corpus: &[crate::oraculo::ArticuloOficial]) -> String {
        use crate::oraculo::{verificar_cita, Cita, Veredicto};
        let citas_str = self
            .citas
            .iter()
            .map(|&(norma, articulo, literal)| {
                let c = Cita { norma: norma.to_string(), articulo, literal };
                let ref_ = c.referencia();
                match verificar_cita(&c, corpus) {
                    Veredicto::Existe { sumilla, .. } => format!("{ref_} {sumilla} ✓"),
                    Veredicto::SinVerificar { sumilla } => format!("{ref_} {sumilla} SIN VERIFICAR"),
                    Veredicto::NoExiste => format!("{ref_} SIN VERIFICAR (fuera del corpus)"),
                }
            })
            .collect::<Vec<_>>()
            .join(" + ");
        match (citas_str.is_empty(), self.extra.is_empty()) {
            (false, false) => format!("{citas_str} {}", self.extra), // extra empieza por "+ "
            (false, true) => citas_str,
            (true, _) => self.extra.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Respuesta {
    Cumple,
    NoCumple,
    NoAplica,
    /// No respondido o valor no reconocido: NO se asume nada (directiva 20).
    SinVerificar,
}

impl Respuesta {
    /// Interpreta el valor escrito por el auditor. Lo desconocido cae en
    /// SinVerificar (falla ruidoso), nunca en Cumple.
    pub fn parsear(v: &str) -> Respuesta {
        match v.trim().to_ascii_lowercase().as_str() {
            "cumple" | "si" | "sí" | "ok" => Respuesta::Cumple,
            "no_cumple" | "no cumple" | "no" | "falla" => Respuesta::NoCumple,
            "no_aplica" | "na" | "n/a" => Respuesta::NoAplica,
            _ => Respuesta::SinVerificar,
        }
    }
    pub fn etiqueta(self) -> &'static str {
        match self {
            Respuesta::Cumple => "✅ cumple",
            Respuesta::NoCumple => "❌ NO CUMPLE",
            Respuesta::NoAplica => "— no aplica",
            Respuesta::SinVerificar => "⚠️ SIN VERIFICAR",
        }
    }
}

pub struct Resultado {
    pub item: &'static Item,
    pub respuesta: Respuesta,
    pub nota: String,
}

/// Parsea el archivo de respuestas: líneas `id: valor  # nota opcional`. Las
/// líneas en blanco y las que empiezan por `#` se ignoran. Devuelve id → (valor, nota).
fn parsear_archivo(texto: &str) -> HashMap<String, (String, String)> {
    let mut m = HashMap::new();
    for linea in texto.lines() {
        let l = linea.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let Some((id, resto)) = l.split_once(':') else {
            continue;
        };
        // separar la nota (tras un '#') del valor
        let (valor, nota) = match resto.split_once('#') {
            Some((v, n)) => (v.trim().to_string(), n.trim().to_string()),
            None => (resto.trim().to_string(), String::new()),
        };
        m.insert(id.trim().to_ascii_lowercase(), (valor, nota));
    }
    m
}

/// Evalúa las respuestas contra el catálogo COMPLETO: cada ítem del catálogo
/// aparece en el resultado; el que no fue respondido queda SIN VERIFICAR
/// (directiva 20: el hueco se ve, no se rellena).
pub fn evaluar(texto_respuestas: &str) -> Vec<Resultado> {
    let respuestas = parsear_archivo(texto_respuestas);
    CATALOGO
        .iter()
        .map(|item| {
            let (respuesta, nota) = match respuestas.get(item.id) {
                Some((v, n)) => (Respuesta::parsear(v), n.clone()),
                None => (Respuesta::SinVerificar, String::new()),
            };
            Resultado { item, respuesta, nota }
        })
        .collect()
}

/// Genera la plantilla de respuestas en blanco para que el auditor la llene.
pub fn plantilla() -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# Checklist §5 — cumplimiento organizacional de protección de datos");
    let _ = writeln!(s, "# Llena cada ítem con: cumple | no_cumple | no_aplica");
    let _ = writeln!(s, "# Lo que NO comprobaste, déjalo en blanco o pon 'sin_verificar' (NO se asume cumplido).");
    let _ = writeln!(s, "# Nota opcional tras '#'.\n");
    for item in CATALOGO {
        let _ = writeln!(s, "# {} ({})", item.pregunta, item.severidad);
        let _ = writeln!(s, "{}: sin_verificar\n", item.id);
    }
    s
}

/// Produce el §5 del dictamen a partir de los resultados evaluados. PURO.
pub fn generar_seccion5(resultados: &[Resultado]) -> String {
    let corpus = crate::oraculo::corpus_proteccion_datos();
    let cuenta = |r: Respuesta| resultados.iter().filter(|x| x.respuesta == r).count();
    let (ok, no, na, sv) = (
        cuenta(Respuesta::Cumple),
        cuenta(Respuesta::NoCumple),
        cuenta(Respuesta::NoAplica),
        cuenta(Respuesta::SinVerificar),
    );

    let mut d = String::new();
    let _ = writeln!(d, "## 5. Hallazgos organizacionales y de cumplimiento documental\n");
    let _ = writeln!(
        d,
        "**Resumen:** {ok} cumple · {no} NO cumple · {na} no aplica · **{sv} SIN VERIFICAR**.\n"
    );
    let _ = writeln!(d, "| Ítem | Estado | Obligación |");
    let _ = writeln!(d, "|---|---|---|");
    for r in resultados {
        let _ = writeln!(
            d,
            "| {} | {} | {} |",
            r.item.pregunta,
            r.respuesta.etiqueta(),
            r.item.obligacion_cotejada(&corpus)
        );
    }
    let _ = writeln!(d);

    // Los incumplimientos se elevan a hallazgos del dictamen con su severidad.
    let fallas: Vec<&Resultado> = resultados
        .iter()
        .filter(|r| r.respuesta == Respuesta::NoCumple)
        .collect();
    if !fallas.is_empty() {
        let _ = writeln!(d, "### Incumplimientos organizacionales (elevan el riesgo del dictamen)\n");
        for r in &fallas {
            let nota = if r.nota.is_empty() { String::new() } else { format!(" — {}", r.nota) };
            let _ = writeln!(
                d,
                "- **[{}] {}** · {}{}",
                r.item.severidad, r.item.pregunta, r.item.obligacion_cotejada(&corpus), nota
            );
        }
        let _ = writeln!(d);
    }
    if sv > 0 {
        let _ = writeln!(
            d,
            "> ⚠️ {sv} ítem(s) SIN VERIFICAR: no se pudieron comprobar en este encargo y NO se \
             asumen cumplidos (directiva 20). Requieren acceso/entrevista para cerrar el dictamen.\n"
        );
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsear_respuesta_lo_desconocido_no_es_cumple() {
        assert_eq!(Respuesta::parsear("cumple"), Respuesta::Cumple);
        assert_eq!(Respuesta::parsear("NO_CUMPLE"), Respuesta::NoCumple);
        assert_eq!(Respuesta::parsear("na"), Respuesta::NoAplica);
        // valor raro o vacío → SIN VERIFICAR, jamás Cumple (directiva 20)
        assert_eq!(Respuesta::parsear("quizás"), Respuesta::SinVerificar);
        assert_eq!(Respuesta::parsear(""), Respuesta::SinVerificar);
    }

    #[test]
    fn evaluar_marca_sin_verificar_lo_no_respondido() {
        // solo respondemos 2 de los 11 ítems del catálogo
        let texto = "rnbd: no_cumple  # sin registro\npolitica: cumple\n";
        let res = evaluar(texto);
        assert_eq!(res.len(), CATALOGO.len(), "cada ítem del catálogo aparece");
        let rnbd = res.iter().find(|r| r.item.id == "rnbd").unwrap();
        assert_eq!(rnbd.respuesta, Respuesta::NoCumple);
        assert_eq!(rnbd.nota, "sin registro");
        let pol = res.iter().find(|r| r.item.id == "politica").unwrap();
        assert_eq!(pol.respuesta, Respuesta::Cumple);
        // los 9 restantes: SIN VERIFICAR (no se asumieron cumplidos)
        let sv = res.iter().filter(|r| r.respuesta == Respuesta::SinVerificar).count();
        assert_eq!(sv, CATALOGO.len() - 2, "lo no respondido queda SIN VERIFICAR");
    }

    #[test]
    fn seccion5_eleva_incumplimientos_y_avisa_de_los_no_verificados() {
        let texto = "autorizacion: no_cumple  # no guardan la prueba\nrnbd: cumple\n";
        let s5 = generar_seccion5(&evaluar(texto));
        // el incumplimiento se eleva con su severidad y su obligación
        assert!(s5.contains("Incumplimientos organizacionales"));
        assert!(s5.contains("[alta]"));
        assert!(s5.contains("no guardan la prueba"));
        // avisa de los SIN VERIFICAR (control de la directiva 20)
        assert!(s5.contains("SIN VERIFICAR"));
        // un ítem cumplido NO aparece como incumplimiento
        assert!(!s5.contains("- **[media] ¿Bases de datos registradas"));
    }

    // ACOPLAMIENTO §5↔corpus: TODA cita de Ley del catálogo debe estar cotejada
    // en el corpus (el mismo candado que el §4/§6). Una cita nueva sin poblar rompe
    // aquí, en vez de imprimirse sin ✓ en un documento firmado. Cierra la Obs 1 de
    // la revisión 2026-08-26.
    #[test]
    fn toda_cita_del_catalogo_esta_cotejada() {
        use crate::oraculo::{corpus_proteccion_datos, verificar_cita, Cita, Veredicto};
        let corpus = corpus_proteccion_datos();
        for item in CATALOGO {
            for &(norma, articulo, literal) in item.citas {
                let c = Cita { norma: norma.to_string(), articulo, literal };
                assert!(
                    matches!(verificar_cita(&c, &corpus), Veredicto::Existe { .. }),
                    "ítem {}: {norma} Art.{articulo}{} NO está cotejado en el corpus",
                    item.id,
                    literal.map(|l| format!("({l})")).unwrap_or_default()
                );
            }
        }
    }

    // El §5 renderizado marca ✓ las citas cotejadas y deja el Decreto SIN cotejar
    // como texto libre — nunca afirma una cita de Ley sin respaldo del oráculo.
    #[test]
    fn seccion5_cita_de_ley_va_con_visto_bueno_del_oraculo() {
        let corpus = crate::oraculo::corpus_proteccion_datos();
        // El ítem `aviso` cita el Decreto 1377 Art. 14 y 15, ahora COTEJADOS (✓).
        let aviso = CATALOGO.iter().find(|i| i.id == "aviso").unwrap().obligacion_cotejada(&corpus);
        assert!(aviso.contains("Decreto 1377 de 2013 Art. 14") && aviso.contains('✓'),
            "el Decreto 1377 Art. 14 va cotejado: {aviso}");
        assert!(!aviso.contains("[verificar]"), "el aviso ya no lleva [verificar]: {aviso}");
        // La retención cita 4(b) (cotejado ✓), no las viejas 4(c)/11 erróneas.
        let ret = CATALOGO.iter().find(|i| i.id == "retencion").unwrap().obligacion_cotejada(&corpus);
        assert!(ret.contains("Art. 4(b)") && ret.contains('✓'), "4(b) finalidad cotejado: {ret}");
        assert!(!ret.contains("4(c)"), "no cita la errónea 4(c): {ret}");
        assert_eq!(
            CATALOGO.iter().find(|i| i.id == "retencion").unwrap().citas,
            &[(L, 4u32, Some('b'))],
            "la cita estructurada es solo 4(b)"
        );
    }

    #[test]
    fn plantilla_trae_todos_los_items_y_ninguno_precumplido() {
        let p = plantilla();
        for item in CATALOGO {
            // cada ítem aparece y NACE 'sin_verificar' (directiva 20), nunca 'cumple'.
            // Se comprueba por-ítem para no tropezar con la línea de instrucciones
            // ("llena con: cumple | no_cumple | ...").
            assert!(
                p.contains(&format!("{}: sin_verificar", item.id)),
                "{} nace sin_verificar en la plantilla",
                item.id
            );
            assert!(
                !p.contains(&format!("{}: cumple", item.id)),
                "{} no debe venir precumplido",
                item.id
            );
        }
    }
}
