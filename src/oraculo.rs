//! Oráculo jurídico: verifica que una CITA a una norma colombiana (Ley/Decreto)
//! EXISTE y dice lo que el dictamen afirma, contra un corpus poblado de **fuente
//! oficial**.
//!
//! Es la aplicación al derecho de LA INVERSIÓN de nexus (ver `nuclei_moldes`): un
//! modelo que cita "de memoria" alucina jurisprudencia y numera mal los artículos;
//! la defensa no es un modelo más listo, sino anclar cada cita a la fuente y
//! validarla con un oráculo limpio. Aquí "ejecutar" = cotejar contra el texto
//! oficial.
//!
//! Filosofía heredada de `chibcha` (constantes legislativas con su norma):
//! 1. **No adivina**: si la norma/artículo no está catalogado → `NoExiste`.
//! 2. **Distingue lo verificado de lo no**: un artículo catalogado cuyo texto
//!    aún no se ha cotejado con la publicación oficial devuelve `SinVerificar`,
//!    NUNCA se afirma como válido (directiva 20).
//!
//! El corpus JAMÁS se puebla desde la memoria de un LLM —sería el mismo fallo que
//! el oráculo combate—. Los textos entran cotejados de la publicación oficial.

/// Una cita tal como la emite el dictamen: "Art. 4(g) de la Ley 1581 de 2012".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cita {
    /// Nombre oficial de la norma, p. ej. "Ley 1581 de 2012".
    pub norma: String,
    /// Número de artículo.
    pub articulo: u32,
    /// Literal, si la cita lo especifica: `Some('g')`.
    pub literal: Option<char>,
}

impl Cita {
    /// Referencia legible para el documento: "Ley 1581 de 2012 Art. 4(g)".
    pub fn referencia(&self) -> String {
        match self.literal {
            Some(l) => format!("{} Art. {}({})", self.norma, self.articulo, l),
            None => format!("{} Art. {}", self.norma, self.articulo),
        }
    }
}

/// Un artículo del corpus, con su texto oficial y su estado de cotejo.
#[derive(Debug, Clone)]
pub struct ArticuloOficial {
    pub norma: &'static str,
    pub articulo: u32,
    pub literal: Option<char>,
    /// De qué trata (lo que el dictamen AFIRMA de la cita). Es la etiqueta a
    /// cotejar contra el texto oficial, no una sustitución de él.
    pub sumilla: &'static str,
    /// Texto oficial del artículo. `None` = aún no poblado de fuente oficial.
    pub texto: Option<&'static str>,
    /// Referencia de la norma / publicación oficial de donde se coteja.
    pub fuente: &'static str,
    /// `true` solo cuando el texto se cotejó con la publicación oficial.
    pub verificado: bool,
}

/// Resultado de verificar una cita.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Veredicto {
    /// El artículo existe y su texto está cotejado con la fuente oficial.
    Existe { sumilla: String, fuente: String },
    /// La norma/artículo NO figura en el corpus oficial: cita a corregir antes
    /// de firmar (posible alucinación / numeración errada).
    NoExiste,
    /// El artículo está catalogado, pero su texto aún no se cotejó con la fuente
    /// oficial. Nunca se afirma como válido: queda marcado para cotejo humano.
    SinVerificar { sumilla: String },
}

/// Verifica una cita contra un corpus dado. Núcleo puro (sin E/S), testeable.
pub fn verificar_cita(cita: &Cita, corpus: &[ArticuloOficial]) -> Veredicto {
    let encontrado = corpus.iter().find(|a| {
        a.norma.eq_ignore_ascii_case(cita.norma.trim())
            && a.articulo == cita.articulo
            && a.literal == cita.literal
    });
    match encontrado {
        None => Veredicto::NoExiste,
        Some(a) if a.verificado && a.texto.is_some() => Veredicto::Existe {
            sumilla: a.sumilla.to_string(),
            fuente: a.fuente.to_string(),
        },
        Some(a) => Veredicto::SinVerificar {
            sumilla: a.sumilla.to_string(),
        },
    }
}

/// Corpus REAL cotejado: los artículos que `nexus dictamen` cita, con su **texto
/// oficial** transcrito. La Ley 1581 (13 artículos) de secretariasenado.gov.co
/// (2026-08-26); el Decreto 1377 reglamentario (7 artículos) del Gestor Normativo
/// de funcionpublica.gov.co (2026-08-27).
///
/// Acotado a lo que el dictamen realmente cita (directiva 22): NO se rellena con
/// artículos que el dictamen no invoca. Lo único que queda SIN VERIFICAR en el
/// §2/§5 es la circular de la SIC (sin fuente oficial cargada).
///
/// El cotejo del 2026-08-26 desmintió dos citas que un borrador previo daba por
/// buenas «de memoria»: Art. 4(c) NO es «finalidad» (es «libertad»; finalidad es
/// 4(b)) y Art. 11 NO es «temporalidad» (es «suministro de la información»). El
/// dictamen vigente no las usa; se registran aquí como lección de por qué el
/// texto entra SOLO de fuente oficial.
pub fn corpus_proteccion_datos() -> Vec<ArticuloOficial> {
    const L1581: &str = "Ley 1581 de 2012";
    const FUENTE: &str = "secretariasenado.gov.co/senado/basedoc/ley_1581_2012.html";
    const D1377: &str = "Decreto 1377 de 2013";
    const FUENTE_D: &str = "funcionpublica.gov.co/eva/gestornormativo/norma.php?i=53646";
    let art = |articulo, literal, sumilla, texto: &'static str| ArticuloOficial {
        norma: L1581,
        articulo,
        literal,
        sumilla,
        texto: Some(texto),
        fuente: FUENTE,
        verificado: true,
    };
    // Decreto 1377 de 2013 (reglamentario), cotejado de funcionpublica (Gestor
    // Normativo) el 2026-08-27. Fuente autoritativa última: Diario Oficial 48.834
    // (27 de junio de 2013); el Gestor Normativo es compilación fiable secundaria.
    // La cadena TLS del servidor está incompleta (no envía el intermedio Sectigo);
    // la identidad del certificado se confirmó fuera de banda (OV de la Función
    // Pública, CA pública Sectigo) antes de descargar.
    let dec = |articulo, sumilla, texto: &'static str| ArticuloOficial {
        norma: D1377,
        articulo,
        literal: None,
        sumilla,
        texto: Some(texto),
        fuente: FUENTE_D,
        verificado: true,
    };
    vec![
        art(4, Some('g'), "principio de seguridad",
            "g) Principio de seguridad: La información sujeta a Tratamiento por el Responsable del Tratamiento o Encargado del Tratamiento a que se refiere la presente ley, se deberá manejar con las medidas técnicas, humanas y administrativas que sean necesarias para otorgar seguridad a los registros evitando su adulteración, pérdida, consulta, uso o acceso no autorizado o fraudulento."),
        art(4, Some('h'), "principio de confidencialidad",
            "h) Principio de confidencialidad: Todas las personas que intervengan en el Tratamiento de datos personales que no tengan la naturaleza de públicos están obligadas a garantizar la reserva de la información, inclusive después de finalizada su relación con alguna de las labores que comprende el Tratamiento, pudiendo sólo realizar suministro o comunicación de datos personales cuando ello corresponda al desarrollo de las actividades autorizadas en la presente ley y en los términos de la misma."),
        art(5, None, "datos sensibles (definición)",
            "Para los propósitos de la presente ley, se entiende por datos sensibles aquellos que afectan la intimidad del Titular o cuyo uso indebido puede generar su discriminación, tales como aquellos que revelen el origen racial o étnico, la orientación política, las convicciones religiosas o filosóficas, la pertenencia a sindicatos, organizaciones sociales, de derechos humanos o que promueva intereses de cualquier partido político o que garanticen los derechos y garantías de partidos políticos de oposición así como los datos relativos a la salud, a la vida sexual y los datos biométricos."),
        art(6, None, "tratamiento de datos sensibles (prohibición/excepciones)",
            "Se prohíbe el Tratamiento de datos sensibles, excepto cuando:"),
        art(8, None, "derechos de los titulares (Habeas Data)",
            "El Titular de los datos personales tendrá los siguientes derechos:"),
        art(17, Some('d'), "deber de conservación segura del Responsable",
            "d) Conservar la información bajo las condiciones de seguridad necesarias para impedir su adulteración, pérdida, consulta, uso o acceso no autorizado o fraudulento."),
        art(23, None, "sanciones",
            "La Superintendencia de Industria y Comercio podrá imponer a los Responsables del Tratamiento y Encargados del Tratamiento las siguientes sanciones:"),
        // --- añadidos para el §5 (cumplimiento organizacional), 2026-08-27 ---
        art(4, Some('b'), "principio de finalidad",
            "b) Principio de finalidad: El Tratamiento debe obedecer a una finalidad legítima de acuerdo con la Constitución y la Ley, la cual debe ser informada al Titular."),
        art(9, None, "autorización previa del titular",
            "Sin perjuicio de las excepciones previstas en la ley, en el Tratamiento se requiere la autorización previa e informada del Titular, la cual deberá ser obtenida por cualquier medio que pueda ser objeto de consulta posterior."),
        art(14, None, "consultas",
            "Los Titulares o sus causahabientes podrán consultar la información personal del Titular que repose en cualquier base de datos, sea esta del sector público o privado. El Responsable del Tratamiento o Encargado del Tratamiento deberán suministrar a estos toda la información contenida en el registro individual o que esté vinculada con la identificación del Titular. La consulta será atendida en un término máximo de diez (10) días hábiles contados a partir de la fecha de recibo de la misma."),
        art(15, None, "reclamos",
            "El Titular o sus causahabientes que consideren que la información contenida en una base de datos debe ser objeto de corrección, actualización o supresión, o cuando adviertan el presunto incumplimiento de cualquiera de los deberes contenidos en esta ley, podrán presentar un reclamo ante el Responsable del Tratamiento o el Encargado del Tratamiento el cual será tramitado bajo las siguientes reglas: […] El término máximo para atender el reclamo será de quince (15) días hábiles contados a partir del día siguiente a la fecha de su recibo."),
        art(25, None, "Registro Nacional de Bases de Datos (definición)",
            "El Registro Nacional de Bases de Datos es el directorio público de las bases de datos sujetas a Tratamiento que operan en el país. El registro será administrado por la Superintendencia de Industria y Comercio y será de libre consulta para los ciudadanos."),
        art(26, None, "prohibición de transferencia internacional",
            "Se prohíbe la transferencia de datos personales de cualquier tipo a países que no proporcionen niveles adecuados de protección de datos. Se entiende que un país ofrece un nivel adecuado de protección de datos cuando cumpla con los estándares fijados por la Superintendencia de Industria y Comercio sobre la materia."),
        // --- Decreto 1377 de 2013 (funcionpublica), 2026-08-27 ---
        dec(4, "recolección de datos (pertinencia y finalidad)",
            "Recolección de los datos personales. En desarrollo de los principios de finalidad y libertad, la recolección de datos deberá limitarse a aquellos datos personales que son pertinentes y adecuados para la finalidad para la cual son recolectados o requeridos conforme a la normatividad vigente. Salvo en los casos expresamente previstos en la ley, no se podrán recolectar datos personales sin autorización del Titular."),
        dec(5, "autorización (procedimiento y prueba)",
            "Autorización. El Responsable del Tratamiento deberá adoptar procedimientos para solicitar, a más tardar en el momento de la recolección de sus datos, la autorización del Titular para el Tratamiento de los mismos e informarle los datos personales que serán recolectados así como todas las finalidades específicas del Tratamiento para las cuales se obtiene el consentimiento."),
        dec(6, "autorización para el tratamiento de datos sensibles",
            "De la autorización para el Tratamiento de datos personales sensibles. El Tratamiento de los datos sensibles a que se refiere el artículo 5° de la Ley 1581 de 2012 está prohibido, a excepción de los casos expresamente señalados en el artículo 6° de la citada ley."),
        dec(13, "política de tratamiento de la información",
            "Políticas de Tratamiento de la información. Los responsables del tratamiento deberán desarrollar sus políticas para el tratamiento de los datos personales y velar porque los Encargados del Tratamiento den cabal cumplimiento a las mismas. Las políticas de Tratamiento deberán constar en medio físico o electrónico, en un lenguaje claro y sencillo."),
        dec(14, "aviso de privacidad",
            "Aviso de privacidad. En los casos en los que no sea posible poner a disposición del Titular las políticas de tratamiento de la información, los responsables deberán informar por medio de un aviso de privacidad al titular sobre la existencia de tales políticas y la forma de acceder a las mismas, de manera oportuna y en todo caso a más tardar al momento de la recolección de los datos personales."),
        dec(15, "contenido mínimo del aviso de privacidad",
            "Contenido mínimo del Aviso de Privacidad. El aviso de privacidad, como mínimo, deberá contener la siguiente información: 1. Nombre o razón social y datos de contacto del responsable del tratamiento. 2. El Tratamiento al cual serán sometidos los datos y la finalidad del mismo. 3. Los derechos que le asisten al titular. 4. Los mecanismos dispuestos por el responsable para que el titular conozca la política de tratamiento […]."),
        dec(23, "designación de área/persona de protección de datos",
            "Medios para el ejercicio de los derechos. Todo Responsable y Encargado deberá designar a una persona o área que asuma la función de protección de datos personales, que dará trámite a las solicitudes de los Titulares, para el ejercicio de los derechos a que se refiere la Ley 1581 de 2012 y el presente decreto."),
        dec(8, "prueba de la autorización",
            "Prueba de la autorización. Los Responsables deberán conservar prueba de la autorización otorgada por los Titulares de datos personales para el Tratamiento de los mismos."),
        dec(26, "responsabilidad demostrada (demostración ante la SIC)",
            "Demostración. Los responsables del tratamiento de datos personales deben ser capaces de demostrar, a petición de la Superintendencia de Industria y Comercio, que han implementado medidas apropiadas y efectivas para cumplir con las obligaciones establecidas en la Ley 1581 de 2012 y este decreto, en una manera que sea proporcional a lo siguiente: 1. La naturaleza jurídica del responsable y, cuando sea del caso, su tamaño empresarial, teniendo en cuenta si se trata de una micro, pequeña, mediana o gran empresa, de acuerdo con la normativa vigente. 2. La naturaleza de los datos personales objeto del tratamiento. 3. El tipo de Tratamiento. 4. Los riesgos potenciales que el referido tratamiento podrían causar sobre los derechos de los titulares. […]"),
        dec(27, "políticas internas efectivas (accountability)",
            "Políticas internas efectivas. En cada caso, de acuerdo con las circunstancias mencionadas en los numerales 1, 2, 3 y 4 del artículo 26 anterior, las medidas efectivas y apropiadas implementadas por el Responsable deben ser consistentes con las instrucciones impartidas por la Superintendencia de Industria y Comercio. Dichas políticas deberán garantizar: 1. La existencia de una estructura administrativa proporcional a la estructura y tamaño empresarial del responsable para la adopción e implementación de políticas consistentes con la Ley 1581 de 2012 y este decreto. […]"),
    ]
}

/// Las citas que el dictamen invoca como base normativa (§2). Se pasan por
/// `verificar_cita` antes de imprimirse: ninguna sale del dictamen sin declarar su
/// cotejo (dir. 20). Cubre la Ley 1581 (lo que `mapear_obligacion` emite en §4/§6
/// más 6/8) y el Decreto 1377 reglamentario (lo que el §5 invoca).
pub fn citas_base_dictamen() -> Vec<Cita> {
    const L: &str = "Ley 1581 de 2012";
    const D: &str = "Decreto 1377 de 2013";
    [
        (L, 4, Some('g')),
        (L, 4, Some('h')),
        (L, 5, None),
        (L, 6, None),
        (L, 8, None),
        (L, 17, Some('d')),
        (L, 23, None),
        (D, 4, None),
        (D, 5, None),
        (D, 6, None),
        (D, 8, None),
        (D, 13, None),
        (D, 14, None),
        (D, 15, None),
        (D, 23, None),
        (D, 26, None),
        (D, 27, None),
    ]
    .into_iter()
    .map(|(norma, articulo, literal)| Cita {
        norma: norma.to_string(),
        articulo,
        literal,
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cita(norma: &str, articulo: u32, literal: Option<char>) -> Cita {
        Cita { norma: norma.to_string(), articulo, literal }
    }

    /// Corpus sintético para probar los TRES veredictos (directiva 33: la pareja
    /// que discrimina, no solo el caso verde). No usa texto de ley real: prueba
    /// la LÓGICA del oráculo, no el contenido.
    fn corpus_prueba() -> Vec<ArticuloOficial> {
        vec![
            ArticuloOficial {
                norma: "Ley 9999 de 2099",
                articulo: 1,
                literal: Some('a'),
                sumilla: "artículo cotejado de prueba",
                texto: Some("texto oficial sintético"),
                fuente: "fuente de prueba",
                verificado: true,
            },
            ArticuloOficial {
                norma: "Ley 9999 de 2099",
                articulo: 2,
                literal: None,
                sumilla: "artículo catalogado sin cotejar",
                texto: None,
                fuente: "fuente de prueba",
                verificado: false,
            },
        ]
    }

    #[test]
    fn articulo_cotejado_da_existe() {
        let v = verificar_cita(&cita("Ley 9999 de 2099", 1, Some('a')), &corpus_prueba());
        assert!(matches!(v, Veredicto::Existe { .. }), "cotejado debe ser Existe, fue {v:?}");
    }

    #[test]
    fn articulo_sin_cotejar_da_sinverificar_no_existe() {
        // El caso rojo real: un artículo catalogado pero NO cotejado NUNCA puede
        // salir como Existe. Debe ser SinVerificar.
        let v = verificar_cita(&cita("Ley 9999 de 2099", 2, None), &corpus_prueba());
        assert!(matches!(v, Veredicto::SinVerificar { .. }), "sin cotejar debe ser SinVerificar, fue {v:?}");
        assert!(!matches!(v, Veredicto::Existe { .. }));
    }

    #[test]
    fn articulo_inexistente_da_noexiste() {
        let v = verificar_cita(&cita("Ley 9999 de 2099", 404, None), &corpus_prueba());
        assert_eq!(v, Veredicto::NoExiste);
    }

    #[test]
    fn literal_equivocado_no_casa() {
        // Art. 1 existe con literal 'a'; pedir 'z' no debe casar.
        let v = verificar_cita(&cita("Ley 9999 de 2099", 1, Some('z')), &corpus_prueba());
        assert_eq!(v, Veredicto::NoExiste);
    }

    #[test]
    fn corpus_real_esta_cotejado_y_da_existe() {
        // El corpus se pobló de fuente oficial (secretariasenado, 2026-08-26):
        // cada cita del dictamen debe dar Existe con su texto y fuente.
        let corpus = corpus_proteccion_datos();
        assert!(!corpus.is_empty());
        for art in &corpus {
            assert!(art.verificado && art.texto.is_some(),
                "todo el corpus real debe estar cotejado: {} art.{}", art.norma, art.articulo);
            let c = cita(art.norma, art.articulo, art.literal);
            assert!(
                matches!(verificar_cita(&c, &corpus), Veredicto::Existe { .. }),
                "{} art.{} cotejado debe dar Existe", art.norma, art.articulo
            );
        }
    }

    #[test]
    fn las_citas_reales_del_dictamen_casan() {
        // Caso rojo del consumidor: las 7 citas que `dictamen.rs` emite deben
        // resolver Existe. Si una falla, el oráculo desmentiría al dictamen.
        let corpus = corpus_proteccion_datos();
        let citas_dictamen = [
            (4u32, Some('g')), (4, Some('h')), (5, None), (6, None),
            (8, None), (17, Some('d')), (23, None),
        ];
        for (a, l) in citas_dictamen {
            let v = verificar_cita(&cita("Ley 1581 de 2012", a, l), &corpus);
            assert!(matches!(v, Veredicto::Existe { .. }),
                "cita del dictamen Art.{a}{} debe existir, fue {v:?}",
                l.map(|c| format!("({c})")).unwrap_or_default());
        }
    }

    #[test]
    fn cita_mal_numerada_del_borrador_no_casa() {
        // Las dos citas que el cotejo desmintió no deben aparecer como válidas:
        // Art.4(c) no es finalidad y Art.11 no es temporalidad — no están en el
        // corpus cotejado, así que dan NoExiste (cita a corregir antes de firmar).
        let corpus = corpus_proteccion_datos();
        assert_eq!(verificar_cita(&cita("Ley 1581 de 2012", 4, Some('c')), &corpus), Veredicto::NoExiste);
        assert_eq!(verificar_cita(&cita("Ley 1581 de 2012", 11, None), &corpus), Veredicto::NoExiste);
    }
}
