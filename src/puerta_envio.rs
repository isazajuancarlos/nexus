// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
//! **Puerta de ENVÍO (pre-submit gate): el 7-Question Gate de bug bounty, hecho código.**
//!
//! Reimplementación propia (D9 — nunca el alfa ajeno; se reimplementa, no se copia)
//! de la técnica `/validate` + `/triage` de `Claude-BugHunter` (MIT), cazada por
//! mindalá el 2026-10-21 como característica #9. Cierra dos huecos MEDIDOS de nexus:
//! `nexus-h1-medida-pre-envio` (H1 no da oráculo de validez pre-envío) y
//! `nexus-fuga-scope-y-cola-limpia` (la cola se llenaba de no-enviables).
//!
//! **NO duplica lo que nexus ya tiene (D1):** las otras mitades del gate ya existen
//! y esta capa COMPONE, no reemplaza:
//!   - reglas del PROGRAMA (scope, clase/CWE aceptada, informativa) → `elegibilidad`;
//!   - fuerza de EVIDENCIA bruta (body-diff, muestreo temporal, marcador) → `refutacion`;
//!   - higiene INFORMATIVA (cabeceras/versiones/SRI/banner) → `verify::is_informational_class`.
//!
//! Lo que falta y aporta ESTE módulo es la mitad bug-bounty del 7-Question Gate que
//! ninguna de esas cubre: la **never-submit-list** enumerada con **exención por
//! CADENA**, y el veredicto COMPUESTO `Pasa | Mata | Degrada | ExigeCadena` que
//! decide ANTES de `autosubmit`.
//!
//! **Puro, como `refutacion`:** recibe lo ya medido (clase + señales booleanas) y
//! decide; no hace red ni navegador. El JUICIO separado para poder probarlo contra
//! artefactos fijos (D33).
//!
//! **Es una MEDIDA, no un enforce (D30, igual que `elegibilidad`):** este módulo NO
//! envía ni descarta nada. Cablearlo en `autosubmit` (p. ej. no auto-enviar lo que
//! no `enviable()`) es una decisión de Signal aparte, que se activa tras validar
//! estas medidas contra hallazgos reales.
//!
//! **Forma de la regla (D23/D20):** se ENUMERA lo *provablemente débil por sí solo*;
//! todo lo demás NO es never-submit y sigue su curso. Ante la ausencia de una señal
//! se falla hacia dejar pasar (no se mata un hallazgo por falta de dato) — salvo el
//! PoC (Q1), cuya ausencia ES el dato que lo mata.

/// Veredicto de la puerta de envío. Las cuatro ramas del gate de `Claude-BugHunter`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Envio {
    /// Pasa los siete chequeos: es candidato real a reporte/auto-envío.
    Pasa,
    /// KILL — un chequeo DURO falló (sin PoC ahora, o exige admin). No se reporta.
    Mata(String),
    /// DOWNGRADE — podría ser real pero el impacto no está probado con DATO (solo un
    /// 200, un callback DNS, un "técnicamente posible"): baja a informativo, no se
    /// auto-envía. Se resuelve solo, sin gastar la validez del programa.
    Degrada(String),
    /// CHAIN-REQUIRED — clase de la never-submit-list SIN cadena demostrada: hoy no
    /// es enviable, pero nombra la cadena que la levantaría (no es basura, es trabajo
    /// pendiente). Con la cadena demostrada el veredicto es `Pasa`.
    ExigeCadena(String),
}

impl Envio {
    /// ¿Es candidato a reporte/auto-envío AHORA? Solo `Pasa`. Lo demás no.
    pub fn enviable(&self) -> bool {
        matches!(self, Envio::Pasa)
    }

    /// ¿Lo saca de la cola de enviables por una regla DURA (no por falta de dato)?
    /// `Mata` y `ExigeCadena` sí; `Degrada` baja a informativo; `Pasa` nunca.
    pub fn descartable(&self) -> bool {
        matches!(self, Envio::Mata(_) | Envio::ExigeCadena(_))
    }

    pub fn motivo(&self) -> String {
        match self {
            Envio::Pasa => "pasa el gate de 7 preguntas".into(),
            Envio::Mata(m) => format!("KILL: {m}"),
            Envio::Degrada(m) => format!("DOWNGRADE: {m}"),
            Envio::ExigeCadena(m) => format!("CHAIN-REQUIRED: {m}"),
        }
    }
}

/// Las señales ya medidas sobre un hallazgo candidato. Todo lo que el gate necesita
/// para decidir, sin volver a la red. Mapea a las preguntas del 7-Question Gate.
#[derive(Debug, Clone, Copy)]
pub struct Senales<'a> {
    /// La clase del hallazgo, en la lingua franca del pipeline (`vuln_type`): la
    /// misma cadena que usan `autosubmit::payable_auto`, `report::cvss_for`,
    /// `dictamen::mapear_obligacion`. No se inventa un enum nuevo (D9).
    pub vuln_type: &'a str,
    /// Q1 — ¿se puede demostrar paso a paso con una petición HTTP real AHORA? Si la
    /// respuesta fuera "hay que mirar más código", esto es `false` y mata el claim.
    pub poc_ahora: bool,
    /// Q4 — ¿exige admin / privilegio que un atacante no puede obtener? "Admin puede
    /// hacer X" no es hallazgo; "un usuario normal hace X que solo admin debería" sí.
    pub requiere_admin: bool,
    /// Q6 — ¿el impacto está probado con DATO real (cuerpo de un servicio interno,
    /// datos de otro usuario), no solo un 200 o un callback DNS? Si no, DOWNGRADE.
    pub impacto_con_dato: bool,
    /// Q7 — ¿hay una CADENA demostrada que levanta una clase débil-por-sí-sola?
    /// (open-redirect + robo de code OAuth → ATO; CORS + exfil con credenciales…).
    pub cadena_demostrada: bool,
}

/// ¿Es una clase de la **never-submit-list** —débil POR SÍ SOLA, pero encadenable—?
/// Devuelve la cadena que la levantaría (para nombrarla en el veredicto), o `None`
/// si la clase NO está en la lista (entonces sigue su curso normal).
///
/// Se ENUMERA lo provablemente débil (D23); lo no listado no es never-submit. NO se
/// repite aquí la higiene informativa (cabeceras/versiones/SRI/banner): esa la juzga
/// `verify::is_informational_class` en la capa de `elegibilidad`, y duplicarla sería
/// la causa de un falso positivo con dos dueños (D1/D32). SSRF tampoco va aquí: un
/// SSRF con dato es de los mejores hallazgos; su variante "solo DNS" la captura Q6
/// como DOWNGRADE, no como never-submit.
pub fn clase_debil_sola(vuln_type: &str) -> Option<&'static str> {
    let v = vuln_type.to_lowercase();
    // (substring, cadena-que-la-levanta). El orden no importa: primera que casa gana.
    const LISTA: &[(&str, &str)] = &[
        ("introspection", "+ IDOR / auth-bypass usando el esquema expuesto"),
        ("open-redirect", "+ robo de authorization code OAuth → ATO"),
        ("open redirect", "+ robo de authorization code OAuth → ATO"),
        ("self-xss", "+ login-CSRF u otra vía que lo dispare en OTRO usuario"),
        ("clickjack", "+ acción sensible de estado con PoC de framing"),
        ("logout-csrf", "+ CSRF sobre una acción con impacto, no el logout"),
        ("csrf-logout", "+ CSRF sobre una acción con impacto, no el logout"),
        ("cors", "+ exfiltración de datos con credenciales (no el header solo)"),
        ("rate-limit", "+ endpoint crítico (login/OTP/pago) con impacto demostrado"),
        ("rate limit", "+ endpoint crítico (login/OTP/pago) con impacto demostrado"),
    ];
    LISTA.iter()
        .find(|(clave, _)| v.contains(clave))
        .map(|(_, cadena)| *cadena)
}

/// El veredicto compuesto. El orden es el del 7-Question Gate: los chequeos DUROS
/// primero (una sola respuesta mala = KILL), luego la never-submit-list (Q7), y por
/// último el DOWNGRADE por impacto no probado (Q6). Puro.
pub fn veredicto(s: &Senales) -> Envio {
    // Q1 — sin PoC demostrable ahora, nada que sostener. Única ausencia que MATA:
    // "necesito mirar más código" es exactamente el no-hallazgo que llena la cola.
    if !s.poc_ahora {
        return Envio::Mata(
            "sin PoC demostrable AHORA (paso a paso con petición real); 'hay que mirar más código' no es hallazgo".into(),
        );
    }
    // Q4 — requiere un privilegio que el atacante no obtiene.
    if s.requiere_admin {
        return Envio::Mata("requiere admin/privilegio que un atacante no puede obtener".into());
    }
    // Q7 — never-submit-list, con exención por cadena.
    if let Some(cadena) = clase_debil_sola(s.vuln_type) {
        if s.cadena_demostrada {
            return Envio::Pasa; // la cadena la levanta: se reporta la CADENA.
        }
        return Envio::ExigeCadena(format!(
            "clase '{}' no es enviable sola; solo encadenada: {cadena}",
            s.vuln_type
        ));
    }
    // Q6 — impacto no probado con dato real → informativo, no se auto-envía.
    if !s.impacto_con_dato {
        return Envio::Degrada(
            "impacto no probado con DATO real (solo 200 / callback / 'técnicamente posible')".into(),
        );
    }
    Envio::Pasa
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn base() -> Senales<'static> {
        // Un IDOR sólido: PoC ahora, sin admin, con dato real, sin cadena. El control
        // POSITIVO del banco (D30): si este no pasa, el gate está ciego y mata todo.
        Senales {
            vuln_type: "idor",
            poc_ahora: true,
            requiere_admin: false,
            impacto_con_dato: true,
            cadena_demostrada: false,
        }
    }

    /// **El control POSITIVO (D30): un hallazgo fuerte PASA.** Sin él, un gate que
    /// devolviera siempre `Mata` saldría "verde" contra puros casos rojos.
    #[test]
    fn idor_solido_pasa() {
        assert_eq!(veredicto(&base()), Envio::Pasa);
        assert!(veredicto(&base()).enviable());
    }

    /// **CASO ROJO #1 — never-submit (D33, por la vía real `veredicto`): una
    /// introspección GraphQL SOLA NO es enviable.** Su PAREJA: la MISMA clase con la
    /// cadena demostrada → `Pasa`. El mutante es el comportamiento ANTERIOR (sin esta
    /// puerta, nada filtraba la clase en la composición de la cola): la introspección
    /// sola habría quedado en la cola como candidata.
    #[test]
    fn introspeccion_sola_exige_cadena_pero_encadenada_pasa() {
        let sola = Senales { vuln_type: "graphql-introspection", ..base() };
        let v = veredicto(&sola);
        assert!(matches!(v, Envio::ExigeCadena(_)), "introspección sola no es enviable: {v:?}");
        assert!(!v.enviable() && v.descartable());

        // PAREJA (discrimina): con cadena demostrada, la misma clase pasa.
        let encadenada = Senales { cadena_demostrada: true, ..sola };
        assert_eq!(veredicto(&encadenada), Envio::Pasa);
    }

    /// **CASO ROJO #2 — DOWNGRADE que CAMBIA el comportamiento actual (D33/D16): un
    /// `ssrf` sin dato.** Hoy `autosubmit::payable_auto("ssrf")` es `true` → se
    /// auto-enviaría; la puerta lo DEGRADA porque no hay dato probado. Es el caso que
    /// justifica el módulo: el mutante (quitar el chequeo Q6) lo dejaría pasar.
    /// PAREJA: el MISMO `ssrf` CON dato real → `Pasa`.
    #[test]
    fn ssrf_sin_dato_degrada_pero_con_dato_pasa() {
        let dns_only = Senales { vuln_type: "ssrf", impacto_con_dato: false, ..base() };
        assert!(matches!(veredicto(&dns_only), Envio::Degrada(_)));
        assert!(!dns_only_enviable());

        let con_dato = Senales { vuln_type: "ssrf", impacto_con_dato: true, ..base() };
        assert_eq!(veredicto(&con_dato), Envio::Pasa);
    }
    fn dns_only_enviable() -> bool {
        veredicto(&Senales { vuln_type: "ssrf", impacto_con_dato: false, ..base() }).enviable()
    }

    /// Q1 — sin PoC ahora MATA; con PoC (el `base`) no mata. La ausencia del PoC es la
    /// única que mata por ausencia; el resto de ausencias dejan pasar (D20/D30).
    #[test]
    fn sin_poc_ahora_mata() {
        let sin_poc = Senales { poc_ahora: false, ..base() };
        assert!(matches!(veredicto(&sin_poc), Envio::Mata(_)));
        // PAREJA: con PoC (base) NO es Mata.
        assert!(!matches!(veredicto(&base()), Envio::Mata(_)));
    }

    /// Q4 — exige admin MATA; sin admin (base) pasa. Un `ssrf` que exige admin muere
    /// antes de llegar a Q6: los chequeos duros van primero.
    #[test]
    fn requiere_admin_mata_antes_que_todo() {
        let admin = Senales { requiere_admin: true, ..base() };
        assert!(matches!(veredicto(&admin), Envio::Mata(_)));
        // Incluso una clase fuerte muere si exige admin (orden de los chequeos).
        let admin_ssrf = Senales { vuln_type: "ssrf", requiere_admin: true, ..base() };
        assert!(matches!(veredicto(&admin_ssrf), Envio::Mata(_)));
    }

    /// `clase_debil_sola` enumera y discrimina: las débiles casan (con su cadena), una
    /// clase fuerte (idor/rce/sqli) devuelve `None`. La pareja del enumerado.
    #[test]
    fn clase_debil_sola_discrimina() {
        assert!(clase_debil_sola("graphql-introspection").is_some());
        assert!(clase_debil_sola("open-redirect").is_some());
        assert!(clase_debil_sola("header-clickjacking").is_some());
        assert!(clase_debil_sola("cors-misconfig").is_some());
        // Fuertes: NO están en la lista.
        assert!(clase_debil_sola("idor").is_none());
        assert!(clase_debil_sola("rce").is_none());
        assert!(clase_debil_sola("sqli").is_none());
        assert!(clase_debil_sola("ssrf").is_none(), "ssrf no es never-submit; su variante sin dato la baja Q6");
    }
}
