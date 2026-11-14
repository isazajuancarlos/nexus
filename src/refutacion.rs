// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
//! **Puertas de refutación: la disciplina de "no afirmar sin demostrar", hecha código.**
//!
//! Del estudio de `claude-bughunter` el 2026-08-30 (`skills/bb-methodology`,
//! `triage-validation`, `docs/verification/hardened-lab-discipline-rules.md`): las mejores
//! reglas anti-falso-positivo del bug bounty maduro estaban escritas como PROSA para que un
//! humano/LLM las recordara. Aquí bajan a funciones PURAS, verificables, con su pareja
//! rojo/verde (directiva 33) — es la directiva 6 (puerta que impide > regla que recordar)
//! aplicada al veredicto de seguridad.
//!
//! Todas son puras (sin red, sin navegador): reciben lo ya medido y deciden. El recolector
//! (que hace las peticiones, intercala los ensayos, etc.) vive en los módulos de red; aquí
//! está el JUICIO, separado para poder probarlo contra artefactos fijos.
//!
//! El eje es el de siempre en nexus: **presencia ≠ verdad**. Un status distinto, una URL
//! reflejada, un body que cambió en 3 bytes o un outlier de tiempo NO son una vulnerabilidad
//! — y estas puertas existen para decir por qué no.

/// Ensayos mínimos por grupo para que una diferencia de tiempo sea creíble (no un jitter).
pub const MUESTRA_MINIMA: usize = 10;

/// Umbral del estadístico t de Welch para declarar señal temporal. Del lab endurecido de
/// `claude-bughunter`: t=5.26 confirmó, t<2 con intervalos solapados habría matado el claim;
/// 3.0 es el corte prudente entre los dos.
pub const UMBRAL_T: f64 = 3.0;

// ── Puerta 1 — BODY-DIFF: un bypass exige diferencia de CUERPO, no de status ──

/// El veredicto de comparar el cuerpo de una respuesta candidata contra su baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    /// Byte-idéntico al baseline: **NO es bypass**, diga lo que diga el status. Es el FP #1
    /// (un `200 OK` con el mismo cuerpo que el `403` baseline no probó nada).
    Identico,
    /// Difiere en `bytes` posiciones/longitud. NO confirma por sí solo: una diferencia de
    /// pocos bytes suele ser un correlation-id o un timestamp. El llamante juzga el delta;
    /// esta puerta solo garantiza que "idéntico" nunca pase por bypass.
    Difiere { bytes: usize },
}

/// Compara dos cuerpos. `Identico` si son exactamente iguales; si no, cuántos bytes difieren
/// (por la métrica simple de |len| + posiciones distintas hasta el mínimo común), para que el
/// llamante distinga "cambió el correlation-id" de "cambió el contenido".
pub fn body_diff(baseline: &[u8], candidato: &[u8]) -> Body {
    if baseline == candidato {
        return Body::Identico;
    }
    let comunes = baseline.iter().zip(candidato).filter(|(a, b)| a != b).count();
    let dif_long = baseline.len().abs_diff(candidato.len());
    Body::Difiere { bytes: comunes + dif_long }
}

// ── Puerta 2 — MUESTREO TEMPORAL: n≥10 intercalados y Welch t>3 ──

/// El veredicto de un contraste de tiempos entre un grupo de control y uno de prueba.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Timing {
    /// Menos de [`MUESTRA_MINIMA`] ensayos en algún grupo: no se decide. Un outlier en n=1
    /// es jitter, no señal.
    MuestraInsuficiente { minimo: usize },
    /// El grupo de prueba es más lento de forma estadísticamente creíble (`t` de Welch por
    /// encima de [`UMBRAL_T`]).
    Senal { t: f64 },
    /// No hay diferencia creíble (`t` por debajo del umbral). Incluye el caso de que el test
    /// sea más RÁPIDO (t negativo).
    SinSenal { t: f64 },
}

/// Contrasta los tiempos de `control` vs `prueba` con el estadístico t de Welch (no asume
/// varianzas iguales). Exige [`MUESTRA_MINIMA`] por grupo. El intercalado (no medir
/// back-to-back) es responsabilidad del recolector; aquí se contrastan las muestras dadas.
pub fn muestreo_temporal(control: &[f64], prueba: &[f64]) -> Timing {
    if control.len() < MUESTRA_MINIMA || prueba.len() < MUESTRA_MINIMA {
        return Timing::MuestraInsuficiente { minimo: MUESTRA_MINIMA };
    }
    let t = welch_t(prueba, control);
    // Solo cuenta que el sospechoso (prueba) sea MÁS lento: t positivo por encima del umbral.
    if t > UMBRAL_T {
        Timing::Senal { t }
    } else {
        Timing::SinSenal { t }
    }
}

fn media(xs: &[f64]) -> f64 {
    xs.iter().sum::<f64>() / xs.len() as f64
}

/// Varianza muestral (divisor n−1). Requiere n≥2 (garantizado por [`MUESTRA_MINIMA`]).
fn varianza(xs: &[f64], media: f64) -> f64 {
    let n = xs.len() as f64;
    xs.iter().map(|x| (x - media).powi(2)).sum::<f64>() / (n - 1.0)
}

/// t de Welch de `a` frente a `b`: positivo si `a` es mayor en media. Si ambos grupos tienen
/// varianza cero e igual media, devuelve 0 (sin señal) en vez de NaN.
fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let (ma, mb) = (media(a), media(b));
    let (va, vb) = (varianza(a, ma), varianza(b, mb));
    let denom = (va / a.len() as f64 + vb / b.len() as f64).sqrt();
    if denom == 0.0 {
        // Sin dispersión: hay señal solo si las medias difieren; el signo lo da la resta.
        return if (ma - mb).abs() < f64::EPSILON { 0.0 } else { (ma - mb) * f64::INFINITY };
    }
    (ma - mb) / denom
}

// ── Puerta 3 — MARKER DISCIPLINE: el marcador no colisiona ni es adivinable ──

/// Palabras prohibidas en un marcador: aparecen "naturales" en respuestas y disparan falsa
/// reflexión. Del `bb-methodology` de claude-bughunter.
const PROHIBIDAS: &[&str] = &[
    "test", "marker", "evil", "attacker", "payload", "javascript", "script", "admin", "aaaa", "bbbb",
];

/// ¿Es un marcador disciplinado? Al menos 8 caracteres, alfanumérico, y sin ninguna palabra
/// prohibida como subcadena (case-insensitive). Un marcador flojo (`test`, `AAAA`, el dominio)
/// produce reflexiones falsas y timings coincidentes.
pub fn marcador_valido(marcador: &str) -> Result<(), &'static str> {
    if marcador.chars().count() < 8 {
        return Err("marcador de menos de 8 caracteres");
    }
    if !marcador.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("marcador con caracteres no alfanuméricos");
    }
    let bajo = marcador.to_ascii_lowercase();
    if PROHIBIDAS.iter().any(|p| bajo.contains(p)) {
        return Err("marcador contiene una palabra que aparece natural en respuestas");
    }
    Ok(())
}

/// **La comprobación que mata el 80% de los FP de reflexión**: ¿aparece el marcador en el
/// cuerpo BASELINE (el que se obtiene SIN inyectarlo)? Si sí, no probaste reflexión —el
/// marcador ya estaba ahí por casualidad—: hay que cambiarlo y reintentar. `true` = colisiona.
pub fn marcador_colisiona(baseline: &[u8], marcador: &str) -> bool {
    contiene(baseline, marcador.as_bytes())
}

fn contiene(heno: &[u8], aguja: &[u8]) -> bool {
    if aguja.is_empty() || aguja.len() > heno.len() {
        return false;
    }
    heno.windows(aguja.len()).any(|w| w == aguja)
}

// ── Puerta 4 — POLÍTICA vs ESTADO: el oráculo distingue existencia, no responde por política ──

/// ¿Discrimina el oráculo el ESTADO (existe / no existe), o responde por POLÍTICA (lo mismo
/// para todo)? Se sondea el recurso real y uno basura garantizado-inexistente con la MISMA
/// forma; si las dos respuestas son iguales, el oráculo es CIEGO (un "403 forbidden" que
/// también da para un id inventado no prueba que el recurso real exista). `true` = discrimina.
///
/// Es el reverso de "bloqueado ≠ existe": sin esta puerta, un enumerador cuenta como hallazgo
/// lo que solo es la política uniforme del servidor.
pub fn oraculo_discrimina(respuesta_real: &[u8], respuesta_basura: &[u8]) -> bool {
    respuesta_real != respuesta_basura
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// body_diff: idéntico → `Identico` (mata el FP del 200-con-cuerpo-igual); distinto →
    /// cuenta los bytes. La pareja: un cuerpo realmente distinto NO es `Identico`.
    #[test]
    fn body_diff_distingue_identico_de_distinto() {
        assert_eq!(body_diff(b"cuerpo igual", b"cuerpo igual"), Body::Identico);
        assert!(matches!(body_diff(b"acceso denegado", b"aqui van tus datos"), Body::Difiere { .. }));
        // Diferencia de pocos bytes (un correlation-id): difiere, pero el llamante ve que es poco.
        assert_eq!(body_diff(b"id=AAA1", b"id=AAA2"), Body::Difiere { bytes: 1 });
    }

    /// **EL EDGE del timing (directiva 33): n<10 no decide; con n≥10 y una diferencia real
    /// hay `Senal`; con ruido sin diferencia, `SinSenal`.** Sin la exigencia de muestra, un
    /// outlier pasaría por señal; sin el umbral t, cualquier diferencia mínima confirmaría.
    #[test]
    fn el_muestreo_temporal_exige_muestra_y_señal_creible() {
        // Menos de 10: no se decide, aunque el único dato sea 10× más lento.
        assert_eq!(
            muestreo_temporal(&[0.1], &[1.0]),
            Timing::MuestraInsuficiente { minimo: 10 }
        );
        // n=12, control ~0.10 s, prueba ~0.30 s con poca dispersión → señal fuerte.
        let control: Vec<f64> = (0..12).map(|i| 0.10 + (i as f64) * 0.001).collect();
        let prueba: Vec<f64> = (0..12).map(|i| 0.30 + (i as f64) * 0.001).collect();
        assert!(matches!(muestreo_temporal(&control, &prueba), Timing::Senal { .. }));
        // Su PAREJA: dos grupos del mismo proceso ruidoso → sin señal (un outlier no basta).
        let a = vec![0.10, 0.12, 0.09, 0.30, 0.11, 0.10, 0.13, 0.08, 0.12, 0.11, 0.10, 0.09];
        let b = vec![0.11, 0.10, 0.12, 0.09, 0.11, 0.28, 0.10, 0.12, 0.09, 0.11, 0.10, 0.13];
        assert!(matches!(muestreo_temporal(&a, &b), Timing::SinSenal { .. }), "un outlier en cada grupo no es señal");
    }

    /// Marker discipline: acepta un marcador fuerte, rechaza los flojos por cada motivo.
    #[test]
    fn marcador_valido_rechaza_los_flojos() {
        assert!(marcador_valido("k7m2q9x4z1").is_ok());
        assert!(marcador_valido("corto7").is_err()); // <8
        assert!(marcador_valido("test12345").is_err()); // palabra prohibida
        assert!(marcador_valido("AAAA9999").is_err()); // aaaa
        assert!(marcador_valido("con-guion1").is_err()); // no alfanumérico
    }

    /// **La comprobación anti-FP de reflexión**: si el marcador ya está en el baseline,
    /// colisiona (no probó reflexión); si no, no colisiona. La pareja discrimina el FP.
    #[test]
    fn marcador_colisiona_caza_la_reflexion_falsa() {
        let baseline = b"pagina normal con la palabra k7m2q9x4z1 ya presente";
        assert!(marcador_colisiona(baseline, "k7m2q9x4z1"), "estaba en el baseline: FP");
        assert!(!marcador_colisiona(baseline, "z9y8w7v6u5"), "no estaba: reflexión genuina posible");
    }

    /// Política vs estado: dos respuestas iguales (recurso real y basura) → oráculo ciego;
    /// distintas → discrimina existencia. Sin esto, un 403 uniforme cuenta como enumeración.
    #[test]
    fn oraculo_discrimina_estado_de_politica() {
        assert!(!oraculo_discrimina(b"403 forbidden", b"403 forbidden"), "misma respuesta = ciego por política");
        assert!(oraculo_discrimina(b"200 {datos del usuario 42}", b"404 not found"), "distinta = discrimina estado");
    }
}
