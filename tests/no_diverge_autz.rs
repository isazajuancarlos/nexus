// SPDX-License-Identifier: LicenseRef-Propietario
//! **Guardián de divergencia: el núcleo puro de `src/autz.rs` NO puede alejarse
//! de la librería `autz` (`/mnt/data/autz`).**
//!
//! nexus conserva su propia copia del motor de control de acceso (fase_autz,
//! fase_bypass, muro-403, persistencia — glue que NO va en la librería), y esa
//! copia incluye las funciones PURAS que también viven, canónicas, en la
//! librería. Se decidió (2026-08-20, Juan) NO acoplar la cadena de suministro
//! de nexus a la librería (git-dep + re-vendor + re-anclar en cada cambio) y en
//! su lugar cerrar el ÚNICO riesgo real de la duplicación: que las dos copias
//! DIVERJAN EN SILENCIO —lo que casi ocurre al editar la de nexus—.
//!
//! Este test hace ruidosa esa divergencia (directiva 6: un test que falla vale
//! más que una regla que recordar; directiva 20: falla, no rellena). Si alguien
//! toca una copia y no la otra, el build se pone ROJO nombrando la función.
//!
//! La librería es el ORIGEN DE VERDAD; nexus la refleja, y este guardián lo
//! comprueba. Al cambiar el motor: se edita la librería, se copia el cambio a
//! nexus, y este test confirma que quedaron idénticos.

use std::path::PathBuf;

/// Extrae un item de nivel superior de un fuente Rust: desde la línea que
/// contiene `firma` (la definición) hasta la primera línea que es EXACTAMENTE
/// `fin` (el cierre a columna 0 — `}` para una fn, `];` para un const). Los
/// cierres anidados van indentados, así que no casan: se captura el bloque
/// completo y solo ese. Devuelve None si no encuentra la firma.
fn extraer(fuente: &str, firma: &str, fin: &str) -> Option<String> {
    let mut bloque: Vec<&str> = Vec::new();
    let mut dentro = false;
    for l in fuente.lines() {
        if !dentro {
            if l.contains(firma) {
                dentro = true;
                bloque.push(l);
            }
        } else {
            bloque.push(l);
            if l == fin {
                return Some(bloque.join("\n"));
            }
        }
    }
    if dentro {
        // Encontró la firma pero nunca el cierre: fuente malformado → que falle.
        Some(bloque.join("\n"))
    } else {
        None
    }
}

#[test]
fn el_nucleo_puro_de_nexus_no_diverge_de_la_libreria() {
    let nexus_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/autz.rs");
    let lib_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../autz/src/lib.rs");

    let nexus = std::fs::read_to_string(&nexus_src)
        .unwrap_or_else(|e| panic!("no pude leer {}: {e}", nexus_src.display()));
    // FALLA RUIDOSO si la librería no está (directiva 20/30): en este montaje de
    // una sola máquina `/mnt/data/autz` SIEMPRE existe; su ausencia es un fallo
    // del entorno, no un motivo para saltarse el guardián en silencio.
    let lib = std::fs::read_to_string(&lib_src).unwrap_or_else(|e| {
        panic!(
            "no pude leer la librería {} ({e}). El guardián de divergencia \
             necesita el repo hermano autz; en /mnt/data debe estar en ../autz.",
            lib_src.display()
        )
    });

    // (firma de la definición, línea de cierre a columna 0). Son las funciones
    // y constantes PURAS cuya divergencia CAMBIARÍA el comportamiento del motor.
    let items: &[(&str, &str)] = &[
        ("fn longitudes_equivalentes", "}"),
        ("pub fn clasificar", "}"),
        ("pub fn firma_cuerpo", "}"),
        ("pub fn firma_normalizada", "}"),
        ("pub fn es_bypass", "}"),
        ("pub fn cliente", "}"),
        ("pub const TECNICAS_EVASION", "];"),
    ];

    let mut divergencias: Vec<String> = Vec::new();
    for (firma, fin) in items {
        let a = extraer(&nexus, firma, fin)
            .unwrap_or_else(|| panic!("`{firma}` no está en src/autz.rs — ¿se renombró?"));
        let b = extraer(&lib, firma, fin)
            .unwrap_or_else(|| panic!("`{firma}` no está en la librería autz — ¿se renombró?"));
        if a != b {
            divergencias.push(format!("  · `{firma}` DIVERGIÓ entre nexus y la librería"));
        }
    }

    assert!(
        divergencias.is_empty(),
        "el núcleo puro de nexus/src/autz.rs se alejó de la librería autz:\n{}\n\
         Reconcilia las dos copias (la librería es el origen de verdad).",
        divergencias.join("\n")
    );
}
