//! Modelado de authz para WHITEBOX — surfacer de asimetrías de gate en el fuente.
//!
//! Contexto (2026-09-05): el whitebox del razonador (clonar→modelar→refutar) hace el
//! MODELADO a mano (el explorador lee los servicios y busca "el gate presente en un camino,
//! ausente en el hermano"). Esa fue la costura que dio los hallazgos de Discourse,
//! Rocket.Chat (allowEmit por-sala ausente) y el candidato de Zabbix/CMap. Esta pieza
//! MECANIZA ese primer filtro: dado un grupo de unidades hermanas (p. ej. los servicios de
//! una API, o los handlers de una carpeta) y el marcador del gate de permiso, señala las
//! que NO lo tienen mientras la mayoría SÍ — las **candidatas** a asimetría.
//!
//! Es un SURFACER, no un probador: entrega candidatos al razonador (el 20% que refuta y
//! confirma por ejecución con `oraculo_diferencial`). No decide nada solo — evita el slop
//! justamente porque el 20% humano-en-el-loop lo filtra después.

use std::path::Path;

/// Una unidad hermana a comparar (un archivo de servicio, un handler, una función).
#[derive(Debug, Clone)]
pub struct Unidad {
    pub nombre: String,
    pub texto: String,
}

impl Unidad {
    /// ¿Esta unidad invoca el gate de permiso? (contiene alguno de los marcadores).
    pub fn tiene_gate(&self, marcadores: &[&str]) -> bool {
        marcadores.iter().any(|m| self.texto.contains(m))
    }
}

/// El reparto del grupo respecto del gate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Asimetria {
    pub con_gate: Vec<String>,
    pub sin_gate: Vec<String>,
}

impl Asimetria {
    /// Las CANDIDATAS a asimetría: las unidades sin gate, PERO solo cuando existe una
    /// NORMA clara (la mayoría de las hermanas SÍ tienen el gate). Sin norma —ninguna o casi
    /// ninguna lo tiene— no hay "oveja negra" que señalar: puede ser que el gate viva en otra
    /// capa, y marcarlas todas sería ruido (directiva 23: una alarma que dispara en falso se
    /// deja de leer). Umbral: al menos 2 con gate Y la mayoría con gate.
    pub fn candidatos(&self) -> Vec<String> {
        let con = self.con_gate.len();
        let sin = self.sin_gate.len();
        let total = con + sin;
        if con >= 2 && total > 0 && con * 2 > total {
            self.sin_gate.clone()
        } else {
            Vec::new()
        }
    }
}

/// Reparte un grupo de unidades hermanas según tengan o no el gate de permiso.
pub fn asimetria_de_gate(unidades: &[Unidad], marcadores: &[&str]) -> Asimetria {
    let mut a = Asimetria::default();
    for u in unidades {
        if u.tiene_gate(marcadores) {
            a.con_gate.push(u.nombre.clone());
        } else {
            a.sin_gate.push(u.nombre.clone());
        }
    }
    a.con_gate.sort();
    a.sin_gate.sort();
    a
}

/// Construye unidades a partir de los archivos de un directorio con una extensión dada
/// (no recursivo por defecto: el "grupo de hermanos" suele ser UNA carpeta de servicios).
/// Solo lectura; no sale del directorio dado.
pub fn unidades_de_dir(dir: &Path, extension: &str) -> std::io::Result<Vec<Unidad>> {
    let mut v = Vec::new();
    for entrada in std::fs::read_dir(dir)? {
        let ruta = entrada?.path();
        if ruta.extension().and_then(|e| e.to_str()) == Some(extension) {
            if let Ok(texto) = std::fs::read_to_string(&ruta) {
                let nombre = ruta.file_name().and_then(|n| n.to_str()).unwrap_or("?").to_string();
                v.push(Unidad { nombre, texto });
            }
        }
    }
    v.sort_by(|a, b| a.nombre.cmp(&b.nombre));
    Ok(v)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn u(nombre: &str, texto: &str) -> Unidad {
        Unidad { nombre: nombre.into(), texto: texto.into() }
    }

    #[test]
    fn la_oveja_negra_es_la_candidata() {
        // 3 hermanas: 2 llaman al gate, 1 no → la que no es la candidata.
        let unidades = vec![
            u("CHost.php", "fn get() { checkPermissions($ids); ... }"),
            u("CItem.php", "fn get() { self::checkPermissions($ids); ... }"),
            u("CScript.php", "fn get() { /* no llama al gate de host */ return $rows; }"),
        ];
        let a = asimetria_de_gate(&unidades, &["checkPermissions"]);
        assert_eq!(a.con_gate, vec!["CHost.php", "CItem.php"]);
        assert_eq!(a.candidatos(), vec!["CScript.php"]);
    }

    #[test]
    fn si_todas_tienen_gate_no_hay_candidata() {
        // Pareja (directiva 33): un grupo simétrico NO debe producir candidatos.
        let unidades = vec![
            u("A", "checkPermissions()"),
            u("B", "checkPermissions()"),
            u("C", "checkPermissions()"),
        ];
        let a = asimetria_de_gate(&unidades, &["checkPermissions"]);
        assert!(a.candidatos().is_empty(), "grupo simétrico → 0 candidatos");
    }

    #[test]
    fn sin_norma_no_se_marca_nada() {
        // Si casi ninguna tiene el gate, no hay "oveja negra": el gate vive en otra capa.
        // Marcar todas sería el falso positivo de la directiva 23.
        let unidades = vec![
            u("A", "sin gate"),
            u("B", "sin gate"),
            u("C", "checkPermissions()"),
        ];
        let a = asimetria_de_gate(&unidades, &["checkPermissions"]);
        assert!(a.candidatos().is_empty(), "sin mayoría-con-gate no hay candidato");
    }

    #[test]
    fn varios_marcadores_alternativos_cuentan_como_gate() {
        let unidades = vec![
            u("A", "canReadRoom(room, user)"),
            u("B", "canAccessRoom(room, user)"),
            u("C", "return fragment; // sin control"),
        ];
        let a = asimetria_de_gate(&unidades, &["canReadRoom", "canAccessRoom"]);
        assert_eq!(a.candidatos(), vec!["C"]);
    }
}
