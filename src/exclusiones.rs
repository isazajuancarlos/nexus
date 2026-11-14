//! EXCLUSIONES — la memoria NEGATIVA por causa. El inverso de [`crate::secuencias`]:
//! aquélla guarda la sonda que GANÓ contra un host para re-lanzarla; ésta guarda
//! por qué una `(host, clase)` se EXCLUYÓ, para que la próxima decisión sea por
//! CAUSA y no por un "seco" indistinto.
//!
//! El fallo que evita (directiva 30): un negativo no es una sola cosa. "No
//! encontré nada" puede ser porque el proceso topó TIEMPO (y con más presupuesto
//! sí), porque el objetivo estaba INOPERABLE (transitorio → reintentar; o
//! amurallado permanente → excluir), porque se AGOTARON LOS MÉTODOS (el arsenal
//! estático no puede; solo un método NUEVO ayudaría), o porque simplemente NO
//! EXISTE superficie (terminal). Tratar los cuatro igual, o como "limpio", pierde
//! los remediables y re-intenta eternamente los que no lo son.
//!
//! Como en `secuencias`, la clave es la HUELLA de defensa del host
//! ([`crate::secuencias::PosturaDefensa::huella`]): si la huella cambia, el
//! entorno que produjo el veredicto negativo ya no está, así que el veredicto
//! CADUCA y se reintenta con normalidad. La política por causa es lógica PURA
//! (directiva 32: la fila guarda el HECHO —causa + huella—, el oráculo deriva la
//! ACCIÓN), así que ajustar una política no migra datos.

use crate::error::Result;
use sqlx::SqlitePool;

/// Por qué se excluyó una `(host, clase)`. La taxonomía la fijó Juan (2026-08-24):
/// un candidato se excluye por agotamiento de tiempo, por inoperabilidad, por
/// agotamiento de métodos, o por inexistencia — y cada uno se subsana distinto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Causa {
    /// El proceso topó su presupuesto de TIEMPO (no terminó). Remediable: más
    /// tiempo. Es el `timed_out` del escáner, que hoy en la fase de scan solo
    /// deprioritiza el programa sin dar más presupuesto (a diferencia de la
    /// verificación, que reintenta con `timeout ×2`).
    Tiempo,
    /// El objetivo estaba INOPERABLE de forma TRANSITORIA: sin hosts vivos ahora,
    /// error de red pasajero, rate-limit momentáneo. Remediable: reintentar.
    InoperabilidadTransitoria,
    /// INOPERABLE de forma PERMANENTE mientras no cambie la huella: WAF que
    /// amuralla la IP compartida, fuera de scope. No se reintenta hasta que el
    /// entorno cambie (la huella).
    InoperabilidadPermanente,
    /// Todos los ataques del arsenal ESTÁTICO fallaron (arnm `Seco`). Retriar el
    /// mismo repertorio no ayuda —el objetivo es inmune a él—; la única cura es un
    /// método NUEVO → cola de generación bespoke.
    MetodosAgotados,
    /// No hay superficie que atacar para esta clase (p. ej. SSRF/DAST sin un solo
    /// parámetro inyectable). Terminal: no reintentar hasta que cambie la huella.
    Inexistencia,
    /// El programa/host acumula fallos sin un solo éxito (estéril crónico). Se
    /// deprioritiza —no se excluye— y se reintenta con menor prioridad.
    Esteril,
}

impl Causa {
    /// Forma persistida (la de la columna `causa`). Inverso EXACTO de
    /// [`Causa::desde_str`] — un `match` sin brazo no compila (directiva 38/20).
    pub fn a_str(self) -> &'static str {
        match self {
            Causa::Tiempo => "tiempo",
            Causa::InoperabilidadTransitoria => "inop_transitoria",
            Causa::InoperabilidadPermanente => "inop_permanente",
            Causa::MetodosAgotados => "metodos_agotados",
            Causa::Inexistencia => "inexistencia",
            Causa::Esteril => "esteril",
        }
    }

    /// Parsea la columna `causa`. `None` ante un valor desconocido, para que el
    /// llamante falle RUIDOSO (directiva 20) en vez de tratar una fila corrupta
    /// como una causa cualquiera.
    pub fn desde_str(s: &str) -> Option<Causa> {
        Some(match s {
            "tiempo" => Causa::Tiempo,
            "inop_transitoria" => Causa::InoperabilidadTransitoria,
            "inop_permanente" => Causa::InoperabilidadPermanente,
            "metodos_agotados" => Causa::MetodosAgotados,
            "inexistencia" => Causa::Inexistencia,
            "esteril" => Causa::Esteril,
            _ => return None,
        })
    }
}

/// Lo que el planificador debe HACER ante una `(host, clase)` con veredicto
/// negativo, dada la huella actual del host. Es el producto del oráculo puro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accion {
    /// Corre la fase, con este multiplicador sobre su presupuesto normal
    /// (1 = presupuesto normal; >1 = más tiempo, para la causa `Tiempo`).
    Reintentar { presupuesto_mult: u32 },
    /// No corras la fase: sigue vigente un veredicto terminal/permanente y la
    /// huella no ha cambiado. Ahorra el trabajo (y la petición) de re-intentar lo
    /// que ya se sabe que no está.
    Saltar,
    /// El arsenal estático está agotado contra este objetivo: no lo repitas, manda
    /// la `(host, clase)` a la cola de GENERACIÓN de método nuevo (bespoke).
    EncolarGeneracion,
}

/// La POLÍTICA por causa cuando la huella NO ha cambiado (el veredicto sigue
/// vigente). Es la tabla de remediación de la taxonomía de Juan, pura y total.
pub fn politica(causa: Causa) -> Accion {
    match causa {
        // Más presupuesto: lo que a la verificación le sirve (timeout ×2), a la
        // fase de scan también.
        Causa::Tiempo => Accion::Reintentar { presupuesto_mult: 2 },
        // Fue pasajero: un intento normal la próxima vez.
        Causa::InoperabilidadTransitoria => Accion::Reintentar { presupuesto_mult: 1 },
        // Amurallado / fuera de scope: no gastes la petición hasta que cambie algo.
        Causa::InoperabilidadPermanente => Accion::Saltar,
        // El arsenal no puede: método nuevo, no repetición.
        Causa::MetodosAgotados => Accion::EncolarGeneracion,
        // No hay superficie: terminal.
        Causa::Inexistencia => Accion::Saltar,
        // Estéril: se deprioritiza fuera de aquí; aquí no se salta (podría revivir).
        Causa::Esteril => Accion::Reintentar { presupuesto_mult: 1 },
    }
}

/// EL ORÁCULO. Dado el veredicto guardado (causa + huella de cuando se registró) y
/// la huella ACTUAL del host, ¿qué hace el planificador?
///
/// DOS caducidades, y basta con que dispare UNA para reintentar:
///  1. POR HUELLA (idéntica a `secuencias`): si la huella actual DIFIERE de la
///     guardada, el entorno que produjo el veredicto ya no está → reintento normal.
///  2. POR ANTIGÜEDAD (el TTL): un veredicto de SALTAR (Saltar/EncolarGeneracion)
///     más viejo que `ttl_secs` caduca aunque la huella coincida → reintento
///     normal. Cierra el falso negativo medido: un objetivo que se vuelve vulnerable
///     conservando su postura observable (misma huella) se saltaría para siempre;
///     con el TTL solo se salta durante la ventana, y pasada se re-caza. Un
///     `ttl_secs <= 0` desactiva esta segunda caducidad (solo huella). El TTL solo
///     puede ABRIR un salto a reintento, nunca al revés — nunca convierte un
///     Reintentar en Saltar.
pub fn decidir(
    causa: Causa,
    huella_guardada: &str,
    huella_actual: &str,
    edad_secs: i64,
    ttl_secs: i64,
) -> Accion {
    if huella_guardada != huella_actual {
        // El entorno cambió: el veredicto negativo caducó. Intento normal.
        return Accion::Reintentar { presupuesto_mult: 1 };
    }
    let accion = politica(causa);
    // El TTL solo caduca los veredictos que SALTARÍAN (los que ahorran trabajo y
    // por tanto arriesgan el falso negativo); los que ya reintentan no lo necesitan.
    let saltaria = matches!(accion, Accion::Saltar | Accion::EncolarGeneracion);
    if saltaria && ttl_secs > 0 && edad_secs > ttl_secs {
        return Accion::Reintentar { presupuesto_mult: 1 };
    }
    accion
}

/// Registra (o reafirma) el veredicto negativo de una `(host, clase)`. Upsert por
/// `UNIQUE(host, clase)`: una causa nueva SUSTITUYE a la anterior (el último
/// veredicto manda) y refresca la huella; si se reafirma la MISMA causa se
/// incrementa `veces` (señal de crónico), y si la causa CAMBIA `veces` vuelve a 1
/// —cuenta reafirmaciones de ESTA causa, no toques a la fila (directiva 32)—.
///
/// CONTRATO DE HUELLA (obs. de la revisión, 2026-08-24): la `huella` es OPACA para
/// este módulo —`decidir` solo la compara por igualdad—, pero el WRITER y el futuro
/// READER de enforcement de una `(host, clase)` DEBEN computarla con la MISMA
/// función, o el subsistema no discrimina. Hoy el único writer es `arnm`, que usa
/// `arnm::huella_filtro` (namespace del filtro SSRF, igual que ya llavea a
/// `secuencias`); quien cable el enforcement de la clase `"ssrf"` debe leer con esa
/// misma huella (computable tras la primera sonda, como hace `secuencias`), NO con
/// `secuencias::PosturaDefensa::huella`. Los fixtures de los tests usan cadenas
/// ilustrativas: solo ejercitan la lógica de igualdad, no fijan el formato.
pub async fn registrar(
    pool: &SqlitePool,
    host: &str,
    clase: &str,
    causa: Causa,
    huella: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO exclusiones (host, clase, causa, huella, veces, registrado_en)
         VALUES (?1, ?2, ?3, ?4, 1, CURRENT_TIMESTAMP)
         ON CONFLICT(host, clase) DO UPDATE SET
             veces         = CASE WHEN causa = excluded.causa THEN veces + 1 ELSE 1 END,
             causa         = excluded.causa,
             huella        = excluded.huella,
             registrado_en = CURRENT_TIMESTAMP",
    )
    .bind(host)
    .bind(clase)
    .bind(causa.a_str())
    .bind(huella)
    .execute(pool)
    .await?;
    Ok(())
}

/// Borra el veredicto negativo de una `(host, clase)` — se llama cuando esa clase
/// CONSIGUE un hallazgo confirmado sobre el host: ya no está excluida (no agotada,
/// no inexistente), y dejar el veredicto viejo mentiría a la próxima decisión. No
/// falla si no había fila.
pub async fn limpiar(pool: &SqlitePool, host: &str, clase: &str) -> Result<()> {
    sqlx::query("DELETE FROM exclusiones WHERE host = ?1 AND clase = ?2")
        .bind(host)
        .bind(clase)
        .execute(pool)
        .await?;
    Ok(())
}

/// El veredicto negativo vigente de una `(host, clase)`, si lo hay: su causa y la
/// huella con que se registró. `None` si nunca se excluyó (→ el llamante corre la
/// fase con normalidad: falla ABIERTO, directiva 20). Una fila con causa corrupta
/// se trata como si no existiera (se re-mide), nunca como un dato válido.
pub async fn consultar(pool: &SqlitePool, host: &str, clase: &str) -> Result<Option<(Causa, String)>> {
    let fila: Option<(String, String)> = sqlx::query_as(
        "SELECT causa, huella FROM exclusiones WHERE host = ?1 AND clase = ?2",
    )
    .bind(host)
    .bind(clase)
    .fetch_optional(pool)
    .await?;
    Ok(fila.and_then(|(c, h)| Causa::desde_str(&c).map(|causa| (causa, h))))
}

/// La ACCIÓN a tomar sobre una `(host, clase)` dada la huella actual y el TTL:
/// consulta el veredicto guardado (con su EDAD en segundos, calculada en SQL sobre
/// `registrado_en` en UTC) y lo pasa por el oráculo. Sin veredicto previo → intento
/// normal. Es el punto único que usa el planificador antes de correr una fase cara.
/// `ttl_secs <= 0` desactiva la caducidad por antigüedad (solo por huella).
pub async fn accion_para(
    pool: &SqlitePool,
    host: &str,
    clase: &str,
    huella_actual: &str,
    ttl_secs: i64,
) -> Result<Accion> {
    // La edad se calcula en SQLite (julianday, UTC) para no arrastrar un reloj ni
    // problemas de zona: `registrado_en` es CURRENT_TIMESTAMP (UTC).
    let fila: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT causa, huella,
                CAST((julianday('now') - julianday(registrado_en)) * 86400 AS INTEGER)
         FROM exclusiones WHERE host = ?1 AND clase = ?2",
    )
    .bind(host)
    .bind(clase)
    .fetch_optional(pool)
    .await?;
    match fila.and_then(|(c, h, e)| Causa::desde_str(&c).map(|causa| (causa, h, e))) {
        Some((causa, huella_guardada, edad_secs)) => {
            Ok(decidir(causa, &huella_guardada, huella_actual, edad_secs, ttl_secs))
        }
        None => Ok(Accion::Reintentar { presupuesto_mult: 1 }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn causa_ida_y_vuelta() {
        for c in [
            Causa::Tiempo,
            Causa::InoperabilidadTransitoria,
            Causa::InoperabilidadPermanente,
            Causa::MetodosAgotados,
            Causa::Inexistencia,
            Causa::Esteril,
        ] {
            assert_eq!(Causa::desde_str(c.a_str()), Some(c), "round-trip roto para {c:?}");
        }
        assert_eq!(Causa::desde_str("inventada"), None, "una causa desconocida falla ruidoso");
    }

    // --- El oráculo de política: cada causa se subsana como debe ---

    #[test]
    fn tiempo_reintenta_con_mas_presupuesto() {
        assert_eq!(politica(Causa::Tiempo), Accion::Reintentar { presupuesto_mult: 2 });
    }

    #[test]
    fn metodos_agotados_van_a_generacion_no_a_repetir() {
        // La distinción clave: agotar el arsenal NO es reintentar el arsenal.
        assert_eq!(politica(Causa::MetodosAgotados), Accion::EncolarGeneracion);
    }

    #[test]
    fn inexistencia_y_permanente_se_saltan() {
        assert_eq!(politica(Causa::Inexistencia), Accion::Saltar);
        assert_eq!(politica(Causa::InoperabilidadPermanente), Accion::Saltar);
    }

    #[test]
    fn transitoria_y_esteril_reintentan_normal() {
        assert_eq!(politica(Causa::InoperabilidadTransitoria), Accion::Reintentar { presupuesto_mult: 1 });
        assert_eq!(politica(Causa::Esteril), Accion::Reintentar { presupuesto_mult: 1 });
    }

    // --- La caducidad por huella: el par rojo/verde del oráculo `decidir` ---

    #[test]
    fn misma_huella_aplica_la_politica() {
        // ROJO: la inexistencia con la MISMA huella se salta (no se re-machaca).
        assert_eq!(decidir(Causa::Inexistencia, "s=200;waf=akamai", "s=200;waf=akamai", 0, 0), Accion::Saltar);
        assert_eq!(
            decidir(Causa::Tiempo, "s=403;waf=cloudflare", "s=403;waf=cloudflare", 0, 0),
            Accion::Reintentar { presupuesto_mult: 2 }
        );
    }

    #[test]
    fn ttl_caduca_por_antiguedad_solo_los_saltos() {
        let h = "s=403;waf=akamai";
        // Fresco (edad 1s < ttl 3600s): un MetodosAgotados SALTA (EncolarGeneracion).
        assert_eq!(decidir(Causa::MetodosAgotados, h, h, 1, 3600), Accion::EncolarGeneracion);
        // Viejo (edad > ttl): CADUCA por antigüedad → reintento normal, aunque la
        // huella coincida. Cierra el falso negativo del host que se abrió sin cambiar
        // su postura. Mismo comportamiento para Inexistencia (Saltar).
        assert_eq!(decidir(Causa::MetodosAgotados, h, h, 7200, 3600), Accion::Reintentar { presupuesto_mult: 1 });
        assert_eq!(decidir(Causa::Inexistencia, h, h, 7200, 3600), Accion::Reintentar { presupuesto_mult: 1 });
        // ttl<=0 desactiva la caducidad por antigüedad: un viejo MetodosAgotados
        // sigue saltando (solo la huella lo caduca).
        assert_eq!(decidir(Causa::MetodosAgotados, h, h, 999_999, 0), Accion::EncolarGeneracion);
        // El TTL NO toca las causas que ya reintentan: una Tiempo vieja sigue ×2,
        // no la "abre" de más (el TTL solo caduca saltos, nunca crea uno).
        assert_eq!(decidir(Causa::Tiempo, h, h, 999_999, 3600), Accion::Reintentar { presupuesto_mult: 2 });
    }

    #[tokio::test]
    async fn un_confirmado_limpia_la_exclusion() {
        // Cruza la BD: registrar → limpiar deja la (host,clase) sin veredicto, así
        // que la próxima consulta la corre con normalidad (no arrastra un "agotado"
        // sobre un host donde acabamos de confirmar algo).
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::db::open(&dir.path().join("l.db"), 2).await.unwrap();
        registrar(&pool, "h.com", "ssrf", Causa::MetodosAgotados, "s=200").await.unwrap();
        assert!(consultar(&pool, "h.com", "ssrf").await.unwrap().is_some());
        limpiar(&pool, "h.com", "ssrf").await.unwrap();
        assert!(consultar(&pool, "h.com", "ssrf").await.unwrap().is_none(), "el confirmado borró la exclusión");
        // Limpiar lo que no existe no falla.
        limpiar(&pool, "h.com", "otra").await.unwrap();
    }

    #[test]
    fn huella_distinta_caduca_el_veredicto_y_reintenta_normal() {
        // VERDE: el objetivo cambió su postura (bajó el WAF) → hasta un veredicto
        // PERMANENTE o de INEXISTENCIA caduca y se vuelve a probar con normalidad.
        // Sin esto, un objetivo que se abrió quedaría excluido para siempre (ciego).
        assert_eq!(
            decidir(Causa::InoperabilidadPermanente, "s=403;waf=akamai;muro=1", "s=200;waf=-;muro=0", 0, 0),
            Accion::Reintentar { presupuesto_mult: 1 }
        );
        assert_eq!(
            decidir(Causa::Inexistencia, "s=200;sec=-", "s=200;sec=csp,hsts", 0, 0),
            Accion::Reintentar { presupuesto_mult: 1 }
        );
        // Y una de tiempo con huella distinta NO conserva el ×2: es un caso nuevo.
        assert_eq!(
            decidir(Causa::Tiempo, "s=200;waf=-", "s=200;waf=cloudflare", 0, 0),
            Accion::Reintentar { presupuesto_mult: 1 }
        );
    }
}
