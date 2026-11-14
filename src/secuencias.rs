//! SECUENCIAS — la memoria de adaptación del cazador (analogía ARNm de Juan,
//! 2026-08-23). El «laboratorio de quipu, pero inverso»: quipu construye la
//! defensa y la mide con un caso rojo que debe fallar por la vía real; esto
//! ataca, y guarda solo lo que un oráculo duro confirmó, con la misma exigencia.
//!
//! Nuclei es un antibiótico de amplio espectro: una firma fija contra un
//! patógeno conocido. Estático. El día que el objetivo se endurece, la plantilla
//! deja de casar y devuelve SECO. Un virus no lleva firma sino método: muta
//! contra el entorno y GUARDA la secuencia que funcionó. Este módulo es ese
//! guardado, con las dos piezas que separan criar un virus de acumular ruido:
//!
//!   - SELECCIÓN: una secuencia solo se escribe con un `OraculoConfirmado`, un
//!     testigo que no se puede construir sin `execution_confirmed=true`. Guardar
//!     sin oráculo no compila (directiva 20: falla ruidoso, nunca por defecto).
//!
//!   - CADUCIDAD: la mutación se llavea a la HUELLA DE DEFENSA del host. Al
//!     reencontrarlo, si la huella actual difiere, la secuencia caduca y no se
//!     re-lanza — el huésped mutó su defensa (directiva 31: el veredicto se
//!     ancla al artefacto, aquí la postura defensiva, no a "este host ya lo
//!     rompimos una vez").

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::Result;

/// Testigo de que el oráculo DURO confirmó la ejecución. Es un tipo que no se
/// puede construir sin ejecución confirmada: `guardar` lo exige por referencia,
/// así que "solo el oráculo escribe secuencias" es un hecho del compilador, no
/// una convención que se olvida. El campo privado `()` impide construirlo por
/// literal desde fuera del módulo.
#[derive(Debug)]
pub struct OraculoConfirmado(());

impl OraculoConfirmado {
    /// Único camino a un testigo. `None` si la herramienta NO vio ejecución
    /// real — el mismo listón que gatea el auto-envío a H1 (`execution_confirmed`,
    /// migración 0004), no la heurística `exploitable`.
    pub fn desde_ejecucion(execution_confirmed: bool) -> Option<Self> {
        if execution_confirmed {
            Some(Self(()))
        } else {
            None
        }
    }
}

/// La postura defensiva OBSERVABLE de un host: el "entorno" al que el virus se
/// adapta. Todo son señales que el escáner ya recoge (status del sondeo sin
/// auth, challenge de WAF, familia del WAF por cabecera, amurallamiento de IP
/// —memoria muro-403—, y el conjunto de cabeceras de seguridad presentes).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PosturaDefensa {
    /// Status ante una petición SIN autenticar al recurso protegido. Se
    /// normaliza a su CLASE (2xx/3xx/4xx/5xx) salvo los que discriminan control
    /// de acceso, que se conservan exactos: 401, 403, 404, 429.
    pub status_no_auth: u16,
    /// ¿El cuerpo es un challenge anti-bot (Cloudflare "Just a moment…")? Un 403
    /// así NO es un endpoint protegido; cambia radicalmente qué mutación aplica.
    pub es_challenge: bool,
    /// Familia del WAF/CDN si se pudo inferir de cabeceras (cloudflare, akamai,
    /// awswaf…). `None` si no se detectó ninguna.
    pub familia_waf: Option<String>,
    /// ¿El host nos AMURALLA la IP tras varios 403 seguidos? (memoria
    /// muro-403-ip-compartida). Cambia la estrategia entera: hay que rotar salida.
    pub amuralla_ip: bool,
    /// Cabeceras de seguridad presentes (hsts, csp, x-frame-options…). Su
    /// aparición/desaparición es la señal más limpia de "el host se endureció".
    pub cabeceras_seguridad: Vec<String>,
}

impl PosturaDefensa {
    /// La HUELLA: cadena canónica, estable y legible, de la postura. Estable =
    /// mismas entradas → misma cadena, entre versiones del binario (por eso NO
    /// se usa un hasher, cuyo seed no se garantiza entre versiones). Legible =
    /// en un dictamen se puede MOSTRAR por qué una secuencia caducó.
    ///
    /// Canonicalización: el status a su forma discriminante, el WAF en
    /// minúsculas, y las cabeceras de seguridad ORDENADAS y deduplicadas (el
    /// orden de llegada no es parte de la postura; el conjunto sí).
    pub fn huella(&self) -> String {
        let mut cabeceras: Vec<String> =
            self.cabeceras_seguridad.iter().map(|c| c.to_ascii_lowercase()).collect();
        cabeceras.sort();
        cabeceras.dedup();
        let waf = self.familia_waf.as_deref().unwrap_or("-").to_ascii_lowercase();
        format!(
            "s={};ch={};waf={};muro={};sec={}",
            self.status_no_auth,
            u8::from(self.es_challenge),
            waf,
            u8::from(self.amuralla_ip),
            if cabeceras.is_empty() { "-".to_string() } else { cabeceras.join(",") },
        )
    }
}

/// Una MUTACIÓN: la variante parametrizada de una sonda que funcionó. Estructural
/// —una técnica con nombre y un mapa ordenado de parámetros—, NO texto libre de
/// un LLM: eso es lo que mantiene al cazador con forma de laboratorio y no de
/// brain. El `BTreeMap` da serialización canónica (orden estable de claves), que
/// es lo que hace la clave UNIQUE(host, familia, mutacion) determinista.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mutacion {
    /// Familia de la vulnerabilidad/técnica: autz-idor, bypass-403, ssrf-oob…
    pub familia: String,
    /// Técnica base sobre la que se mutó (p. ej. "header-inject", "path-mangle").
    pub tecnica: String,
    /// Los parámetros que se variaron respecto de la sonda base. Ordenado.
    pub parametros: BTreeMap<String, String>,
}

impl Mutacion {
    /// JSON canónico para persistir y deduplicar. Determinista por el `BTreeMap`.
    pub fn canonico(&self) -> String {
        // serde_json sobre un BTreeMap emite las claves en orden; el struct tiene
        // orden de campos fijo. Serialización infalible para estos tipos.
        serde_json::to_string(self).expect("Mutacion siempre serializa")
    }
}

/// Una secuencia recuperada de la memoria, lista para re-lanzar.
#[derive(Debug, Clone)]
pub struct SecuenciaVigente {
    pub id: i64,
    pub mutacion: Mutacion,
    pub huella_defensa: String,
    pub veces_confirmada: i64,
    pub repro_ratio: Option<String>,
}

/// GUARDA una secuencia confirmada. Exige el testigo `OraculoConfirmado`: sin él
/// no se puede llamar. Si la mutación ya existía para (host, familia), la
/// REVALIDA (veces_confirmada++, refresca huella y confirmada_en) en vez de
/// duplicar — la misma técnica contra el mismo host es la misma secuencia.
///
/// Devuelve `true` si nació una secuencia nueva, `false` si revalidó una
/// existente.
#[allow(clippy::too_many_arguments)] // escritura a BD: muchos campos por naturaleza (cf. db.rs)
pub async fn guardar(
    pool: &SqlitePool,
    _oraculo: &OraculoConfirmado, // <- la selección: no compila sin esto
    program_name: &str,
    host: &str,
    huella: &str,
    mutacion: &Mutacion,
    evidencia_ref: Option<&str>,
    repro_ratio: Option<&str>,
) -> Result<bool> {
    let canonico = mutacion.canonico();
    // UPSERT: si (host, familia, mutacion) ya existe, revalida y REACTIVA
    // (caducada=0) con la huella nueva — el oráculo acaba de confirmarla otra vez
    // bajo la postura actual, así que vuelve a estar vigente.
    //
    // `rows_affected()` NO sirve para distinguir alta de revalidación: en un
    // upsert de SQLite devuelve 1 en ambos casos. Se usa `RETURNING
    // veces_confirmada`: en un alta nace en 1; una revalidación la sube a ≥2.
    let veces: i64 = sqlx::query_scalar(
        "INSERT INTO secuencias
            (program_name, host, familia, huella_defensa, mutacion, evidencia_ref, repro_ratio)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(host, familia, mutacion) DO UPDATE SET
            veces_confirmada = veces_confirmada + 1,
            huella_defensa   = excluded.huella_defensa,
            evidencia_ref    = COALESCE(excluded.evidencia_ref, secuencias.evidencia_ref),
            repro_ratio      = COALESCE(excluded.repro_ratio, secuencias.repro_ratio),
            caducada         = 0,
            confirmada_en    = datetime('now')
         RETURNING veces_confirmada",
    )
    .bind(program_name)
    .bind(host)
    .bind(&mutacion.familia)
    .bind(huella)
    .bind(&canonico)
    .bind(evidencia_ref)
    .bind(repro_ratio)
    .fetch_one(pool)
    .await?;
    Ok(veces == 1)
}

/// RECUPERA las secuencias que valen para re-lanzar contra `host`/`familia` bajo
/// la huella ACTUAL, y en la misma pasada CADUCA las que ya no valen.
///
/// La regla, en una frase (directiva 23, sin "en cualquier otro caso"): devuelve
/// exactamente las mutaciones de este host y familia cuya huella guardada COINCIDE
/// con la actual y que no están caducadas; y marca `caducada` toda la de este
/// host y familia cuya huella DIFIERE de la actual.
///
/// Las dos caras del fallo (directiva 23, la pareja):
///   - lado RUIDOSO: re-lanzar una secuencia obsoleta (huella cambió) quema señal
///     en el programa → esas se caducan y NO se devuelven.
///   - lado CIEGO: no re-lanzar una secuencia válida (huella coincide) hace la
///     memoria inútil → esas SÍ se devuelven, y NO se caducan.
pub async fn recuperar(
    pool: &SqlitePool,
    host: &str,
    familia: &str,
    huella_actual: &str,
) -> Result<Vec<SecuenciaVigente>> {
    // 1. Caduca lo que dejó de describir el entorno: misma host+familia, huella
    //    distinta, aún viva. (No toca las que coinciden: no sobre-caduca.)
    sqlx::query(
        "UPDATE secuencias SET caducada = 1
         WHERE host = ?1 AND familia = ?2 AND huella_defensa <> ?3 AND caducada = 0",
    )
    .bind(host)
    .bind(familia)
    .bind(huella_actual)
    .execute(pool)
    .await?;

    // 2. Devuelve solo lo vigente bajo la huella actual. `veces_confirmada > 0`
    //    es el blindaje de la reforma-biblioteca: la tabla ahora guarda también
    //    variantes REFUTADAS (veces_confirmada=0, veces_refutada>=1); el replay
    //    confirmado por-host NO debe re-lanzarlas como si fueran aciertos. El
    //    reciclaje de refutadas es otra vía (`biblioteca`), no ésta.
    let filas: Vec<(i64, String, String, i64, Option<String>)> = sqlx::query_as(
        "SELECT id, mutacion, huella_defensa, veces_confirmada, repro_ratio
         FROM secuencias
         WHERE host = ?1 AND familia = ?2 AND huella_defensa = ?3 AND caducada = 0
           AND veces_confirmada > 0
         ORDER BY veces_confirmada DESC, id ASC",
    )
    .bind(host)
    .bind(familia)
    .bind(huella_actual)
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(filas.len());
    for (id, mut_json, huella_defensa, veces, repro) in filas {
        // Una mutación ilegible en la BD es un dato corrupto: se salta con aviso,
        // no se inventa (directiva 20). No debería pasar: lo escribió `canonico`.
        match serde_json::from_str::<Mutacion>(&mut_json) {
            Ok(mutacion) => out.push(SecuenciaVigente {
                id,
                mutacion,
                huella_defensa,
                veces_confirmada: veces,
                repro_ratio: repro,
            }),
            Err(e) => tracing::warn!("secuencia {id} ilegible, se ignora: {e}"),
        }
    }
    Ok(out)
}

/// Cuántas secuencias vigentes (no caducadas) guarda la memoria para un host.
/// Para el panel/dictamen: el tamaño del corpus adaptado es la evidencia del foso.
pub async fn contar_vigentes(pool: &SqlitePool, host: &str) -> Result<i64> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM secuencias WHERE host = ?1 AND caducada = 0",
    )
    .bind(host)
    .fetch_one(pool)
    .await?;
    Ok(n)
}

/// Cuenta solo las secuencias CONFIRMADAS y vigentes de un host (aciertos reales).
/// Desde el camino A (2026-08-26) la tabla también guarda FRACASOS (refutadas y
/// amuralladas, para reciclar cross-host), así que `contar_vigentes` —que cuenta
/// TODA fila viva— dejó de equivaler a «cuántos aciertos hay». Esta lo dice sin
/// ambigüedad: es la que quiere quien pregunta si el oráculo confirmó algo aquí.
pub async fn contar_confirmadas(pool: &SqlitePool, host: &str) -> Result<i64> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM secuencias WHERE host = ?1 AND veces_confirmada > 0 AND caducada = 0",
    )
    .bind(host)
    .fetch_one(pool)
    .await?;
    Ok(n)
}

/// REGISTRA un FRACASO: esta variante se probó contra `host` bajo la postura
/// actual y el oráculo NO confirmó. Es la cara opuesta de `guardar`, y por eso NO
/// exige el testigo `OraculoConfirmado` — no afirma un éxito, afirma un intento sin
/// éxito, que es legítimo guardar (y necesario: es lo que hace la variante
/// reciclable en otro sitio, la observación de Juan 2026-08-26).
///
/// NO toca `veces_confirmada` ni `caducada`: un fracaso AQUÍ no des-confirma un
/// acierto previo en este mismo host (de eso se ocupa la caducidad por huella).
/// Si la fila no existía, nace con `veces_confirmada = 0` — una variante conocida
/// pero aún no probada-buena en ningún sitio, que la biblioteca ordena por debajo
/// de las confirmadas pero por encima de nada (sigue siendo candidata en otro host).
pub async fn registrar_refutada(
    pool: &SqlitePool,
    program_name: &str,
    host: &str,
    huella: &str,
    mutacion: &Mutacion,
) -> Result<()> {
    let canonico = mutacion.canonico();
    sqlx::query(
        "INSERT INTO secuencias
            (program_name, host, familia, huella_defensa, mutacion,
             veces_confirmada, veces_refutada, intentada_en)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, 1, datetime('now'))
         ON CONFLICT(host, familia, mutacion) DO UPDATE SET
            veces_refutada = veces_refutada + 1,
            huella_defensa = excluded.huella_defensa,
            intentada_en   = datetime('now')",
    )
    .bind(program_name)
    .bind(host)
    .bind(&mutacion.familia)
    .bind(huella)
    .bind(&canonico)
    .execute(pool)
    .await?;
    Ok(())
}

/// REGISTRA un BLOQUEO: esta variante se probó contra `host` y el WAF/app la AMURALLÓ
/// (status >= 400) — nunca llegó a procesarse server-side. Camino A (Juan 2026-08-26):
/// la amurallada TAMBIÉN entra a la biblioteca, porque un 403 es ruido de la postura
/// de ESTE host, no de la variante, y cross-host sigue siendo un candidato no probado.
/// Pero se marca en `veces_amurallada` (no en `veces_refutada`): es señal más débil que
/// una refutación servida, y el reciclaje la ordena por debajo (no reciclar a ciegas).
///
/// Como `registrar_refutada`, NO exige testigo (no afirma éxito) y NO toca
/// `veces_confirmada` ni `caducada`. Si la fila no existía, nace con las dos caras de
/// éxito/servido en 0 — una variante conocida solo por haber sido bloqueada en algún
/// sitio, candidata al fondo de la cola en otro host de distinta postura.
pub async fn registrar_amurallada(
    pool: &SqlitePool,
    program_name: &str,
    host: &str,
    huella: &str,
    mutacion: &Mutacion,
) -> Result<()> {
    let canonico = mutacion.canonico();
    sqlx::query(
        "INSERT INTO secuencias
            (program_name, host, familia, huella_defensa, mutacion,
             veces_confirmada, veces_refutada, veces_amurallada, intentada_en)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, 1, datetime('now'))
         ON CONFLICT(host, familia, mutacion) DO UPDATE SET
            veces_amurallada = veces_amurallada + 1,
            huella_defensa   = excluded.huella_defensa,
            intentada_en     = datetime('now')",
    )
    .bind(program_name)
    .bind(host)
    .bind(&mutacion.familia)
    .bind(huella)
    .bind(&canonico)
    .execute(pool)
    .await?;
    Ok(())
}

/// Una variante candidata que la BIBLIOTECA recicla desde otros hosts, con su
/// registro global (para que el llamante y el dictamen vean por qué se prioriza).
#[derive(Debug, Clone)]
pub struct Candidata {
    pub mutacion: Mutacion,
    /// Suma de confirmaciones de esta variante a través de TODOS los hosts.
    pub confirmada_global: i64,
    /// Suma de refutaciones SERVIDAS (status < 400) a través de todos los hosts.
    pub refutada_global: i64,
    /// Suma de bloqueos (status >= 400) a través de todos los hosts. Señal más débil
    /// que `refutada_global`: la variante nunca llegó a procesarse en esos hosts.
    pub amurallada_global: i64,
}

/// LA BIBLIOTECA — el reciclaje cross-host (Juan 2026-08-26). Devuelve las
/// variantes de esta `familia`, probadas en OTROS hosts, que `host_actual` AÚN NO
/// ha intentado, priorizadas por puntaje global. Es lo barato que se prueba ANTES
/// de generar una variante nueva (cara, con riesgo brain): en cada sitio nuevo se
/// re-lanza el corpus acumulado primero.
///
/// El PUNTAJE (el anti-ruido que Juan pidió, y que sobrevive donde brain no porque
/// el oráculo es limpio):
///   1. las CONFIRMADAS en algún lado primero (probaron edge real);
///   2. entre las confirmadas, más confirmaciones globales primero;
///   3. las SERVIDAS (refutada>0) por encima de las solo-amuralladas: una variante que
///      la app llegó a procesar en algún sitio es candidata más fuerte que una que solo
///      se ha topado con muros (camino A, Juan 2026-08-26);
///   4. entre las servidas, las MENOS refutadas primero (menos exploradas / agotadas);
///   5. las solo-AMURALLADAS al fondo, menos-amuralladas primero — se reciclan solo
///      tras agotar lo servido, y el LIMITE las acota (la barandilla anti-ciego).
///
/// Sin exclusión dura: una variante refutada N veces sigue en la lista, solo que al
/// fondo — puede ganar en la config del sitio N+1 (dir. 21: no cerrar por inusual).
/// El `LIMITE` es la barandilla anti-baneo: nunca se recicla un corpus ilimitado
/// contra un objetivo de un tirón.
///
/// Excluye las ya intentadas en `host_actual` (por `mutacion`): no re-sugiere lo
/// que este host ya probó, sea acierto o fracaso — eso lo cubre `recuperar` (los
/// aciertos) y no hay razón para re-fracasar un fracaso conocido del mismo host.
pub async fn biblioteca(
    pool: &SqlitePool,
    familia: &str,
    host_actual: &str,
    limite: i64,
) -> Result<Vec<Candidata>> {
    // NOTA (revisión 2026-08-26): `biblioteca` IGNORA `caducada` a propósito. La
    // caducidad se ancla a la HUELLA del host DONDE la variante se confirmó
    // (`recuperar` la respeta para el replay por-host); pero el reciclaje cross-host
    // es POSTURE-AGNÓSTICO por diseño — una variante caducada en el host A (A mutó su
    // defensa) sigue siendo candidata válida para el host B, que tiene su propia
    // postura. Filtrar por `caducada` aquí cegaría el reciclaje sin razón.
    let filas: Vec<(String, i64, i64, i64)> = sqlx::query_as(
        "SELECT mutacion,
                SUM(veces_confirmada) AS conf,
                SUM(veces_refutada)   AS refu,
                SUM(veces_amurallada) AS amur
         FROM secuencias
         WHERE familia = ?1
           AND mutacion NOT IN (
               SELECT mutacion FROM secuencias WHERE familia = ?1 AND host = ?2
           )
         GROUP BY mutacion
         ORDER BY (SUM(veces_confirmada) > 0) DESC,
                  SUM(veces_confirmada) DESC,
                  (SUM(veces_refutada) > 0)  DESC,
                  SUM(veces_refutada)   ASC,
                  SUM(veces_amurallada) ASC,
                  mutacion ASC
         LIMIT ?3",
    )
    .bind(familia)
    .bind(host_actual)
    .bind(limite)
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(filas.len());
    for (mut_json, conf, refu, amur) in filas {
        // Corrupto = se salta con aviso, no se inventa (directiva 20).
        match serde_json::from_str::<Mutacion>(&mut_json) {
            Ok(mutacion) => out.push(Candidata {
                mutacion,
                confirmada_global: conf,
                refutada_global: refu,
                amurallada_global: amur,
            }),
            Err(e) => tracing::warn!("candidata ilegible en biblioteca, se ignora: {e}"),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mutacion_demo(tecnica: &str) -> Mutacion {
        let mut p = BTreeMap::new();
        p.insert("cabecera".into(), "X-Original-URL".into());
        p.insert("valor".into(), "/admin".into());
        Mutacion { familia: "bypass-403".into(), tecnica: tecnica.into(), parametros: p }
    }

    // ---- Unidad pura: la huella ----

    #[test]
    fn huella_es_estable_e_independiente_del_orden_de_cabeceras() {
        let a = PosturaDefensa {
            status_no_auth: 403,
            es_challenge: false,
            familia_waf: Some("Cloudflare".into()),
            amuralla_ip: true,
            cabeceras_seguridad: vec!["CSP".into(), "HSTS".into()],
        };
        let b = PosturaDefensa {
            // mismas señales, cabeceras en otro orden y otra caja
            status_no_auth: a.status_no_auth,
            es_challenge: a.es_challenge,
            amuralla_ip: a.amuralla_ip,
            cabeceras_seguridad: vec!["hsts".into(), "csp".into()],
            familia_waf: Some("cloudflare".into()),
        };
        assert_eq!(a.huella(), b.huella(), "la huella debe ser canónica");
        assert_eq!(a.huella(), "s=403;ch=0;waf=cloudflare;muro=1;sec=csp,hsts");
    }

    #[test]
    fn huella_cambia_cuando_el_host_se_endurece() {
        let antes = PosturaDefensa {
            status_no_auth: 200, // endpoint estaba abierto
            ..Default::default()
        };
        let despues = PosturaDefensa {
            status_no_auth: 403, // ahora protegido
            familia_waf: Some("akamai".into()),
            cabeceras_seguridad: vec!["hsts".into()],
            ..Default::default()
        };
        assert_ne!(antes.huella(), despues.huella(), "endurecerse cambia la huella");
    }

    // ---- La SELECCIÓN: el testigo del oráculo ----

    #[test]
    fn sin_ejecucion_confirmada_no_hay_testigo() {
        // RED por la vía real: el oráculo dijo NO → no se puede ni intentar guardar.
        assert!(OraculoConfirmado::desde_ejecucion(false).is_none());
        // GREEN: ejecución confirmada → testigo.
        assert!(OraculoConfirmado::desde_ejecucion(true).is_some());
    }

    // ---- Persistencia: par verde/rojo sobre BD real ----

    async fn pool_memoria() -> SqlitePool {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn verde_confirma_y_relanza_bajo_misma_huella() {
        let pool = pool_memoria().await;
        let testigo = OraculoConfirmado::desde_ejecucion(true).unwrap();
        let huella = PosturaDefensa { status_no_auth: 403, ..Default::default() }.huella();
        let m = mutacion_demo("header-inject");

        let nueva = guardar(&pool, &testigo, "prog", "api.ejemplo.com", &huella, &m, Some("f#1"), Some("3/3"))
            .await
            .unwrap();
        assert!(nueva, "primera vez: secuencia nueva");

        // Reencuentro con la MISMA huella → se re-lanza (lado ciego cubierto:
        // una memoria válida DEBE aflorar).
        let vig = recuperar(&pool, "api.ejemplo.com", "bypass-403", &huella).await.unwrap();
        assert_eq!(vig.len(), 1, "la secuencia válida debe re-lanzarse");
        assert_eq!(vig[0].mutacion, m);
        assert_eq!(vig[0].repro_ratio.as_deref(), Some("3/3"));
    }

    #[tokio::test]
    async fn rojo_huella_cambiada_caduca_y_no_relanza() {
        let pool = pool_memoria().await;
        let testigo = OraculoConfirmado::desde_ejecucion(true).unwrap();
        let huella_vieja = PosturaDefensa { status_no_auth: 403, ..Default::default() }.huella();
        let m = mutacion_demo("header-inject");
        guardar(&pool, &testigo, "prog", "api.ejemplo.com", &huella_vieja, &m, None, None)
            .await
            .unwrap();

        // El host MUTÓ su defensa (ahora hay WAF): huella distinta.
        let huella_nueva = PosturaDefensa {
            status_no_auth: 403,
            familia_waf: Some("cloudflare".into()),
            ..Default::default()
        }
        .huella();

        // RED por la vía REAL (huella distinta, no una bandera fabricada): la
        // secuencia vieja NO debe re-lanzarse. Un impl que ignore la huella
        // —el mutante que este caso mata— devolvería la secuencia obsoleta.
        let vig = recuperar(&pool, "api.ejemplo.com", "bypass-403", &huella_nueva).await.unwrap();
        assert!(vig.is_empty(), "huella cambiada: no se re-lanza la secuencia obsoleta");

        // Y quedó marcada caducada (no meramente filtrada): visible en el corpus.
        assert_eq!(contar_vigentes(&pool, "api.ejemplo.com").await.unwrap(), 0);

        // Contraprueba de que NO sobre-caduca: con la huella VIEJA otra vez, la
        // secuencia ya está caducada y no revive sola (solo el oráculo la revive).
        let vig_vieja = recuperar(&pool, "api.ejemplo.com", "bypass-403", &huella_vieja).await.unwrap();
        assert!(vig_vieja.is_empty(), "una vez caducada, no revive sin reconfirmación del oráculo");
    }

    #[tokio::test]
    async fn reconfirmar_revalida_y_reactiva() {
        let pool = pool_memoria().await;
        let testigo = OraculoConfirmado::desde_ejecucion(true).unwrap();
        let h = PosturaDefensa { status_no_auth: 403, ..Default::default() }.huella();
        let m = mutacion_demo("header-inject");

        assert!(guardar(&pool, &testigo, "prog", "h.com", &h, &m, None, None).await.unwrap());
        // Segunda confirmación de la MISMA mutación: revalida, no duplica.
        let nueva = guardar(&pool, &testigo, "prog", "h.com", &h, &m, None, None).await.unwrap();
        assert!(!nueva, "misma mutación: revalida, no nace otra");

        let vig = recuperar(&pool, "h.com", "bypass-403", &h).await.unwrap();
        assert_eq!(vig.len(), 1);
        assert_eq!(vig[0].veces_confirmada, 2, "veces_confirmada sube al revalidar");
    }

    #[tokio::test]
    async fn no_sobrecaduca_secuencia_de_misma_huella() {
        // Lado ciego, explícito: recuperar NO debe caducar la que coincide.
        let pool = pool_memoria().await;
        let testigo = OraculoConfirmado::desde_ejecucion(true).unwrap();
        let h = PosturaDefensa { status_no_auth: 403, ..Default::default() }.huella();
        let m = mutacion_demo("header-inject");
        guardar(&pool, &testigo, "prog", "h.com", &h, &m, None, None).await.unwrap();

        // Tres reencuentros con la misma huella: sigue vigente las tres veces.
        for _ in 0..3 {
            let vig = recuperar(&pool, "h.com", "bypass-403", &h).await.unwrap();
            assert_eq!(vig.len(), 1, "misma huella: nunca se auto-caduca");
        }
    }

    // ---- REFORMA BIBLIOTECA: fracasos reciclables (Juan 2026-08-26) ----

    /// El BLINDAJE de `recuperar` (mutante: quitar `veces_confirmada > 0`): una
    /// variante REFUTADA no se re-lanza como si fuera un acierto. RED por la vía
    /// real — un refutado en el mismo host bajo la misma huella NO aflora en el
    /// replay confirmado.
    #[tokio::test]
    async fn refutada_no_se_relanza_como_acierto() {
        let pool = pool_memoria().await;
        let h = PosturaDefensa { status_no_auth: 403, ..Default::default() }.huella();
        let m = mutacion_demo("header-inject");
        registrar_refutada(&pool, "prog", "h.com", &h, &m).await.unwrap();
        // recuperar (replay confirmado) NO la devuelve: no es un acierto.
        let vig = recuperar(&pool, "h.com", "bypass-403", &h).await.unwrap();
        assert!(vig.is_empty(), "una refutada nunca se re-lanza como acierto");
    }

    /// El corazón de la reforma: una variante refutada en el host A se RECICLA en
    /// el host B (otra config puede aceptarla) pero NO se re-sugiere en A (ya la
    /// probó). Pareja: presente para B, ausente para A.
    #[tokio::test]
    async fn biblioteca_recicla_en_otro_host_no_en_el_mismo() {
        let pool = pool_memoria().await;
        let h = PosturaDefensa { status_no_auth: 403, ..Default::default() }.huella();
        let m = mutacion_demo("header-inject");
        registrar_refutada(&pool, "prog", "host-A.com", &h, &m).await.unwrap();

        // host B (nuevo): la variante entra como candidata reciclable.
        let para_b = biblioteca(&pool, "bypass-403", "host-B.com", 50).await.unwrap();
        assert_eq!(para_b.len(), 1, "la refutada en A se recicla en B");
        assert_eq!(para_b[0].mutacion, m);
        assert_eq!(para_b[0].confirmada_global, 0);
        assert_eq!(para_b[0].refutada_global, 1);

        // host A (el que ya la probó): NO se le re-sugiere.
        let para_a = biblioteca(&pool, "bypass-403", "host-A.com", 50).await.unwrap();
        assert!(para_a.is_empty(), "no se recicla en el host que ya la intentó");
    }

    /// El PUNTAJE (anti-ruido): una confirmada-en-algún-lado va ANTES que una
    /// refutada-solo. Mata al mutante que ordena sin mirar el signo del oráculo.
    #[tokio::test]
    async fn biblioteca_prioriza_confirmada_sobre_refutada() {
        let pool = pool_memoria().await;
        let testigo = OraculoConfirmado::desde_ejecucion(true).unwrap();
        let h = PosturaDefensa { status_no_auth: 403, ..Default::default() }.huella();
        let confirmada = mutacion_demo("gano-en-otro-lado");
        let refutada = mutacion_demo("fallo-en-otro-lado");
        guardar(&pool, &testigo, "prog", "host-A.com", &h, &confirmada, None, None).await.unwrap();
        registrar_refutada(&pool, "prog", "host-A.com", &h, &refutada).await.unwrap();

        let lib = biblioteca(&pool, "bypass-403", "host-nuevo.com", 50).await.unwrap();
        assert_eq!(lib.len(), 2);
        assert_eq!(lib[0].mutacion, confirmada, "la confirmada-en-algún-lado va primera");
        assert_eq!(lib[1].mutacion, refutada);
    }

    /// Entre refutadas, la MENOS agotada va primero (menos explorada). Y sin
    /// exclusión dura: la más refutada sigue en la lista, solo que al fondo.
    #[tokio::test]
    async fn biblioteca_entre_refutadas_menos_refutada_primero() {
        let pool = pool_memoria().await;
        let h = PosturaDefensa { status_no_auth: 403, ..Default::default() }.huella();
        let muy = mutacion_demo("muy-refutada");
        let poco = mutacion_demo("poco-refutada");
        // `muy` refutada en 3 hosts; `poco` en 1.
        for host in ["a.com", "b.com", "c.com"] {
            registrar_refutada(&pool, "prog", host, &h, &muy).await.unwrap();
        }
        registrar_refutada(&pool, "prog", "a.com", &h, &poco).await.unwrap();

        let lib = biblioteca(&pool, "bypass-403", "nuevo.com", 50).await.unwrap();
        assert_eq!(lib.len(), 2, "sin exclusión dura: la muy-refutada sigue presente");
        assert_eq!(lib[0].mutacion, poco, "la menos refutada va primero");
        assert_eq!(lib[0].refutada_global, 1);
        assert_eq!(lib[1].mutacion, muy);
        assert_eq!(lib[1].refutada_global, 3);
    }

    /// Un fracaso AQUÍ no des-confirma un acierto previo en el MISMO host: la
    /// variante confirmada sigue re-lanzándose. (registrar_refutada no pisa
    /// veces_confirmada.)
    #[tokio::test]
    async fn refutar_no_desconfirma_un_acierto_del_mismo_host() {
        let pool = pool_memoria().await;
        let testigo = OraculoConfirmado::desde_ejecucion(true).unwrap();
        let h = PosturaDefensa { status_no_auth: 403, ..Default::default() }.huella();
        let m = mutacion_demo("header-inject");
        guardar(&pool, &testigo, "prog", "h.com", &h, &m, None, None).await.unwrap();
        registrar_refutada(&pool, "prog", "h.com", &h, &m).await.unwrap();

        let vig = recuperar(&pool, "h.com", "bypass-403", &h).await.unwrap();
        assert_eq!(vig.len(), 1, "una refutación no borra el acierto del mismo host");
        assert_eq!(vig[0].veces_confirmada, 1);
    }

    /// El límite es la barandilla anti-baneo: `biblioteca` nunca devuelve más de
    /// `limite`, por grande que sea el corpus reciclable.
    #[tokio::test]
    async fn biblioteca_respeta_el_limite_antibaneo() {
        let pool = pool_memoria().await;
        let h = PosturaDefensa { status_no_auth: 403, ..Default::default() }.huella();
        for i in 0..10 {
            let m = mutacion_demo(&format!("variante-{i}"));
            registrar_refutada(&pool, "prog", "a.com", &h, &m).await.unwrap();
        }
        let lib = biblioteca(&pool, "bypass-403", "nuevo.com", 3).await.unwrap();
        assert_eq!(lib.len(), 3, "el limite acota el reciclaje por objetivo");
    }

    /// Camino A (Juan 2026-08-26): la variante AMURALLADA (4xx/5xx) TAMBIÉN entra a la
    /// biblioteca — pero MARCADA en su propio campo y por DEBAJO de una servida. Par
    /// discriminante en un solo test; mata tres mutantes:
    ///   (a) no-almacenar la amurallada → `lib.len()` sería 1;
    ///   (b) mandarla a `veces_refutada` (borrar la separación, dir 32) →
    ///       `amurallada.refutada_global` sería 1;
    ///   (c) ordenar sin el tier `(refutada>0) DESC` → la amurallada saldría primera
    ///       (empatan en confirmadas=0), y el orden se rompe.
    #[tokio::test]
    async fn biblioteca_amurallada_entra_marcada_y_bajo_la_servida() {
        let pool = pool_memoria().await;
        let h = PosturaDefensa { status_no_auth: 403, ..Default::default() }.huella();
        let servida = mutacion_demo("servida-sin-exfiltrar");
        let amurallada = mutacion_demo("bloqueada-por-waf");
        registrar_refutada(&pool, "prog", "host-A.com", &h, &servida).await.unwrap();
        registrar_amurallada(&pool, "prog", "host-B.com", &h, &amurallada).await.unwrap();

        let lib = biblioteca(&pool, "bypass-403", "host-nuevo.com", 50).await.unwrap();
        assert_eq!(lib.len(), 2, "la amurallada TAMBIÉN es candidata cross-host (camino A)");
        // La servida va primera (llegó a procesarse en algún host).
        assert_eq!(lib[0].mutacion, servida, "la servida va antes que la amurallada");
        assert_eq!(lib[0].refutada_global, 1);
        assert_eq!(lib[0].amurallada_global, 0);
        // La amurallada al fondo, marcada en SU campo — no ensucia veces_refutada.
        assert_eq!(lib[1].mutacion, amurallada, "la amurallada va al fondo, pero está presente");
        assert_eq!(lib[1].refutada_global, 0, "amurallada NO cuenta como refutada (dir 32)");
        assert_eq!(lib[1].amurallada_global, 1);
    }

    /// `registrar_amurallada` NO toca `veces_confirmada`: un bloqueo AQUÍ no
    /// des-confirma un acierto previo del MISMO host (misma garantía que refutada).
    #[tokio::test]
    async fn amurallar_no_desconfirma_un_acierto_del_mismo_host() {
        let pool = pool_memoria().await;
        let testigo = OraculoConfirmado::desde_ejecucion(true).unwrap();
        let h = PosturaDefensa { status_no_auth: 403, ..Default::default() }.huella();
        let m = mutacion_demo("header-inject");
        guardar(&pool, &testigo, "prog", "h.com", &h, &m, None, None).await.unwrap();
        registrar_amurallada(&pool, "prog", "h.com", &h, &m).await.unwrap();

        let vig = recuperar(&pool, "h.com", "bypass-403", &h).await.unwrap();
        assert_eq!(vig.len(), 1, "un bloqueo no borra el acierto del mismo host");
        assert_eq!(vig[0].veces_confirmada, 1);
    }
}
