//! Oráculo diferencial UNIFICADO — el núcleo compartido de whitebox y blackbox.
//!
//! Contexto (2026-09-05): el razonador (modelar→invariante→refutar→confirmar) y el
//! `certificado` anti-slop son idénticos en los dos modos; solo cambian la ENTRADA al
//! modelado (fuente clonada vs comportamiento observado) y el DESTINO de la confirmación
//! (un lab que controlamos vs un objetivo vivo con cuentas provisionadas). Esta pieza es
//! ese destino común: prueba un invariante de control de acceso —"solo el sujeto
//! AUTORIZADO ve `marca` en `ruta`"— por EJECUCIÓN con control positivo Y negativo, y
//! devuelve un [`Certificado`] (la misma puerta anti-slop del reporte).
//!
//! - **Whitebox:** `Objetivo.base` es el lab Docker; las identidades se siembran.
//! - **Blackbox:** `Objetivo.base` es el host vivo en scope; las identidades son dos
//!   cuentas provisionadas. El código es EL MISMO; cambia la construcción del `Objetivo`.
//!
//! No reconstruye la caza autónoma (esa era amplitud sin edge = slop): esto es un oráculo
//! de VERDAD (diferencial), la calidad que faltaba para el camino vivo.

use crate::certificado::Certificado;

/// Modo de operación. Solo selecciona de dónde salió el modelo y a qué se confirma; la
/// disciplina de refutación y el certificado son iguales en ambos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modo {
    /// Fuente clonada + lab que controlamos.
    Whitebox,
    /// Objetivo vivo en scope + cuentas provisionadas.
    Blackbox,
}

impl Modo {
    pub fn nombre(self) -> &'static str {
        match self {
            Modo::Whitebox => "whitebox",
            Modo::Blackbox => "blackbox",
        }
    }
}

/// Una identidad con la que golpear el objetivo: sus cabeceras de autenticación
/// (cookie de sesión, `X-Auth-Token`/`X-User-Id`, `Authorization: Bearer …`…). Anónimo =
/// sin cabeceras.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Identidad {
    pub etiqueta: String,
    pub cabeceras: Vec<(String, String)>,
}

impl Identidad {
    pub fn anonimo() -> Self {
        Identidad { etiqueta: "anónimo".into(), cabeceras: vec![] }
    }
    pub fn con(etiqueta: &str, cabeceras: Vec<(&str, &str)>) -> Self {
        Identidad {
            etiqueta: etiqueta.into(),
            cabeceras: cabeceras.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }
}

/// El objetivo, común a los dos modos.
#[derive(Debug, Clone)]
pub struct Objetivo {
    pub base: String,
    pub modo: Modo,
}

/// Un caso a probar: el invariante "solo `autorizado` ve `marca` en `ruta`".
/// Serializable → se carga de un archivo JSON (misma forma para lab white y vivo black).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CasoDiferencial {
    /// Qué se prueba (para el reporte).
    pub descripcion: String,
    /// Clase de vulnerabilidad si el invariante se rompe (bac/idor/…).
    pub clase: String,
    /// Ruta relativa del recurso protegido (p. ej. `/api/invoices/1002`).
    pub ruta: String,
    /// Quien SÍ debe ver el recurso (control positivo: el recurso existe y es legible).
    pub autorizado: Identidad,
    /// Quien NO debe ver el recurso. Si LO ve → hallazgo (BAC).
    pub no_autorizado: Identidad,
    /// Ruta de un recurso GARANTIZADO inexistente (control negativo: discrimina real vs
    /// plantilla ciega). Si al pedirla aparece `marca`, el oráculo es CIEGO.
    pub inexistente: Option<String>,
    /// La marca secreta que SOLO el autorizado debería ver en el cuerpo.
    pub marca: String,
}

/// El veredicto del oráculo, con su certificado anti-slop.
#[derive(Debug, Clone)]
pub enum Veredicto {
    /// El no-autorizado ve la marca → BAC confirmado. Certificado válido.
    Fuga(Certificado),
    /// El invariante se sostiene (autorizado ve, no-autorizado no).
    Solido,
    /// Los controles no discriminan (autorizado no ve, o el inexistente sí ve).
    NoConcluyente(String),
}

/// Extrae el host (sin esquema ni puerto) de una URL base, en minúsculas.
fn host_de(base: &str) -> String {
    let sin_esquema = base.split("://").nth(1).unwrap_or(base);
    let hostport = sin_esquema.split('/').next().unwrap_or("");
    // recorta credenciales user@host y el puerto
    let host = hostport.rsplit('@').next().unwrap_or(hostport);
    host.split(':').next().unwrap_or(host).to_lowercase()
}

fn es_loopback(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]")
}

/// BARANDILLA POR MODO (directiva 18/estatuto "sin daño"). Se corre ANTES de `sonda`:
/// - **Whitebox:** el objetivo DEBE ser loopback — el modo lab no toca nada externo.
/// - **Blackbox:** `scope` no puede estar vacío Y el host del objetivo debe estar en él
///   (coincidencia exacta o sufijo de dominio). Tocar un vivo fuera de scope es lo que la
///   barandilla impide. `sonda` además solo hace GET (sin escritura), pero el scope es la
///   puerta dura.
pub fn guardia(objetivo: &Objetivo, scope: &[String]) -> Result<(), String> {
    let host = host_de(&objetivo.base);
    if host.is_empty() {
        return Err(format!("no pude extraer host de la base '{}'", objetivo.base));
    }
    match objetivo.modo {
        Modo::Whitebox => {
            if es_loopback(&host) {
                Ok(())
            } else {
                Err(format!(
                    "whitebox solo toca loopback (lab), no '{host}'. Si es un objetivo vivo, usa blackbox con scope"
                ))
            }
        }
        Modo::Blackbox => {
            if scope.is_empty() {
                return Err("blackbox exige --scope (host(s) autorizados); sin scope no se toca un vivo".into());
            }
            let en_scope = scope.iter().any(|s| {
                let s = s.trim().to_lowercase();
                host == s || host.ends_with(&format!(".{s}"))
            });
            if en_scope {
                Ok(())
            } else {
                Err(format!("host '{host}' fuera de scope {scope:?}: no se toca"))
            }
        }
    }
}

/// Resultado de una petición: ¿el cuerpo contenía la marca?
async fn ve_marca(
    cli: &reqwest::Client,
    base: &str,
    ruta: &str,
    ident: &Identidad,
    marca: &str,
) -> Result<bool, String> {
    let url = format!("{}{}", base.trim_end_matches('/'), ruta);
    let mut req = cli.get(&url);
    for (k, v) in &ident.cabeceras {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let body = resp.text().await.map_err(|e| e.to_string())?;
    Ok(body.contains(marca))
}

/// EL RUNNER. Corre `intentos` veces el diferencial y devuelve el veredicto con
/// certificado. Igual para whitebox (lab) y blackbox (vivo): solo cambia `objetivo.base`
/// y las identidades. `intentos` alimenta el `repro_ratio n/n` del certificado.
pub async fn sonda(
    cli: &reqwest::Client,
    objetivo: &Objetivo,
    caso: &CasoDiferencial,
    intentos: usize,
) -> Veredicto {
    let intentos = intentos.max(1);
    let mut fugas = 0usize; // veces que el no-autorizado vio la marca
    let mut pos_ok = 0usize; // veces que el autorizado la vio (control positivo)

    // DISCIPLINA DE ESTADO (veta x64dbg-mcp, 2026-09-24; ver conocimiento/patrones/
    // disciplina-de-estado.md): el invariante del que depende el veredicto se re-verifica EN
    // CADA RONDA, no solo en t0. El control negativo —"un recurso inexistente NO muestra la
    // marca", o sea el oráculo no es ciego— se comprobaba una sola vez al inicio y se asumía
    // estable el resto de la corrida. Pero un objetivo puede DEGRADARSE a mitad (un WAF o
    // limitador que empieza a servir una plantilla genérica con la marca a TODO, incluido lo
    // inexistente): ese estado se ve idéntico a una fuga real y produce un FALSO POSITIVO. Es
    // el par D23 —el chequeo de un solo tiro es a la vez falso negativo de ceguera y causa del
    // falso positivo de fuga—. Pareado con la sonda cada ronda, se detecta → NoConcluyente.
    for ronda in 0..intentos {
        // Control positivo: el autorizado DEBE ver su propio recurso.
        match ve_marca(cli, &objetivo.base, &caso.ruta, &caso.autorizado, &caso.marca).await {
            Ok(true) => pos_ok += 1,
            Ok(false) => {}
            Err(e) => return Veredicto::NoConcluyente(format!("control positivo falló: {e}")),
        }
        // Control negativo RE-VERIFICADO cada ronda: lo inexistente NO debe mostrar la marca.
        // Temporalmente pareado con la sonda de abajo: mide la ceguera EN EL MOMENTO en que se
        // observa la (posible) fuga, no minutos antes.
        if let Some(inx) = &caso.inexistente {
            match ve_marca(cli, &objetivo.base, inx, &caso.no_autorizado, &caso.marca).await {
                Ok(true) => {
                    return Veredicto::NoConcluyente(format!(
                        "el recurso inexistente muestra la marca (oráculo ciego, detectado en la \
                         ronda {ronda}): responde por plantilla o estado degradado, no por \
                         existencia"
                    ))
                }
                Ok(false) => {}
                Err(e) => return Veredicto::NoConcluyente(format!("control negativo falló: {e}")),
            }
        }
        // La sonda: ¿el no-autorizado ve la marca?
        match ve_marca(cli, &objetivo.base, &caso.ruta, &caso.no_autorizado, &caso.marca).await {
            Ok(true) => fugas += 1,
            Ok(false) => {}
            Err(e) => return Veredicto::NoConcluyente(format!("sonda del no-autorizado falló: {e}")),
        }
    }

    // El control positivo DEBE sostenerse siempre: si el autorizado no ve su propio
    // recurso, no medimos nada (el arnés está mal, no el objetivo).
    if pos_ok != intentos {
        return Veredicto::NoConcluyente(format!(
            "el autorizado no vio la marca de forma consistente ({pos_ok}/{intentos}): \
             el arnés no discrimina"
        ));
    }

    if fugas == 0 {
        return Veredicto::Solido;
    }

    // fugas>0 y reproducible → HALLAZGO con certificado.
    let cert = Certificado {
        execution_confirmed: true,
        repro_ratio: Some(format!("{fugas}/{intentos}")),
        diferencial: true, // el control es el diferencial de identidad, no la repetición
        evidencia_presente: true,
        herramienta: Some(format!("oraculo-diferencial:{}", objetivo.modo.nombre())),
        confianza: Some(if fugas == intentos { "high" } else { "medium" }.into()),
        clase: caso.clase.clone(),
        ancla: format!("nexus v{} · {}", env!("CARGO_PKG_VERSION"), objetivo.modo.nombre()),
    };
    Veredicto::Fuga(cert)
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use axum::{extract::Path, http::HeaderMap, routing::get, Router};
    use tokio::net::TcpListener;

    const SECRETO: &str = "SECRETO-doc-42";

    // App-trampa con DOS rutas del mismo recurso: una respeta el dueño, la otra filtra.
    async fn seguro(Path(id): Path<String>, h: HeaderMap) -> String {
        // Solo el dueño (X-User: owner) ve el secreto; el id 1 existe, otros no.
        let dueno = h.get("x-user").and_then(|v| v.to_str().ok()) == Some("owner");
        if id == "1" && dueno { format!("doc {id}: {SECRETO}") } else { format!("doc {id}: (denegado)") }
    }
    async fn con_fuga(Path(id): Path<String>, _h: HeaderMap) -> String {
        // BAC: devuelve el secreto a cualquiera para el id existente.
        if id == "1" { format!("doc {id}: {SECRETO}") } else { format!("doc {id}: (no existe)") }
    }

    async fn levantar() -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route("/seguro/{id}", get(seguro))
            .route("/fuga/{id}", get(con_fuga));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let h = tokio::spawn(async move { axum::serve(l, app).await.unwrap(); });
        (base, h)
    }

    fn caso(ruta: &str) -> CasoDiferencial {
        CasoDiferencial {
            descripcion: "lectura de doc ajeno".into(),
            clase: "bac".into(),
            ruta: ruta.into(),
            autorizado: Identidad::con("owner", vec![("X-User", "owner")]),
            no_autorizado: Identidad::con("eve", vec![("X-User", "eve")]),
            inexistente: Some(ruta.replace("/1", "/999")),
            marca: SECRETO.into(),
        }
    }

    #[test]
    fn guardia_white_solo_loopback_black_solo_en_scope() {
        // Whitebox: loopback pasa, externo NO.
        let w_ok = Objetivo { base: "http://127.0.0.1:3000".into(), modo: Modo::Whitebox };
        assert!(guardia(&w_ok, &[]).is_ok());
        let w_mal = Objetivo { base: "https://target.example.com".into(), modo: Modo::Whitebox };
        assert!(guardia(&w_mal, &[]).is_err(), "whitebox no toca un host externo");
        // Blackbox: sin scope falla; con el host en scope pasa; fuera de scope falla.
        let b = Objetivo { base: "https://app.target.com/x".into(), modo: Modo::Blackbox };
        assert!(guardia(&b, &[]).is_err(), "blackbox sin scope no toca nada");
        assert!(guardia(&b, &["target.com".into()]).is_ok(), "sufijo de dominio en scope pasa");
        assert!(guardia(&b, &["otro.com".into()]).is_err(), "fuera de scope no se toca");
        assert!(guardia(&b, &["app.target.com".into()]).is_ok(), "host exacto en scope pasa");
    }

    #[tokio::test]
    async fn ruta_segura_da_solido() {
        let (base, _h) = levantar().await;
        let cli = reqwest::Client::new();
        let obj = Objetivo { base, modo: Modo::Whitebox };
        let v = sonda(&cli, &obj, &caso("/seguro/1"), 3).await;
        assert!(matches!(v, Veredicto::Solido), "el recurso que respeta al dueño es sólido, fue {v:?}");
    }

    #[tokio::test]
    async fn ruta_con_fuga_da_hallazgo_con_certificado_valido() {
        let (base, _h) = levantar().await;
        let cli = reqwest::Client::new();
        let obj = Objetivo { base, modo: Modo::Blackbox };
        let v = sonda(&cli, &obj, &caso("/fuga/1"), 3).await;
        match v {
            Veredicto::Fuga(cert) => {
                assert!(cert.es_valido(), "el hallazgo debe traer certificado válido");
                assert_eq!(cert.repro_ratio.as_deref(), Some("3/3"));
                assert!(cert.diferencial);
            }
            otro => panic!("esperaba Fuga, fue {otro:?}"),
        }
    }

    // App que se DEGRADA a mitad: se porta bien las primeras peticiones y luego sirve el
    // secreto a TODO (incluido lo inexistente) — modela un WAF/caché/limitador que empieza a
    // devolver una plantilla genérica con la marca. Es el estado que un control negativo de un
    // solo tiro (en t0) no ve, y que produce una Fuga falsa.
    async fn levantar_degradado(
        umbral: usize,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use axum::extract::State;
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        async fn degrada(
            Path(id): Path<String>,
            State((umbral, n)): State<(usize, Arc<AtomicUsize>)>,
            h: HeaderMap,
        ) -> String {
            let c = n.fetch_add(1, Ordering::SeqCst);
            if c >= umbral {
                // ciego: la plantilla degradada muestra el secreto a cualquiera, exista o no.
                return format!("doc {id}: {SECRETO}");
            }
            let dueno = h.get("x-user").and_then(|v| v.to_str().ok()) == Some("owner");
            if id == "1" && dueno {
                format!("doc {id}: {SECRETO}")
            } else {
                format!("doc {id}: (denegado)")
            }
        }
        let estado = (umbral, Arc::new(AtomicUsize::new(0)));
        let app = Router::new()
            .route("/degrada/{id}", get(degrada))
            .with_state(estado);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let h = tokio::spawn(async move { axum::serve(l, app).await.unwrap(); });
        (base, h)
    }

    #[tokio::test]
    async fn objetivo_ciego_a_mitad_de_corrida_no_es_fuga() {
        // CASO ROJO (D33) de la disciplina de estado: NO ciego en t0, ciego tras 4 peticiones.
        // Con el control negativo RE-VERIFICADO cada ronda → NoConcluyente (se ve la degradación).
        // Con el control de un solo tiro (el mutante = versión anterior) daría Fuga: falso positivo.
        let (base, _h) = levantar_degradado(4).await;
        let cli = reqwest::Client::new();
        let obj = Objetivo { base, modo: Modo::Whitebox };
        let v = sonda(&cli, &obj, &caso("/degrada/1"), 3).await;
        assert!(
            matches!(v, Veredicto::NoConcluyente(_)),
            "un objetivo que se ciega a mitad NO es una fuga; debe salir NoConcluyente, fue {v:?}"
        );
    }

    #[tokio::test]
    async fn oraculo_ciego_da_no_concluyente() {
        // Si el "inexistente" también muestra la marca, el oráculo no discrimina.
        let (base, _h) = levantar().await;
        let cli = reqwest::Client::new();
        let obj = Objetivo { base, modo: Modo::Whitebox };
        // apuntamos el control negativo a la ruta con fuga del id 1 (siempre muestra marca)
        let mut c = caso("/fuga/1");
        c.inexistente = Some("/fuga/1".into());
        let v = sonda(&cli, &obj, &c, 3).await;
        assert!(matches!(v, Veredicto::NoConcluyente(_)), "control negativo que ve la marca → ciego, fue {v:?}");
    }
}
