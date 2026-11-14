// SPDX-License-Identifier: LicenseRef-Xiliux-Propietario
//! **El banco de FALSOS POSITIVOS: casos-trampa + controles, en DOS planos.**
//!
//! Del estudio de `claude-bughunter/eval/run_fp.py` + `hardened-lab-discipline-rules.md`
//! (2026-08-30). Cada oráculo de nexus tiene su pareja rojo/verde (directiva 33), pero nadie
//! medía que el CONJUNTO de gates no genere falsos positivos sobre artefactos que *parecen*
//! vulnerables y son seguros. Este módulo lo cierra en dos planos:
//!
//! 1. **Gates puras** ([`evaluar_gates`]): casos FP-shaped fijos pasados por la gate que le toca
//!    a cada uno ([`crate::refutacion`]). Mide el JUICIO, sin red.
//! 2. **Sistema contra HTTP real** ([`evaluar_sistema`]): levanta la app-trampa
//!    ([`crate::fp_app`], un `axum` en 127.0.0.1) con parejas SAFE/VULN por clase, la golpea con
//!    `reqwest`, aplica la detección de nexus, y cuenta FP/TP. **Cruza la frontera del programa**
//!    (directiva 28): el plano 1 mide el códec del juicio; este mide el producto.
//!
//! La condición de victoria es la de `run_fp.py`: **FPR baja sin bajar TPR**. Con las gates
//! puras se exige el óptimo (FPR = 0, TPR = 1) porque los casos son fijos. Contra la app-trampa
//! se exige FPR = 0 (ninguna trampa reportada) y TPR alto (los controles se reportan); una clase
//! que no se pueda cablear a lo real (p. ej. XSS sin navegador) se EXCLUYE del cómputo diciéndolo
//! (directiva 30: un negativo silencioso no cuenta como fallo).

use crate::config::Config;
use crate::refutacion::{body_diff, marcador_colisiona, muestreo_temporal, oraculo_discrimina, Body, Timing};
use std::time::{Duration, Instant};

/// Lo que un caso ES de verdad.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdad {
    /// Parece vulnerable pero es seguro (una trampa). No debe reportarse.
    Safe,
    /// Vulnerable de verdad (un control). Debe reportarse.
    Vulnerable,
}

/// Un caso del banco: su verdad y si la detección lo REPORTA.
struct Caso {
    /// Para nombrar el caso que falle en el banco; solo lo lee el test.
    #[cfg_attr(not(test), allow(dead_code))]
    nombre: &'static str,
    verdad: Verdad,
    reportado: bool,
}

/// Corre todos los casos-trampa y controles PUROS contra las gates de [`crate::refutacion`].
fn casos() -> Vec<Caso> {
    let mut v = Vec::new();

    // ── IDOR: body-diff ── un 200 con el MISMO cuerpo que el baseline no probó acceso ajeno.
    // Trampa (safe): el atacante pide el recurso de otro y recibe el mismo cuerpo genérico.
    v.push(Caso {
        nombre: "idor-200-sin-leak",
        verdad: Verdad::Safe,
        reportado: !matches!(body_diff(b"{\"error\":\"forbidden\"}", b"{\"error\":\"forbidden\"}"), Body::Identico),
    });
    // Control (vulnerable): el cuerpo trae datos de OTRO usuario → difiere.
    v.push(Caso {
        nombre: "idor-real",
        verdad: Verdad::Vulnerable,
        reportado: matches!(body_diff(b"{\"error\":\"forbidden\"}", b"{\"user\":\"victima\",\"ssn\":\"123\"}"), Body::Difiere { .. }),
    });

    // ── XSS: colisión de marcador ── el "reflejo" era una palabra que ya estaba en la página.
    // Trampa (safe): el marcador flojo ya aparece en el baseline → no es reflexión.
    let baseline_con_palabra = b"bienvenido, tu busqueda de admin no dio resultados";
    v.push(Caso {
        nombre: "xss-word-collision",
        verdad: Verdad::Safe,
        // Se "reporta" solo si NO colisiona (reflexión genuina). Con un marcador que ya está
        // en el baseline, colisiona → no se reporta.
        reportado: !marcador_colisiona(baseline_con_palabra, "admin"),
    });
    // Control (vulnerable): un marcador disciplinado que NO estaba y aparece reflejado.
    v.push(Caso {
        nombre: "xss-reflexion-real",
        verdad: Verdad::Vulnerable,
        reportado: !marcador_colisiona(baseline_con_palabra, "k7m2q9x4z1"),
    });

    // ── SSRF/IDOR: política vs estado ── un 403 uniforme no prueba existencia.
    // Trampa (safe): el recurso real y uno basura dan la MISMA respuesta (política) → ciego.
    v.push(Caso {
        nombre: "file-oracle-blocklist",
        verdad: Verdad::Safe,
        reportado: oraculo_discrimina(b"403 blocked by policy", b"403 blocked by policy"),
    });
    // Control (vulnerable): el real existe (200) y el basura no (404) → discrimina estado.
    v.push(Caso {
        nombre: "enum-por-estado-real",
        verdad: Verdad::Vulnerable,
        reportado: oraculo_discrimina(b"200 user profile", b"404 not found"),
    });

    // ── Timing enum: muestreo estadístico ── un outlier no es señal.
    // Trampa (safe): dos grupos del mismo proceso ruidoso, sin diferencia creíble.
    let ruido_a = vec![0.10, 0.12, 0.09, 0.30, 0.11, 0.10, 0.13, 0.08, 0.12, 0.11, 0.10, 0.09];
    let ruido_b = vec![0.11, 0.10, 0.12, 0.09, 0.11, 0.28, 0.10, 0.12, 0.09, 0.11, 0.10, 0.13];
    v.push(Caso {
        nombre: "timing-enum-ruidoso",
        verdad: Verdad::Safe,
        reportado: matches!(muestreo_temporal(&ruido_a, &ruido_b), Timing::Senal { .. }),
    });
    // Control (vulnerable): diferencia real y estable (t de Welch alto).
    let base: Vec<f64> = (0..12).map(|i| 0.10 + (i as f64) * 0.001).collect();
    let lento: Vec<f64> = (0..12).map(|i| 0.30 + (i as f64) * 0.001).collect();
    v.push(Caso {
        nombre: "timing-enum-real",
        verdad: Verdad::Vulnerable,
        reportado: matches!(muestreo_temporal(&base, &lento), Timing::Senal { .. }),
    });

    v
}

/// Las métricas del banco: cuántos safe/vuln hay y cuántos falsos/verdaderos positivos dio la
/// detección. Compartida por los dos planos (gates puras y sistema).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Metricas {
    pub safe: usize,
    pub vuln: usize,
    /// Falsos positivos: casos SAFE que la detección reportó.
    pub fp: usize,
    /// Verdaderos positivos: casos VULNERABLE que la detección reportó.
    pub tp: usize,
}

impl Metricas {
    /// Tasa de falsos positivos (fp / safe).
    pub fn fpr(&self) -> f64 {
        if self.safe == 0 { 0.0 } else { self.fp as f64 / self.safe as f64 }
    }
    /// Tasa de verdaderos positivos (tp / vuln).
    pub fn tpr(&self) -> f64 {
        if self.vuln == 0 { 0.0 } else { self.tp as f64 / self.vuln as f64 }
    }
    /// Suma otra tanda de casos (para agregar por clase al total).
    fn acumular(&mut self, otra: &Metricas) {
        self.safe += otra.safe;
        self.vuln += otra.vuln;
        self.fp += otra.fp;
        self.tp += otra.tp;
    }
}

/// Pliega una lista de casos a sus métricas (safe/vuln/fp/tp).
fn metricas_de(casos: &[Caso]) -> Metricas {
    let mut m = Metricas::default();
    for c in casos {
        match c.verdad {
            Verdad::Safe => {
                m.safe += 1;
                if c.reportado {
                    m.fp += 1;
                }
            }
            Verdad::Vulnerable => {
                m.vuln += 1;
                if c.reportado {
                    m.tp += 1;
                }
            }
        }
    }
    m
}

/// Evalúa las gates PURAS contra el banco fijo y devuelve las métricas.
pub fn evaluar_gates() -> Metricas {
    metricas_de(&casos())
}

// ─────────────────────────────────────────────────────────────────────────────
//  PLANO 2 — el SISTEMA contra la app-trampa HTTP real (directiva 28)
// ─────────────────────────────────────────────────────────────────────────────

/// El resultado de UNA clase medida contra la app-trampa.
pub struct ResultadoClase {
    /// Nombre de la clase (ssrf, xss, idor, file, login, timing).
    pub clase: &'static str,
    /// Métricas de esta clase.
    pub metricas: Metricas,
    /// `false` si la clase no se pudo medir (p. ej. XSS sin navegador): NO cuenta como fallo.
    pub cableado: bool,
    /// Por qué no se cableó, o un detalle.
    pub nota: Option<String>,
}

/// Trae el cuerpo de una GET (cadena vacía si falla la red — el gate lo verá como "sin señal").
async fn cuerpo(cli: &reqwest::Client, url: &str) -> String {
    match cli.get(url).send().await {
        Ok(r) => r.text().await.unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/// Trae `"<status> <cuerpo>"` de una GET: para el oráculo de política-vs-estado, donde el status
/// (403 uniforme vs 200/404) es parte de la señal.
async fn estado_cuerpo(cli: &reqwest::Client, url: &str) -> String {
    match cli.get(url).send().await {
        Ok(r) => {
            let s = r.status().as_u16();
            let b = r.text().await.unwrap_or_default();
            format!("{s} {b}")
        }
        Err(e) => format!("ERR {e}"),
    }
}

/// Trae el cuerpo de un endpoint SSRF con el parámetro `url` (reqwest lo percent-encodea).
async fn cuerpo_ssrf(cli: &reqwest::Client, endpoint: &str, url_param: &str) -> String {
    match cli.get(endpoint).query(&[("url", url_param)]).send().await {
        Ok(r) => r.text().await.unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/// Mide la latencia (segundos) de una GET completa (headers + cuerpo). El handler de la
/// app-trampa duerme ANTES de responder, así que esto captura su canal temporal.
async fn medir(cli: &reqwest::Client, url: &str) -> f64 {
    let t = Instant::now();
    if let Ok(r) = cli.get(url).send().await {
        let _ = r.text().await;
    }
    t.elapsed().as_secs_f64()
}

/// IDOR (gate `body_diff`): SAFE = genfields da el mismo cuerpo para dos ids (Identico → no se
/// reporta); VULN = real da cuerpos distintos (Difiere → se reporta).
async fn eval_idor(cli: &reqwest::Client, base: &str) -> Vec<Caso> {
    let s1 = cuerpo(cli, &format!("{base}/idor-genfields?id=1")).await;
    let s2 = cuerpo(cli, &format!("{base}/idor-genfields?id=2")).await;
    let safe_report = !matches!(body_diff(s1.as_bytes(), s2.as_bytes()), Body::Identico);
    let v1 = cuerpo(cli, &format!("{base}/idor-real?id=1")).await;
    let v2 = cuerpo(cli, &format!("{base}/idor-real?id=2")).await;
    let vuln_report = matches!(body_diff(v1.as_bytes(), v2.as_bytes()), Body::Difiere { .. });
    vec![
        Caso { nombre: "idor-genfields", verdad: Verdad::Safe, reportado: safe_report },
        Caso { nombre: "idor-real", verdad: Verdad::Vulnerable, reportado: vuln_report },
    ]
}

/// File-oracle (gate `oraculo_discrimina`): SAFE = 403 uniforme para existente/inexistente (no
/// discrimina); VULN = 200 vs 404 (discrimina estado).
async fn eval_file(cli: &reqwest::Client, base: &str) -> Vec<Caso> {
    let sa = estado_cuerpo(cli, &format!("{base}/file?name=reporte.pdf")).await;
    let sb = estado_cuerpo(cli, &format!("{base}/file?name=zzz_no_existe_nxfp")).await;
    let safe_report = oraculo_discrimina(sa.as_bytes(), sb.as_bytes());
    let va = estado_cuerpo(cli, &format!("{base}/file-real?name=reporte.pdf")).await;
    let vb = estado_cuerpo(cli, &format!("{base}/file-real?name=zzz_no_existe_nxfp")).await;
    let vuln_report = oraculo_discrimina(va.as_bytes(), vb.as_bytes());
    vec![
        Caso { nombre: "file-safe", verdad: Verdad::Safe, reportado: safe_report },
        Caso { nombre: "file-real", verdad: Verdad::Vulnerable, reportado: vuln_report },
    ]
}

/// User-enum (gate `oraculo_discrimina`): SAFE = mismo cuerpo para usuario válido/ inválido;
/// VULN = cuerpos distintos ("contraseña incorrecta" vs "usuario no existe").
async fn eval_login(cli: &reqwest::Client, base: &str) -> Vec<Caso> {
    let sa = estado_cuerpo(cli, &format!("{base}/login?user=juan")).await;
    let sb = estado_cuerpo(cli, &format!("{base}/login?user=noexiste_nxfp")).await;
    let safe_report = oraculo_discrimina(sa.as_bytes(), sb.as_bytes());
    let va = estado_cuerpo(cli, &format!("{base}/login-real?user=juan")).await;
    let vb = estado_cuerpo(cli, &format!("{base}/login-real?user=noexiste_nxfp")).await;
    let vuln_report = oraculo_discrimina(va.as_bytes(), vb.as_bytes());
    vec![
        Caso { nombre: "login-safe", verdad: Verdad::Safe, reportado: safe_report },
        Caso { nombre: "login-real", verdad: Verdad::Vulnerable, reportado: vuln_report },
    ]
}

/// SSRF por contenido (disciplina de marcador, `marcador_colisiona`): reportado sii el secreto
/// interno aparece en la respuesta del ataque Y no colisiona (no estaba ya) en el baseline. SAFE
/// = echo refleja la URL pero nunca fetchea → sin secreto. VULN = real fetchea → filtra secreto.
async fn eval_ssrf(cli: &reqwest::Client, base: &str) -> Vec<Caso> {
    let secreto = crate::fp_app::SECRETO_INTERNO;
    let url_secreto = format!("{base}/_internal/secret");
    let url_publico = format!("{base}/_internal/public");

    let echo = format!("{base}/ssrf-echo");
    let a_echo = cuerpo_ssrf(cli, &echo, &url_secreto).await;
    let b_echo = cuerpo_ssrf(cli, &echo, &url_publico).await;
    let safe_report = a_echo.contains(secreto) && !marcador_colisiona(b_echo.as_bytes(), secreto);

    let real = format!("{base}/ssrf-real");
    let a_real = cuerpo_ssrf(cli, &real, &url_secreto).await;
    let b_real = cuerpo_ssrf(cli, &real, &url_publico).await;
    let vuln_report = a_real.contains(secreto) && !marcador_colisiona(b_real.as_bytes(), secreto);

    vec![
        Caso { nombre: "ssrf-echo", verdad: Verdad::Safe, reportado: safe_report },
        Caso { nombre: "ssrf-real", verdad: Verdad::Vulnerable, reportado: vuln_report },
    ]
}

/// Timing-enum (gate `muestreo_temporal`, Welch t>3, n>=10 intercalado): SAFE = latencia
/// constante para válido/ inválido → SinSenal; VULN = válido más lento y estable → Senal.
async fn eval_timing(cli: &reqwest::Client, base: &str, endpoint: &str, es_real: bool) -> Caso {
    const N: usize = 12;
    let mut validos = Vec::with_capacity(N);
    let mut invalidos = Vec::with_capacity(N);
    for i in 0..N {
        // Intercalado (no back-to-back por grupo): reduce el sesgo de deriva del reloj/carga.
        validos.push(medir(cli, &format!("{base}{endpoint}?user=juan")).await);
        invalidos.push(medir(cli, &format!("{base}{endpoint}?user=noexiste_nxfp{i}")).await);
    }
    // control = inválidos (rápidos), prueba = válidos (sospechosos de tardar más).
    let reportado = matches!(muestreo_temporal(&invalidos, &validos), Timing::Senal { .. });
    if es_real {
        Caso { nombre: "timing-real", verdad: Verdad::Vulnerable, reportado }
    } else {
        Caso { nombre: "timing-safe", verdad: Verdad::Safe, reportado }
    }
}

/// XSS (oráculo por EJECUCIÓN, [`crate::browser::confirm_xss_multipunto`]): SAFE = reflejo
/// escapado o inerte → no ejecuta → no confirmado; VULN = reflejo crudo en sink → ejecuta el
/// marcador computado → confirmado. Necesita navegador.
async fn eval_xss(cfg: &Config, base: &str, tries: usize) -> Vec<Caso> {
    let tries = tries.max(1);
    let min_ok = tries; // reproducibilidad total en el lab
    let confirmar = |ruta: &str, nonce: u64| {
        let url = format!("{base}{ruta}?q=INIT");
        async move { crate::browser::confirm_xss_multipunto(cfg, &url, tries, min_ok, nonce).await.confirmed }
    };
    let safe_encoded = confirmar("/xss-encoded", 710000).await;
    let safe_collision = confirmar("/xss-collision", 720000).await;
    let vuln_real = confirmar("/xss-real", 730000).await;
    vec![
        Caso { nombre: "xss-encoded", verdad: Verdad::Safe, reportado: safe_encoded },
        Caso { nombre: "xss-collision", verdad: Verdad::Safe, reportado: safe_collision },
        Caso { nombre: "xss-real", verdad: Verdad::Vulnerable, reportado: vuln_real },
    ]
}

/// ¿Hay un Chromium invocable en `cfg.chromium_path`? Se comprueba corriendo `--version`; sin él
/// la clase XSS se excluye del cómputo (directiva 30), no se cuenta como negativo.
pub async fn hay_navegador(cfg: &Config) -> bool {
    matches!(
        crate::tools::run(&cfg.chromium_path, &["--version".to_string()], Duration::from_secs(10)).await,
        Ok(o) if o.code == Some(0)
    )
}

/// **Evalúa el SISTEMA de detección contra la app-trampa** en `base` (`http://127.0.0.1:PORT`).
/// Devuelve una fila por clase. La clase XSS se cablea solo si hay navegador.
pub async fn evaluar_sistema(base: &str, cfg: &Config, xss_tries: usize) -> Vec<ResultadoClase> {
    let cli = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("cliente reqwest del fp-eval");

    let mut out = Vec::new();
    out.push(ResultadoClase { clase: "ssrf", metricas: metricas_de(&eval_ssrf(&cli, base).await), cableado: true, nota: None });
    out.push(ResultadoClase { clase: "idor", metricas: metricas_de(&eval_idor(&cli, base).await), cableado: true, nota: None });
    out.push(ResultadoClase { clase: "file", metricas: metricas_de(&eval_file(&cli, base).await), cableado: true, nota: None });
    out.push(ResultadoClase { clase: "login", metricas: metricas_de(&eval_login(&cli, base).await), cableado: true, nota: None });

    // Timing: los dos endpoints (safe + real) forman una clase.
    let t_safe = eval_timing(&cli, base, "/timing", false).await;
    let t_real = eval_timing(&cli, base, "/timing-real", true).await;
    out.push(ResultadoClase { clase: "timing", metricas: metricas_de(&[t_safe, t_real]), cableado: true, nota: None });

    // XSS: solo si hay navegador (si no, se excluye del cómputo, D30).
    if hay_navegador(cfg).await {
        let casos = eval_xss(cfg, base, xss_tries).await;
        out.push(ResultadoClase { clase: "xss", metricas: metricas_de(&casos), cableado: true, nota: None });
    } else {
        out.push(ResultadoClase {
            clase: "xss",
            metricas: Metricas::default(),
            cableado: false,
            nota: Some("sin navegador Chromium: XSS no medida (no cuenta como fallo, D30)".to_string()),
        });
    }
    out
}

/// Agrega las clases CABLEADAS en una sola métrica (el total del que salen FPR/TPR del sistema).
pub fn total_cableado(res: &[ResultadoClase]) -> Metricas {
    let mut m = Metricas::default();
    for r in res {
        if r.cableado {
            m.acumular(&r.metricas);
        }
    }
    m
}

/// Imprime la tabla por clase + FPR/TPR total (solo clases cableadas).
pub fn imprimir(res: &[ResultadoClase]) {
    println!("{:<8} {:>4} {:>4} {:>4} {:>4}  {:>6} {:>6}", "clase", "safe", "vuln", "fp", "tp", "FPR", "TPR");
    for r in res {
        if r.cableado {
            println!(
                "{:<8} {:>4} {:>4} {:>4} {:>4}  {:>6.2} {:>6.2}",
                r.clase, r.metricas.safe, r.metricas.vuln, r.metricas.fp, r.metricas.tp,
                r.metricas.fpr(), r.metricas.tpr()
            );
        } else {
            println!("{:<8}  — no medida: {}", r.clase, r.nota.as_deref().unwrap_or(""));
        }
    }
    let t = total_cableado(res);
    println!("{:-<44}", "");
    println!(
        "TOTAL (cableado): safe={} vuln={} fp={} tp={} → FPR={:.3} TPR={:.3}",
        t.safe, t.vuln, t.fp, t.tp, t.fpr(), t.tpr()
    );
    if t.fp == 0 {
        println!("FPR = 0: ninguna trampa SAFE fue reportada.");
    } else {
        println!("¡ATENCIÓN! {} falso(s) positivo(s): una gate se degradó.", t.fp);
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// **El banco de GATES PURAS: discriminan trampas de controles con FPR = 0 y TPR = 1.** Es la
    /// condición de victoria de un FP-harness en su forma óptima (casos fijos). Nombra el caso
    /// que falle.
    #[test]
    fn las_gates_no_generan_falsos_positivos_ni_pierden_los_reales() {
        let m = evaluar_gates();
        assert!(m.safe >= 4 && m.vuln >= 4, "el banco necesita trampas y controles: {m:?}");
        for c in casos() {
            match c.verdad {
                Verdad::Safe => assert!(!c.reportado, "falso positivo en «{}»", c.nombre),
                Verdad::Vulnerable => assert!(c.reportado, "control «{}» no se reportó", c.nombre),
            }
        }
        assert_eq!(m.fpr(), 0.0, "FPR debe ser 0: {m:?}");
        assert_eq!(m.tpr(), 1.0, "TPR debe ser 1: {m:?}");
    }

    /// `metricas_de` cuenta bien safe/vuln/fp/tp, y su pareja: un caso SAFE reportado sube fp, un
    /// VULN no reportado NO sube tp.
    #[test]
    fn metricas_de_cuenta_fp_y_tp() {
        let casos = vec![
            Caso { nombre: "s-ok", verdad: Verdad::Safe, reportado: false },
            Caso { nombre: "s-fp", verdad: Verdad::Safe, reportado: true },
            Caso { nombre: "v-tp", verdad: Verdad::Vulnerable, reportado: true },
            Caso { nombre: "v-miss", verdad: Verdad::Vulnerable, reportado: false },
        ];
        let m = metricas_de(&casos);
        assert_eq!((m.safe, m.vuln, m.fp, m.tp), (2, 2, 1, 1));
        assert_eq!(m.fpr(), 0.5);
        assert_eq!(m.tpr(), 0.5);
    }

    /// `total_cableado` suma solo las clases medidas: una clase `cableado=false` (XSS sin
    /// navegador) NO contamina el total ni con su safe ni con su vuln.
    #[test]
    fn total_cableado_ignora_las_no_medidas() {
        let res = vec![
            ResultadoClase { clase: "idor", metricas: Metricas { safe: 1, vuln: 1, fp: 0, tp: 1 }, cableado: true, nota: None },
            ResultadoClase { clase: "xss", metricas: Metricas { safe: 2, vuln: 1, fp: 2, tp: 0 }, cableado: false, nota: Some("sin navegador".into()) },
        ];
        let t = total_cableado(&res);
        assert_eq!((t.safe, t.vuln, t.fp, t.tp), (1, 1, 0, 1));
        assert_eq!(t.fpr(), 0.0);
        assert_eq!(t.tpr(), 1.0);
    }
}
