// SPDX-License-Identifier: LicenseRef-Propietario
//! BANCO A/B/C — calibración del bucle adaptativo de AUTH (`autenticacion::ciclo_auth`)
//! ANTES de gastar un solo request en un objetivo real (directiva 30: un 0 de un
//! instrumento sin calibrar es indistinguible de un objetivo limpio; se calibra contra
//! terreno de VERDAD-conocida primero).
//!
//! Tres servidores JWT sintéticos en localhost (dir. 28: transporte HTTP real, reqwest →
//! axum, no un mock que dice sí a todo), cada uno una postura conocida — es un DISCRIMINADOR
//! (dir. 33: el que TIENE que ver y el que TIENE que no ver):
//!
//!   A  vulnerable-defendido : valida JWTs, RECHAZA el `alg:none` canónico (blocklist naíf
//!                             case-sensitive), pero ACEPTA la variante de caja `None`.
//!                             → arnm transcribe, la variante ATERRIZA, `secuencias` SIEMBRA.
//!   B  defendido-limpio     : valida firma siempre; ninguna variante pasa.
//!                             → arnm transcribe y NO confirma nada; `secuencias` VACÍA (anti-FP).
//!   C  sin-sink (abierto)   : no gatea sobre el token; el control basura también pasa.
//!                             → el selector PODA: 0 variantes gastadas, 0 FP.
//!
//! RIESGO CERO: todo el tráfico se queda en 127.0.0.1; forjamos nuestros propios tokens.
//! Correr y VERLO:  cargo test --test auth_arnm_sim -- --nocapture

use std::sync::Arc;

use axum::http::{HeaderMap, StatusCode};
use axum::{routing::get, Router};
use nexus::autenticacion::{self as auth, MoldeAuth};
use nexus::protection::{Guard, ProtectionConfig};
use nexus::{db, secuencias};

// ── Helpers de servidor ──────────────────────────────────────────────────────

/// Extrae el token del header Authorization (con o sin prefijo `Bearer `).
fn header_tok(h: &HeaderMap) -> Option<String> {
    let v = h.get("authorization")?.to_str().ok()?;
    Some(v.strip_prefix("Bearer ").unwrap_or(v).to_string())
}

fn unauth() -> (StatusCode, String) {
    (StatusCode::UNAUTHORIZED, "{\"error\":\"invalid_token\"}".into())
}

/// SERVIDOR A — vulnerable-defendido. El sink existe (valida JWTs) y RECHAZA el `alg:none`
/// canónico con una blocklist NAÍF (compara `alg == "none"`, case-sensitive). El bug: no
/// cubre las variantes de caja, así que `None`/`NONE`/`nOnE` pasan como token sin firma.
async fn srv_a(headers: HeaderMap) -> (StatusCode, String) {
    let Some(authz) = header_tok(&headers) else { return unauth() };
    let Some(jwt) = auth::parse_jwt(&authz) else { return unauth() };
    if jwt.alg == "none" {
        // CANÓNICO bloqueado — aquí es donde un escáner que dispara la forma cruda se estrella.
        return (StatusCode::FORBIDDEN, "{\"error\":\"alg none blocked\"}".into());
    }
    if jwt.alg.eq_ignore_ascii_case("none") {
        // BUG: la blocklist case-sensitive no cubrió la variante → token sin firma aceptado.
        let rol = jwt.payload.get("role").and_then(|v| v.as_str()).unwrap_or("user");
        return (StatusCode::OK, format!("{{\"role\":\"{rol}\",\"access\":\"granted\"}}"));
    }
    // Cualquier otro alg exige firma válida; nuestras forjas no la tienen → 401.
    unauth()
}

/// SERVIDOR B — defendido-limpio. Valida firma SIEMPRE; `alg:none` (cualquier caja) es
/// "sin firma" → rechazado, y nada de lo forjado tiene firma válida → 401 universal.
async fn srv_b(headers: HeaderMap) -> (StatusCode, String) {
    let Some(authz) = header_tok(&headers) else { return unauth() };
    let Some(_jwt) = auth::parse_jwt(&authz) else { return unauth() };
    unauth()
}

/// SERVIDOR C — sin-sink (recurso público). No gatea sobre el token: el control basura
/// también pasa. Es la trampa del FP del recurso público (el oráculo IDOR endurecido).
async fn srv_c(_headers: HeaderMap) -> (StatusCode, String) {
    (StatusCode::OK, "{\"data\":\"publico\"}".into())
}

async fn arranca(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("127.0.0.1:{}", addr.port())
}

/// La sonda de auth sobre HTTP real (dir. 28). El cazador real usa `fetch_evasion`; aquí,
/// reqwest a localhost. Misma costura (`SondaAuth`), así el rojo no falla por el arnés.
struct Harness {
    cliente: reqwest::Client,
    url: String,
}

impl auth::SondaAuth for Harness {
    async fn probar(&self, token: &str) -> (u16, String) {
        let r = self
            .cliente
            .get(&self.url)
            .header("Authorization", token)
            .send()
            .await
            .unwrap();
        let s = r.status().as_u16();
        (s, r.text().await.unwrap_or_default())
    }

    async fn probar_sin_auth(&self) -> (u16, String) {
        let r = self.cliente.get(&self.url).send().await.unwrap();
        let s = r.status().as_u16();
        (s, r.text().await.unwrap_or_default())
    }
}

/// Un JWT de muestra normal (HS256, role=user) — lo que se observaría en una identidad real.
fn muestra() -> auth::Jwt {
    let payload = serde_json::json!({"sub": "u", "role": "user"});
    let token = auth::forjar_hs256(&payload, b"secreto-de-muestra");
    auth::parse_jwt(&token).unwrap()
}

const MOLDES: [MoldeAuth; 2] = [MoldeAuth::AlgNone, MoldeAuth::AlgConfusion];

// ── EL BANCO A/B/C ───────────────────────────────────────────────────────────

#[tokio::test]
async fn banco_abc_discrimina() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("abc.db"), 4).await.unwrap();
    let jwt = muestra();
    let cli = reqwest::Client::new();

    let a = arranca(Router::new().route("/x", get(srv_a))).await;
    let b = arranca(Router::new().route("/x", get(srv_b))).await;
    let c = arranca(Router::new().route("/x", get(srv_c))).await;

    let h = |host: &str| Harness { cliente: cli.clone(), url: format!("http://{host}/x") };

    eprintln!("\n┌─ BANCO A/B/C — calibración de arnm-auth sobre terreno conocido ─────────");
    eprintln!("│ servidor          señal          variantes  bypass        secuencias");
    eprintln!("├────────────────────────────────────────────────────────────────────────");

    // ── A: vulnerable-defendido ──
    let ra = auth::ciclo_auth(&pool, "sim", "host-a", &jwt, &[], &MOLDES, &h(&a))
        .await
        .unwrap();
    let seed_a = secuencias::contar_vigentes(&pool, "host-a").await.unwrap();
    eprintln!(
        "│ A vuln-defendido  {:<13?}  {:>4}       {:<12}  {}",
        ra.senal,
        ra.variantes_probadas,
        ra.bypass.as_ref().map(|b| b.molde.as_str()).unwrap_or("—"),
        seed_a
    );
    assert!(ra.bypass.is_some(), "A: la variante DEBE aterrizar");
    let bx = ra.bypass.as_ref().unwrap();
    assert_eq!(bx.molde, "alg-none", "A: el molde que aterriza es alg-none");
    assert_eq!(bx.status, 200, "A: acceso concedido");
    // La canónica ("none") se probó y fue RECHAZADA antes de que la variante de caja pasara:
    // >=2 prueba que hizo falta transcribir, no que la forma cruda ya valía.
    assert!(ra.variantes_probadas >= 2, "A: la canónica no bastó, la variante sí");
    assert_eq!(seed_a, 1, "A: `secuencias` SEMBRÓ la variante ganadora");

    // ── A de nuevo: la MEMORIA acierta directo (enviar preciso/estrecho) ──
    let ra2 = auth::ciclo_auth(&pool, "sim", "host-a", &jwt, &[], &MOLDES, &h(&a))
        .await
        .unwrap();
    eprintln!(
        "│ A (2ª vuelta)     {:<13?}  {:>4}       {:<12}  memoria={}",
        ra2.senal, ra2.variantes_probadas, "memoria", ra2.desde_memoria
    );
    assert!(ra2.desde_memoria, "A-2: debe acertar DESDE memoria");
    assert_eq!(ra2.variantes_probadas, 1, "A-2: una sola prueba, no re-barre");

    // ── B: defendido-limpio (el anti-FP: ataca y NO confirma nada) ──
    let rb = auth::ciclo_auth(&pool, "sim", "host-b", &jwt, &[], &MOLDES, &h(&b))
        .await
        .unwrap();
    let seed_b = secuencias::contar_vigentes(&pool, "host-b").await.unwrap();
    eprintln!(
        "│ B defend-limpio   {:<13?}  {:>4}       {:<12}  {}",
        rb.senal,
        rb.variantes_probadas,
        rb.bypass.as_ref().map(|b| b.molde.as_str()).unwrap_or("—"),
        seed_b
    );
    assert_eq!(rb.senal, auth::SenalAuth::SinkDefendido, "B: hay sink, se defiende");
    assert!(rb.bypass.is_none(), "B: NADA debe confirmarse (anti-FP)");
    assert!(rb.variantes_probadas > 2, "B: transcribió y agotó variantes, sin FP");
    assert_eq!(seed_b, 0, "B: `secuencias` VACÍA — no se contamina con no-confirmados");

    // ── C: sin-sink (el selector PODA) ──
    let rc = auth::ciclo_auth(&pool, "sim", "host-c", &jwt, &[], &MOLDES, &h(&c))
        .await
        .unwrap();
    let seed_c = secuencias::contar_vigentes(&pool, "host-c").await.unwrap();
    eprintln!(
        "│ C sin-sink        {:<13?}  {:>4}       {:<12}  {}",
        rc.senal,
        rc.variantes_probadas,
        rc.bypass.as_ref().map(|b| b.molde.as_str()).unwrap_or("—"),
        seed_c
    );
    assert_eq!(rc.senal, auth::SenalAuth::SinSink, "C: sin auth que respetar");
    assert!(rc.bypass.is_none(), "C: recurso público NO es bypass");
    assert_eq!(rc.variantes_probadas, 0, "C: el selector PODA — 0 variantes gastadas");
    assert_eq!(seed_c, 0, "C: nada que sembrar");

    eprintln!("└────────────────────────────────────────────────────────────────────────");

    // ── El MUTANTE del oráculo (dir. 33): A y C dan 200 al token forjado. La ÚNICA
    //    diferencia es el control (A→401, C→200). El oráculo debe discriminar POR el
    //    control, no por el 200 del forjado: si no, confirmaría el recurso público de C.
    assert!(
        auth::es_bypass_confirmado(401, 200, "{\"access\":\"granted\"}"),
        "control rechazado + forjado aceptado = bypass"
    );
    assert!(
        !auth::es_bypass_confirmado(200, 200, "{\"access\":\"granted\"}"),
        "control ACEPTADO (recurso público) NO es bypass — el mutante del oráculo"
    );
    eprintln!(
        "  oráculo discrimina: es_bypass(401→200)=true, es_bypass(200→200)=false ✓\n"
    );
}

// ── ESCALA + CONCURRENCIA (dir. 8: 100+ operaciones) ─────────────────────────

#[tokio::test]
async fn ciento_veinte_hosts_concurrentes() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(db::open(&dir.path().join("escala.db"), 8).await.unwrap());
    let jwt = Arc::new(muestra());

    // Un servidor con las tres posturas en rutas distintas.
    let app = Router::new()
        .route("/a", get(srv_a))
        .route("/b", get(srv_b))
        .route("/c", get(srv_c));
    let host = arranca(app).await;
    let cli = reqwest::Client::new();

    // 40 A + 40 B + 40 C = 120 hosts lógicos (claves de memoria distintas), concurrentes.
    let mut tareas = Vec::new();
    for i in 0..120u32 {
        let (ruta, clase) = match i % 3 {
            0 => ("a", 'A'),
            1 => ("b", 'B'),
            _ => ("c", 'C'),
        };
        let pool = Arc::clone(&pool);
        let jwt = Arc::clone(&jwt);
        let sonda = Harness { cliente: cli.clone(), url: format!("http://{host}/{ruta}") };
        let hkey = format!("h-{clase}-{i}");
        tareas.push(tokio::spawn(async move {
            let r = auth::ciclo_auth(&pool, "sim", &hkey, &jwt, &[], &MOLDES, &sonda)
                .await
                .unwrap();
            (clase, r.senal, r.bypass.is_some(), r.variantes_probadas)
        }));
    }

    let mut confirmados_a = 0;
    let mut fp_bc = 0;
    let mut poda_c = 0;
    for t in tareas {
        let (clase, senal, bypass, probadas) = t.await.unwrap();
        match clase {
            'A' if bypass => confirmados_a += 1,
            'B' | 'C' if bypass => fp_bc += 1, // NINGUNO debe entrar aquí
            'C' if senal == auth::SenalAuth::SinSink && probadas == 0 => poda_c += 1,
            _ => {}
        }
    }

    assert_eq!(confirmados_a, 40, "los 40 vulnerables DEBEN confirmar");
    assert_eq!(fp_bc, 0, "CERO falsos positivos en defendidos-limpios y abiertos");
    assert_eq!(poda_c, 40, "los 40 sin-sink DEBEN podarse (0 variantes)");

    // La memoria acumuló exactamente 40 secuencias vigentes (una por host vulnerable).
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secuencias WHERE caducada = 0")
        .fetch_one(&*pool)
        .await
        .unwrap();
    assert_eq!(total, 40, "40 secuencias propias sembradas, ni una de B/C");
    eprintln!("\n  escala: 120 hosts concurrentes → 40 confirmados, 0 FP, 40 podados, 40 sembrados ✓\n");
}

// ── FAN-OUT: la FASE completa sobre un corpus mixto, persistiendo hallazgos ───

#[tokio::test]
async fn fase_auth_fanout_persiste_solo_los_vulnerables() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("fanout.db"), 4).await.unwrap();
    let program = "sim-fanout";
    let program_id = db::upsert_program(&pool, program).await.unwrap();

    // Reusa srv_a/b/c del banco (A vuln-defendido, B defendido, C abierto).
    let a = arranca(Router::new().route("/x", get(srv_a))).await;
    let b = arranca(Router::new().route("/x", get(srv_b))).await;
    let c = arranca(Router::new().route("/x", get(srv_c))).await;
    let corpus = vec![format!("http://{a}/x"), format!("http://{b}/x"), format!("http://{c}/x")];

    let token = auth::forjar_hs256(&serde_json::json!({"sub":"u","role":"user"}), b"s");
    let cli = reqwest::Client::new();
    let mut guard = Guard::new(ProtectionConfig::default());
    let mut k = 0u64;
    let rng = move || {
        k += 1;
        (k % 7) as f64 / 7.0
    };

    // Fan-out de la fase: control barato poda B(defendido→sin bypass) sin FP y C(abierto→sin sink).
    let n = auth::fase_autenticacion(
        &pool, program, program_id, &corpus, &[token], &cli, "", &mut guard, None, None, rng,
    )
    .await
    .unwrap();

    assert_eq!(n, 1, "solo el endpoint vulnerable (A) produce hallazgo");
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM findings")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(total, 1, "exactamente 1 finding persistido (ni B ni C)");
    let (url, cwe): (String, Option<String>) =
        sqlx::query_as("SELECT url, cwe FROM findings LIMIT 1").fetch_one(&pool).await.unwrap();
    assert!(url.contains(&a), "el finding es del endpoint vulnerable A");
    assert_eq!(cwe.as_deref(), Some("CWE-347"), "CWE-347 (firma no verificada)");
    eprintln!("\n  fan-out auth: 3 endpoints (A vuln, B limpio, C abierto) → 1 hallazgo (A), CWE-347 ✓\n");
}

// ── CONFUSIÓN DE ALGORITMO vía JWKS (pipeline completo, dir. 28 + 33) ─────────
//
// Valida la CADENA ENTERA: descubrir JWKS → reconstruir el PEM SPKI de (n,e) → forjar HS256
// con ese PEM → el server (que verifica HS256 con SU pubkey como secreto, el bug) lo ACEPTA.
// Si el codificador DER estuviera mal por un byte, el secreto no casaría y n=0 → rojo real.

const N_B64URL_C: &str = "1U7loz5JUPxOW41rQB5ROikGVsfV3bTvJwN26XonRmq4qpXDR5msTJUI62fGx4gv9dcp1BQnQp57ovKk6poRnOfYmwQn9jKbsybBcvTaL9fKP4sJyRw0nmVFVi8gu5cOIxtYbhNwB-k8kretKlB_Xn7m_HMnNAt1UXs4lEsCVbWPqbYNuyf9cEqUPYAjm4ojgzXSV8SoIw9RZTULdeHnGTMqagWAEerLOO8HN4imz6_ABrpci6zeAq8WiB2BIzqW3VUBPmbEXmYnngSf9kMqU5T_Mi3P4DqO7IHAU5bLYmu53gcO_dcYhxyWZk2GevtG6cM2YKHkNipowzQPpY5A2Q";
const PEM_REF_C: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1U7loz5JUPxOW41rQB5R\nOikGVsfV3bTvJwN26XonRmq4qpXDR5msTJUI62fGx4gv9dcp1BQnQp57ovKk6poR\nnOfYmwQn9jKbsybBcvTaL9fKP4sJyRw0nmVFVi8gu5cOIxtYbhNwB+k8kretKlB/\nXn7m/HMnNAt1UXs4lEsCVbWPqbYNuyf9cEqUPYAjm4ojgzXSV8SoIw9RZTULdeHn\nGTMqagWAEerLOO8HN4imz6/ABrpci6zeAq8WiB2BIzqW3VUBPmbEXmYnngSf9kMq\nU5T/Mi3P4DqO7IHAU5bLYmu53gcO/dcYhxyWZk2GevtG6cM2YKHkNipowzQPpY5A\n2QIDAQAB\n-----END PUBLIC KEY-----\n";

/// Endpoint VULNERABLE a confusión: verifica HS256 con la PUBKEY (PEM) como secreto HMAC.
async fn srv_confusion(headers: HeaderMap) -> (StatusCode, String) {
    let Some(authz) = header_tok(&headers) else { return unauth() };
    let Some(jwt) = auth::parse_jwt(&authz) else { return unauth() };
    if jwt.alg == "HS256" && auth::verificar_hs256(&authz, PEM_REF_C.as_bytes()) {
        let rol = jwt.payload.get("role").and_then(|v| v.as_str()).unwrap_or("user");
        if rol == "admin" || rol == "administrator" {
            return (StatusCode::OK, "{\"access\":\"granted\"}".into());
        }
    }
    unauth()
}

/// JWKS que publica la pubkey (n,e).
async fn jwks_endpoint() -> (StatusCode, String) {
    (
        StatusCode::OK,
        format!("{{\"keys\":[{{\"kty\":\"RSA\",\"n\":\"{N_B64URL_C}\",\"e\":\"AQAB\",\"kid\":\"1\"}}]}}"),
    )
}

#[tokio::test]
async fn fase_auth_confusion_de_algoritmo_via_jwks() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("conf.db"), 4).await.unwrap();
    let program = "sim-confusion";
    let program_id = db::upsert_program(&pool, program).await.unwrap();

    let app = Router::new()
        .route("/x", get(srv_confusion))
        .route("/.well-known/jwks.json", get(jwks_endpoint));
    let host = arranca(app).await;
    let corpus = vec![format!("http://{host}/x")];

    let token = auth::forjar_hs256(&serde_json::json!({"sub":"u","role":"user"}), b"s");
    let cli = reqwest::Client::new();
    let mut guard = Guard::new(ProtectionConfig::default());
    let mut k = 0u64;
    let rng = move || {
        k += 1;
        (k % 7) as f64 / 7.0
    };

    let n = auth::fase_autenticacion(
        &pool, program, program_id, &corpus, &[token], &cli, "", &mut guard, None, None, rng,
    )
    .await
    .unwrap();

    assert_eq!(n, 1, "confusión de algoritmo CONFIRMADA con la clave derivada del JWKS");
    let (cwe, ev): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT cwe, verification_evidence FROM findings LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cwe.as_deref(), Some("CWE-347"), "CWE-347");
    assert!(
        ev.unwrap_or_default().contains("alg-confusion"),
        "el molde ganador es alg-confusion (no alg-none)"
    );
    eprintln!("\n  confusión: JWKS (n,e) → PEM SPKI → HS256 forjado → ACEPTADO → 1 hallazgo (alg-confusion) ✓\n");
}

// ── FIRMA NO VERIFICADA — el falso negativo que cazó la revisión (2026-08-25) ──
//
// Un servidor que exige token pero NO verifica la firma (CWE-347 clásico) aceptaba el token
// de CONTROL, y la vieja compuerta lo leía como "sin sink" y lo podaba. Ahora se distingue
// con una sonda SIN token: si sin-token→401 y control(firma basura)→200, es el hallazgo.

/// SERVIDOR D — firma NO verificada: exige un JWT bien formado pero no comprueba su firma.
async fn srv_d(headers: HeaderMap) -> (StatusCode, String) {
    let Some(authz) = header_tok(&headers) else { return unauth() };
    let Some(_jwt) = auth::parse_jwt(&authz) else { return unauth() };
    (StatusCode::OK, "{\"access\":\"granted\"}".into()) // BUG: acepta sin verificar la firma
}

#[tokio::test]
async fn firma_no_verificada_se_detecta_y_publico_se_poda() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("firma.db"), 4).await.unwrap();
    let jwt = muestra();
    let cli = reqwest::Client::new();

    // D: firma-ciega → DEBE detectarse (antes se podaba: el falso negativo de la revisión).
    let d = arranca(Router::new().route("/x", get(srv_d))).await;
    let hd = Harness { cliente: cli.clone(), url: format!("http://{d}/x") };
    let rd = auth::ciclo_auth(&pool, "sim", "host-d", &jwt, &[], &MOLDES, &hd).await.unwrap();
    assert!(rd.bypass.is_some(), "D: firma-no-verificada DEBE detectarse, no podarse");
    assert_eq!(rd.bypass.as_ref().unwrap().molde, "firma-no-verificada");
    assert_eq!(secuencias::contar_vigentes(&pool, "host-d").await.unwrap(), 1, "D: sembrada");

    // C (público): no-token también pasa → sigue siendo poda, SIN FP (la pareja, dir. 33).
    let c = arranca(Router::new().route("/x", get(srv_c))).await;
    let hc = Harness { cliente: cli.clone(), url: format!("http://{c}/x") };
    let rc = auth::ciclo_auth(&pool, "sim", "host-c2", &jwt, &[], &MOLDES, &hc).await.unwrap();
    assert!(rc.bypass.is_none(), "C: recurso público NO es firma-no-verificada (no-token también pasa)");
    assert_eq!(rc.senal, auth::SenalAuth::SinSink, "C: sin sink");
    assert_eq!(secuencias::contar_vigentes(&pool, "host-c2").await.unwrap(), 0, "C: nada sembrado");

    eprintln!("\n  firma-no-verificada: firma-ciega DETECTADA, público podado (sin FP) ✓\n");
}
