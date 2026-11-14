// SPDX-License-Identifier: LicenseRef-Propietario
//! SIMULACIÓN a escala de los clasificadores de PRECISIÓN nuevos (2026-08-21).
//! Directiva 8 (100+ operaciones) + 33 (banco con las DOS listas que DISCRIMINA):
//! cada simulación corre cientos de casos sintéticos con positivos y negativos y
//! exige 0 falsos positivos / 0 falsos negativos. Puro (sin red): rápido y total.

use nexus::autz::{deadline_vencido, es_bypass, es_pagina_publica, Observado, Papel};
use nexus::{secretos, takeover};

fn obs(status: u16, len: usize, sig: u64, es_html: bool) -> Observado {
    Observado { papel: Papel::Anonimo, status, cuerpo_len: len, cuerpo_sig: sig, es_html, es_challenge: false }
}

fn obs_ch(status: u16, len: usize, sig: u64) -> Observado {
    Observado { papel: Papel::Anonimo, status, cuerpo_len: len, cuerpo_sig: sig, es_html: true, es_challenge: true }
}

#[test]
fn sim_secretos_discrimina_a_escala() {
    let total = 400usize;
    let (mut fp, mut fneg) = (0usize, 0usize);
    for i in 0..total {
        if i % 2 == 0 {
            // POSITIVO: cuerpo con un secreto de forma real embebido.
            let secreto = match i % 8 {
                0 => format!("ghp_{}", "a".repeat(36)),
                2 => format!("sk_live_{}", "b".repeat(30)),
                4 => format!("xoxb-{}", "1234567890abcdef1234"),
                _ => format!("sk-proj-{}", "c".repeat(50)),
            };
            let cuerpo = format!("var cfg={{}}; const t = '{secreto}'; init(t); // línea {i}");
            if secretos::detectar(&cuerpo).is_empty() {
                fneg += 1;
            }
        } else {
            // NEGATIVO: texto benigno con los substrings que ANTES eran FP.
            let benigno = format!(
                "const api_key = config.get('apikey'); let password = form.value; // token id {i}"
            );
            if !secretos::detectar(&benigno).is_empty() {
                fp += 1;
            }
        }
    }
    assert_eq!(fneg, 0, "0 falsos negativos sobre {} positivos", total / 2);
    assert_eq!(fp, 0, "0 falsos positivos sobre {} negativos", total / 2);
}

#[test]
fn sim_publicable_nunca_cuenta_como_secreto() {
    // 200 claves publicables de Stripe: NINGUNA debe ser verificable-como-secreto.
    for i in 0..200 {
        let pk = format!("pk_live_{}{}", "d".repeat(24), i % 10);
        let dets = secretos::detectar(&format!("stripe = '{pk}';"));
        assert!(dets.iter().all(|d| d.clase.publicable() || !d.clase.verificable()),
            "una pk_live no puede clasificarse como secreto verificable");
    }
}

#[test]
fn sim_deadline_gate_discrimina_a_escala() {
    // Fix del timeout de systemd (2026-08-21): las fases autz/bypass paran al
    // vencer el presupuesto del ciclo. A escala: 300 deadlines pasados → TODOS
    // vencidos (la fase para); 300 futuros y None → NINGUNO (la fase sigue).
    use std::time::{Duration, Instant};
    let ahora = Instant::now();
    let (mut fp, mut fneg) = (0usize, 0usize);
    for i in 1..=300u64 {
        // PASADO (deadline ya cruzado): debe estar vencido.
        if !deadline_vencido(ahora.checked_sub(Duration::from_millis(i))) {
            fneg += 1;
        }
        // FUTURO (aún hay presupuesto): NO debe estar vencido.
        if deadline_vencido(Some(ahora + Duration::from_secs(i))) {
            fp += 1;
        }
    }
    // Sin presupuesto (caza profunda): jamás vence.
    assert!(!deadline_vencido(None), "None nunca vence");
    assert_eq!(fneg, 0, "0 falsos negativos (deadline pasado que no paró la fase)");
    assert_eq!(fp, 0, "0 falsos positivos (deadline futuro que paró la fase antes de tiempo)");
}

#[test]
fn sim_es_bypass_discrimina_a_escala() {
    let n = 400usize;
    let (mut fp, mut fneg) = (0usize, 0usize);
    for i in 0..n {
        let sig_a = 0xA000 + i as u64;
        let sig_b = 0xB000 + i as u64;
        match i % 5 {
            // BYPASS REAL: 401 JSON → 200 con datos JSON distintos, sustancial.
            0 => {
                let base = obs(401, 66, sig_a, false);
                let var = obs(200, 300, sig_b, false);
                if !es_bypass(&base, &var) {
                    fneg += 1;
                }
            }
            // SHELL DEL SPA (FP): 401 JSON → 200 text/html (cambio no-HTML→HTML).
            1 => {
                let base = obs(401, 66, sig_a, false);
                let var = obs(200, 19329, sig_b, true);
                if es_bypass(&base, &var) {
                    fp += 1;
                }
            }
            // PÚBLICO (sin control): baseline ya 2xx → nada que saltar.
            2 => {
                let base = obs(200, 500, sig_a, false);
                let var = obs(200, 500, sig_a, false);
                if es_bypass(&base, &var) {
                    fp += 1;
                }
            }
            // CHALLENGE de WAF (FP nuevo, 2026-08-21): 403 "Just a moment…" (html) →
            // 200 página real (html). html→html, firma distinta: solo la cláusula
            // `!baseline.es_challenge` lo mata.
            3 => {
                let base = obs_ch(403, 5413, sig_a);
                let var = obs(200, 88076, sig_b, true);
                if es_bypass(&base, &var) {
                    fp += 1;
                }
            }
            // MISMA PÁGINA DE ERROR: 403 → 200 con el MISMO cuerpo (firma igual).
            _ => {
                let base = obs(403, 200, sig_a, false);
                let var = obs(200, 200, sig_a, false);
                if es_bypass(&base, &var) {
                    fp += 1;
                }
            }
        }
    }
    assert_eq!(fneg, 0, "0 falsos negativos (bypasses reales perdidos)");
    assert_eq!(fp, 0, "0 falsos positivos (shell/público/error marcados)");
}

#[test]
fn sim_es_pagina_publica_a_escala() {
    // El shell público (misma firma que la ruta-fantasma 2xx) SIEMPRE se descarta;
    // datos con otra firma NUNCA. 300 casos.
    for i in 0..300u64 {
        let publica = obs(200, 19329, 0x5A0F, true);
        let shell = obs(200, 19329, 0x5A0F, true);
        assert!(es_pagina_publica(&shell, &publica), "mismo cuerpo que la pública");
        let datos = obs(200, 100 + i as usize, 0xD000 + i, false);
        assert!(!es_pagina_publica(&datos, &publica), "otra firma no es la pública");
    }
}

#[test]
fn sim_takeover_discrimina_a_escala() {
    let fps = takeover::FINGERPRINTS;
    let (mut fp, mut fneg) = (0usize, 0usize);
    let mut casos = 0usize;
    for (i, (_servicio, cname_pat, huella)) in fps.iter().enumerate() {
        for k in 0..20 {
            casos += 1;
            let cname = format!("sub{k}.{cname_pat}");
            // POSITIVO: cname del servicio + su huella de no-reclamado.
            let cuerpo_pos = format!("<html>error {i}: {huella} — reclama este recurso</html>");
            if takeover::evaluar_takeover(&cname, &cuerpo_pos).is_none() {
                fneg += 1;
            }
            // NEGATIVO A: mismo cname pero recurso RECLAMADO (sin la huella).
            casos += 1;
            let cuerpo_neg = format!("<html>bienvenido al sitio {k} de la empresa</html>");
            if takeover::evaluar_takeover(&cname, &cuerpo_neg).is_some() {
                fp += 1;
            }
            // NEGATIVO B: la huella en un cname AJENO (no del servicio) no cuenta.
            casos += 1;
            if takeover::evaluar_takeover("cdn.propio-cliente.com", &cuerpo_pos).is_some() {
                fp += 1;
            }
        }
    }
    assert!(casos >= 100, "banco a escala: {casos} casos");
    assert_eq!(fneg, 0, "0 falsos negativos");
    assert_eq!(fp, 0, "0 falsos positivos");
}

#[test]
fn sim_graphql_introspeccion_discrimina_a_escala() {
    let (mut fp, mut fneg) = (0usize, 0usize);
    for i in 0..300u64 {
        if i % 2 == 0 {
            // Esquema real (introspección abierta).
            let ok = format!("{{\"data\":{{\"__schema\":{{\"queryType\":{{\"name\":\"Query{i}\"}}}}}}}}");
            if !nexus::graphql::introspeccion_expuesta(&ok) {
                fneg += 1;
            }
        } else {
            // Bloqueada o datos normales.
            let neg = if i % 3 == 0 {
                format!("{{\"errors\":[{{\"message\":\"introspection is not allowed ({i})\"}}]}}")
            } else {
                format!("{{\"data\":{{\"user\":{{\"id\":{i}}}}}}}")
            };
            if nexus::graphql::introspeccion_expuesta(&neg) {
                fp += 1;
            }
        }
    }
    assert_eq!(fneg, 0, "0 falsos negativos (esquemas reales)");
    assert_eq!(fp, 0, "0 falsos positivos (errores/datos normales)");
}

#[test]
fn sim_ssrf_metadata_discrimina_a_escala() {
    let (mut fp, mut fneg) = (0usize, 0usize);
    // El payload que se inyecta (para el guardián de reflexión).
    let payload = nexus::ssrf::PAYLOADS[0];
    for i in 0..300u64 {
        if i % 2 == 0 {
            // Metadata exfiltrada DE VERDAD: token de CUERPO real (nunca subcadena
            // del payload). El `inyectado` es benigno, así que el guardián no lo toca.
            let tok = match i % 6 {
                0 => "\"AccessKeyId\"",
                2 => "\"numericProjectId\"",
                _ => "\"vmId\"",
            };
            let resp = format!("{{\"n\":{i},\"body\":\"...{tok}...\"}}");
            if nexus::ssrf::detectar_metadata_exfiltrada(&resp, "https://x/api?u=1").is_none() {
                fneg += 1;
            }
        } else {
            // EL FALSO POSITIVO: la respuesta REFLEJA el payload inyectado (mensaje
            // de error con la URL). Contiene `iam/security-credentials` solo porque
            // lo inyectamos → con el guardián debe dar None. Antes esto era el bug.
            let resp = format!("{{\"n\":{i},\"error\":\"could not fetch {payload}\"}}");
            if nexus::ssrf::detectar_metadata_exfiltrada(&resp, payload).is_some() {
                fp += 1;
            }
        }
    }
    assert_eq!(fneg, 0, "0 falsos negativos (metadata real en el cuerpo)");
    assert_eq!(fp, 0, "0 falsos positivos (reflexión del payload inyectado)");
}

#[test]
fn sim_mass_assign_campo_pego_a_escala() {
    let (mut fp, mut fneg) = (0usize, 0usize);
    for i in 0..300u64 {
        if i % 2 == 0 {
            // El centinela pegó (role pasó a nuestro valor).
            let antes = format!("{{\"id\":{i},\"role\":\"user\"}}");
            let despues = format!("{{\"id\":{i},\"role\":\"nexusprobe_role\"}}");
            if !nexus::mass_assign::campo_pego(&antes, &despues, "role", "nexusprobe_role") {
                fneg += 1;
            }
        } else {
            // El servidor IGNORÓ el campo (sigue user) → no pegó.
            let antes = format!("{{\"id\":{i},\"role\":\"user\"}}");
            let despues = format!("{{\"id\":{i},\"role\":\"user\",\"updated_at\":{i}}}");
            if nexus::mass_assign::campo_pego(&antes, &despues, "role", "nexusprobe_role") {
                fp += 1;
            }
        }
    }
    assert_eq!(fneg, 0, "0 falsos negativos (inyección que pegó)");
    assert_eq!(fp, 0, "0 falsos positivos (servidor la ignoró)");
}

#[test]
fn sim_smuggling_timing_discrimina_a_escala() {
    let (mut fp, mut fneg) = (0usize, 0usize);
    for i in 0..300u128 {
        let base = 100 + (i % 500); // baseline 100–600ms
        if i % 2 == 0 {
            // Se colgó (desync): 6–10s.
            let prueba = 6_000 + (i % 4_000);
            if !nexus::smuggling::es_desync_por_tiempo(base, prueba) {
                fneg += 1;
            }
        } else {
            // Normal: proporcional y por debajo del piso → NO es desync.
            let prueba = base + (i % 300);
            if nexus::smuggling::es_desync_por_tiempo(base, prueba) {
                fp += 1;
            }
        }
    }
    assert_eq!(fneg, 0, "0 falsos negativos (colgados reales)");
    assert_eq!(fp, 0, "0 falsos positivos (jitter normal)");
}
