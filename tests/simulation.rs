//! Simulación a escala (directiva 8): 100+ operaciones, concurrencia con la BD
//! real, y prueba de que las salvaguardas DISCRIMINAN sobre todo el rango.

use nexus::db::{self, NewFinding};
use nexus::protection::{backoff, jitter, phase_timeout};

/// 120 hallazgos únicos, cada uno intentado 3 veces en paralelo (360 inserciones
/// concurrentes contra SQLite). Solo deben quedar 120: el dedup discrimina bajo
/// concurrencia real.
#[tokio::test]
async fn dedup_concurrente_a_escala() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("sim.db"), 8).await.unwrap();
    let pid = db::upsert_program(&pool, "sim").await.unwrap();

    let mut handles = Vec::new();
    for i in 0..120u32 {
        for _ in 0..3 {
            let pool = pool.clone();
            handles.push(tokio::spawn(async move {
                let f = NewFinding {
                    program_name: "sim".into(),
                    vuln_name: format!("vuln-{i}"),
                    severity: "high".into(),
                    url: format!("https://h{i}.example.com/p"),
                    cwe: None,
                    evidencia: None,
                };
                db::insert_finding_dedup(&pool, &f, pid).await.unwrap()
            }));
        }
    }

    let mut inserted = 0u32;
    for h in handles {
        if h.await.unwrap() {
            inserted += 1;
        }
    }
    assert_eq!(inserted, 120, "360 intentos concurrentes, 120 únicos → 120 insertados");
    assert_eq!(db::count_findings(&pool).await.unwrap(), 120);
}

/// El backoff es no-decreciente y queda topado sobre 100 valores.
#[test]
fn backoff_monotono_y_topado_en_rango() {
    let mut prev = 0u64;
    for n in 1..=100u32 {
        let b = backoff(120, 1800, n);
        assert!(b <= 1800, "nunca supera el techo");
        assert!(b >= prev || b == 1800, "no decrece hasta topar");
        prev = b;
    }
    assert_eq!(backoff(120, 1800, 100), 1800);
}

/// El jitter se mantiene en ±20% sobre 1000 muestras — no puede degenerar en un
/// valor fijo (patrón detectable) ni salirse de rango (baneo).
#[test]
fn jitter_acotado_en_mil_muestras() {
    let mut distintos = std::collections::BTreeSet::new();
    for k in 0..1000u32 {
        let r = k as f64 / 1000.0;
        let j = jitter(100.0, 20, r);
        assert!(j >= 80.0 - 1e-9, "no baja de -20%");
        assert!(j < 120.0 + 1e-9, "no sube de +20%");
        distintos.insert((j * 1000.0) as i64);
    }
    assert!(distintos.len() > 900, "el jitter debe variar, no colapsar a un valor");
}

/// El timeout por fase crece con hosts y tags, con piso de 900s.
#[test]
fn timeout_de_fase_escala() {
    assert_eq!(phase_timeout(0, 0), 900);
    let mut prev = 0u64;
    for hosts in (0..=1000).step_by(50) {
        let t = phase_timeout(hosts, 8);
        assert!(t >= prev, "monótono en nº de hosts");
        prev = t;
    }
}
