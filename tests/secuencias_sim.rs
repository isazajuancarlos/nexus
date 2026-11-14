//! Simulación de la memoria adaptativa (`secuencias`) sobre BD REAL en disco,
//! con concurrencia y ciclos de endurecimiento del objetivo (directiva 8: 100+
//! operaciones; directiva 28: se cruza la frontera de la BD con un archivo y un
//! pool multi-conexión, no un `:memory:` de una sola conexión).
//!
//! El invariante que se persigue es el que separa criar un virus de acumular
//! ruido: NINGUNA secuencia caducada (host que mutó su defensa) se re-lanza
//! jamás, y TODA secuencia vigente bajo la huella actual SÍ aflora.

use std::collections::BTreeMap;
use std::sync::Arc;

use nexus::db;
use nexus::secuencias::{self, Mutacion, OraculoConfirmado, PosturaDefensa};

fn mutacion(host: &str, tecnica: &str) -> Mutacion {
    let mut p = BTreeMap::new();
    p.insert("host".into(), host.into());
    p.insert("payload".into(), format!("var-{tecnica}"));
    Mutacion { familia: "bypass-403".into(), tecnica: tecnica.into(), parametros: p }
}

fn huella_base(status: u16) -> String {
    PosturaDefensa { status_no_auth: status, ..Default::default() }.huella()
}

fn huella_endurecida(status: u16, waf: &str) -> String {
    PosturaDefensa {
        status_no_auth: status,
        familia_waf: Some(waf.into()),
        cabeceras_seguridad: vec!["hsts".into(), "csp".into()],
        ..Default::default()
    }
    .huella()
}

/// 120 hosts, cada uno recorre el ciclo completo confirmar→re-lanzar→endurecer→
/// caducar→reconfirmar. Comprueba las dos caras (directiva 23) en cada vuelta.
#[tokio::test]
async fn ciclo_de_endurecimiento_sobre_120_hosts() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("sim.db"), 8).await.unwrap();

    for i in 0..120 {
        let host = format!("host{i}.ejemplo.com");
        let h0 = huella_base(403);
        let m = mutacion(&host, "header-inject");
        let testigo = OraculoConfirmado::desde_ejecucion(true).unwrap();

        // 1. Confirmar (nace).
        assert!(
            secuencias::guardar(&pool, &testigo, "prog", &host, &h0, &m, Some("f"), Some("3/3"))
                .await
                .unwrap(),
            "host {i}: primera confirmación debe nacer"
        );

        // 2. Re-lanzar bajo misma huella (lado ciego: DEBE aflorar).
        let vig = secuencias::recuperar(&pool, &host, "bypass-403", &h0).await.unwrap();
        assert_eq!(vig.len(), 1, "host {i}: la secuencia válida debe re-lanzarse");

        // 3. El host se endurece → huella nueva. La vieja caduca, no se re-lanza
        //    (lado ruidoso: NO debe aflorar la obsoleta).
        let h1 = huella_endurecida(403, "cloudflare");
        let vig = secuencias::recuperar(&pool, &host, "bypass-403", &h1).await.unwrap();
        assert!(vig.is_empty(), "host {i}: tras endurecerse no se re-lanza lo obsoleto");
        assert_eq!(
            secuencias::contar_vigentes(&pool, &host).await.unwrap(),
            0,
            "host {i}: la secuencia obsoleta quedó caducada"
        );

        // 4. El oráculo reconfirma una mutación NUEVA bajo la huella endurecida.
        let m2 = mutacion(&host, "path-mangle");
        assert!(
            secuencias::guardar(&pool, &testigo, "prog", &host, &h1, &m2, None, Some("2/2"))
                .await
                .unwrap(),
            "host {i}: la mutación adaptada al WAF nace"
        );
        let vig = secuencias::recuperar(&pool, &host, "bypass-403", &h1).await.unwrap();
        assert_eq!(vig.len(), 1, "host {i}: solo la secuencia adaptada aflora");
        assert_eq!(vig[0].mutacion.tecnica, "path-mangle");
    }

    // Invariante global final: por cada host, exactamente 1 vigente (la adaptada)
    // y 1 caducada (la vieja) = 240 filas, 120 vigentes.
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secuencias")
        .fetch_one(&pool)
        .await
        .unwrap();
    let vigentes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secuencias WHERE caducada = 0")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(total, 240, "120 hosts × (1 vieja caducada + 1 adaptada)");
    assert_eq!(vigentes, 120, "exactamente una vigente por host");
}

/// Concurrencia: 100 tareas confirmando y recuperando a la vez sobre el mismo
/// pool. No debe haber pánico, deadlock ni conteo inconsistente. Cada tarea usa
/// su propio host para que el invariante por-host sea comprobable sin carreras
/// lógicas (la carrera que se prueba es la de la BD, no la del modelo).
#[tokio::test]
async fn cien_confirmaciones_concurrentes() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(db::open(&dir.path().join("conc.db"), 8).await.unwrap());

    let mut handles = Vec::new();
    for i in 0..100 {
        let pool = Arc::clone(&pool);
        handles.push(tokio::spawn(async move {
            let host = format!("c{i}.ejemplo.com");
            let h = huella_base(401);
            let m = mutacion(&host, "verb-tamper");
            let testigo = OraculoConfirmado::desde_ejecucion(true).unwrap();
            secuencias::guardar(&pool, &testigo, "prog", &host, &h, &m, None, None)
                .await
                .unwrap();
            // Inmediatamente recupera lo que acaba de confirmar.
            let vig = secuencias::recuperar(&pool, &host, "bypass-403", &h).await.unwrap();
            assert_eq!(vig.len(), 1, "tarea {i}: recupera lo que confirmó");
        }));
    }
    for h in handles {
        h.await.expect("ninguna tarea entra en pánico");
    }

    let vigentes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secuencias WHERE caducada = 0")
        .fetch_one(&*pool)
        .await
        .unwrap();
    assert_eq!(vigentes, 100, "100 confirmaciones concurrentes → 100 vigentes");
}

/// Inyección del camino de error del oráculo: de 100 sondas, solo las que el
/// oráculo confirmó (`execution_confirmed=true`) deben poder guardarse. Las que
/// devolvieron NO ni siquiera producen testigo — imposible guardarlas. Comprueba
/// que la SELECCIÓN filtra el ruido antes de que llegue a la memoria.
#[tokio::test]
async fn solo_lo_confirmado_por_el_oraculo_entra() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("sel.db"), 4).await.unwrap();
    let h = huella_base(403);

    let mut confirmadas = 0;
    for i in 0..100 {
        // La mitad "no ejecuta" (heurística sin confirmación): sin testigo posible.
        let ejecuto = i % 2 == 0;
        let host = format!("s{i}.ejemplo.com");
        let m = mutacion(&host, "header-inject");
        match OraculoConfirmado::desde_ejecucion(ejecuto) {
            Some(testigo) => {
                secuencias::guardar(&pool, &testigo, "prog", &host, &h, &m, None, None)
                    .await
                    .unwrap();
                confirmadas += 1;
            }
            None => { /* el oráculo dijo NO: no hay nada que guardar, y no se puede */ }
        }
    }
    assert_eq!(confirmadas, 50);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secuencias")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(total, 50, "solo las 50 confirmadas por el oráculo llegaron a la memoria");
}
