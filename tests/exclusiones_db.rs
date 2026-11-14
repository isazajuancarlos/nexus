//! La memoria negativa por causa, cruzando la BD real (directiva 28): abre un
//! pool que aplica la migración 0010, registra veredictos y comprueba que la
//! ACCIÓN que sale por `accion_para` es la correcta —incluida la caducidad por
//! huella— sobre SQLite de verdad, no en estructura.

use nexus::db;
use nexus::exclusiones::{self, Accion, Causa};

#[tokio::test]
async fn registra_consulta_y_caduca_por_huella() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("exc.db"), 4).await.unwrap();
    let host = "api.objetivo.com";

    // Sin veredicto previo: intento normal (falla ABIERTO, directiva 20).
    assert_eq!(
        exclusiones::accion_para(&pool, host, "ssrf", "s=200;waf=-", 86_400).await.unwrap(),
        Accion::Reintentar { presupuesto_mult: 1 },
        "una (host,clase) nunca excluida se corre con normalidad"
    );

    // INEXISTENCIA (sin parámetros inyectables) con una huella dada.
    exclusiones::registrar(&pool, host, "ssrf", Causa::Inexistencia, "s=200;waf=akamai").await.unwrap();

    // Misma huella → se SALTA (no se re-machaca lo que no existe).
    assert_eq!(
        exclusiones::accion_para(&pool, host, "ssrf", "s=200;waf=akamai", 86_400).await.unwrap(),
        Accion::Saltar
    );

    // Huella DISTINTA (el objetivo cambió su postura) → el veredicto caduca y se
    // reintenta con normalidad. Es el caso que evita quedarse ciego para siempre.
    assert_eq!(
        exclusiones::accion_para(&pool, host, "ssrf", "s=200;waf=-;sec=csp", 86_400).await.unwrap(),
        Accion::Reintentar { presupuesto_mult: 1 }
    );

    // Otra clase del MISMO host es independiente: métodos agotados → generación.
    exclusiones::registrar(&pool, host, "autz", Causa::MetodosAgotados, "s=403;waf=akamai").await.unwrap();
    assert_eq!(
        exclusiones::accion_para(&pool, host, "autz", "s=403;waf=akamai", 86_400).await.unwrap(),
        Accion::EncolarGeneracion
    );
    // ...y no contaminó la de ssrf.
    assert_eq!(
        exclusiones::consultar(&pool, host, "ssrf").await.unwrap().map(|(c, _)| c),
        Some(Causa::Inexistencia)
    );

    // UPSERT: un veredicto nuevo sobre la misma (host,clase) SUSTITUYE al viejo
    // (el último manda) — de inexistencia a tiempo → ×2 con la nueva huella.
    exclusiones::registrar(&pool, host, "ssrf", Causa::Tiempo, "s=200;waf=cloudflare").await.unwrap();
    assert_eq!(
        exclusiones::accion_para(&pool, host, "ssrf", "s=200;waf=cloudflare", 86_400).await.unwrap(),
        Accion::Reintentar { presupuesto_mult: 2 },
        "la causa más reciente manda, con su huella"
    );
}

/// `veces` cuenta reafirmaciones de LA MISMA causa (directiva 32): sube al repetir
/// la misma, y vuelve a 1 cuando la causa cambia — no mezcla "veces tocada" con
/// "veces reafirmada".
#[tokio::test]
async fn veces_cuenta_reafirmaciones_de_la_misma_causa() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("v.db"), 2).await.unwrap();
    let veces = |p: sqlx::SqlitePool| async move {
        sqlx::query_scalar::<_, i64>("SELECT veces FROM exclusiones WHERE host='h' AND clase='ssrf'")
            .fetch_one(&p).await.unwrap()
    };
    exclusiones::registrar(&pool, "h", "ssrf", Causa::MetodosAgotados, "f1").await.unwrap();
    assert_eq!(veces(pool.clone()).await, 1);
    exclusiones::registrar(&pool, "h", "ssrf", Causa::MetodosAgotados, "f1").await.unwrap();
    assert_eq!(veces(pool.clone()).await, 2, "misma causa reafirmada → ++");
    // Cambia la causa → el contador de la causa nueva arranca en 1, no en 3.
    exclusiones::registrar(&pool, "h", "ssrf", Causa::Tiempo, "f2").await.unwrap();
    assert_eq!(veces(pool.clone()).await, 1, "causa distinta → veces vuelve a 1");
}
