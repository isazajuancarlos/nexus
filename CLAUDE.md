# nexus — guía del proyecto

> La configuración GENERAL (directivas, stack, VPS, protocolo solo-local, memoria)
> vive en `~/.claude/CLAUDE.md` y se carga siempre. Aquí va **solo lo propio de
> nexus**. Etiqueta de sesión: `[nexus]`.

## Qué es

Orquestador de bug bounty / detección de seguridad en Rust: el motor son binarios
externos (`nuclei`/`subfinder`/`httpx`/`sqlmap`…) y **Rust los DIRIGE**, protege la IP
del baneo, deduplica y persiste. El valor propio no es el catálogo (eso es el efecto
brain, [[numasec-el-mejor-80-sin-oraculo-de-verdad]]) sino los **oráculos de confirmación
por ejecución**.

**Postura, y manda sobre todo lo demás:** el cazador AUTÓNOMO está apagado desde el
2026-08-27 ([[nexus-detenido-efecto-brain]]) por no tener edge pagable en las clases
maduras. nexus se opera **a demanda, con el razonador** (`~/.claude/skills/razonador`),
un objetivo a la vez — NO como barrido automático. Toda capacidad nueva se justifica por
(a) llenar un hueco vivo del razonador/authz, o (b) abrir un edge fresco con oráculo
limpio; repetir recon canónico no es ninguna de las dos.

## Estatuto (no negociable)

nexus **ataca solo para ENCONTRAR y reportar**, nunca para perjudicar
([[nexus-detector-ataca-para-encontrar]]): sin implante, persistencia, exfiltración ni
DoS; PoC mínimo. Scope: sistemas propios/lab, o programas con bounty en scope explícito.
**No se crean cuentas en el objetivo** (huella→baneo, [[no-crear-cuentas-en-objetivos-huella-baneo]]):
se confirma por **lab local** con identidades sembradas.

## Invariantes del motor (salvaguardas «sin daño»)

- **`autz` (IDOR/BOLA/BAC) es GET-only**: nunca POST/PUT/DELETE sobre recurso ajeno.
  Diffea la MISMA URL entre identidades; predicado de la doc defensiva invertida
  (404≠403 al recurso ajeno). Confianza ALTA se auto-confirma, MEDIA sigue al verificador.
- **`mass_assign` ESCRIBE, y por eso es opt-in** (`--mass-assign`): PATCH solo sobre el
  objeto PROPIO del dueño (semillas), valores centinela, additivo, no-op sin el flag.
- **`protection.rs` es el anti-baneo** (cooldown+jitter+backoff, cortacircuitos por
  rate-limit): la IP del VPS es COMPARTIDA — si el objetivo frena, se PARA. Toda fase
  larga honra un deadline de presupuesto.
- **Los oráculos confirman por EJECUCIÓN**, no por presencia: `oraculo_diferencial`
  (control + y − ), canario para LLM, re-fetch para mass-assign. Un oráculo de presencia
  es la trampa del efecto brain.

## Capacidades de la veta mindalá (2026-09-24)

Reimplementaciones nativas de técnicas externas (soberanas, keyless). CLI y ejemplos en
`README.md` §Uso.

- **`parametros`** (`src/parametros.rs`): descubridor de parámetros ocultos por anomalía
  (técnica de Arjun, reimplementada — nexus ya invocaba `arjun` externo en enhanced-recon;
  esta es la versión nativa que ALIMENTA los oráculos). Factores + reflexión de centinela,
  bisección de lotes; longitud/líneas OFF por defecto (ruidosos, rompen la bisección).
- **`--mass-assign-descubrir`**: engancha lo anterior a `mass_assign` — los campos ocultos
  que el backend acepta amplían la inyección más allá del listado estático.
- **`redteam-llm`** (`src/redteam_llm.rs`): red-team de seguridad de LLM (OWASP LLM Top 10)
  con **oráculo de canario** (`RT_<hex>` en la salida del modelo, extraída por
  `ruta_respuesta` para evitar el FP del eco). Listo, a la espera de objetivo LLM en scope
  ([[agentic-bug-hunter-confirma-brain-y-llm-oraculo-canario]]).

## Capacidad `candidatos` — SELECCIÓN para el carril whitebox (2026-10-21)

- **`candidatos`** (`src/candidatos.rs`): la capa que la auditoría del 2026-10-21
  (`conocimiento/objetivos/AUDITORIA-NEXUS-METODOS-2026-10-21.md`) halló AUSENTE — todo el
  resto de nexus es live-DAST (modelo medido SECO, efecto brain), y los 6 hallazgos reales
  salieron de **whitebox de código-fuente sobre OSS joven**, hecho a mano con `curl`. Esto lo
  persiste: keyless (search API + advisories de GitHub), por dominio trae repos jóvenes, cuenta
  avisos por CLASE authz vs total, cruza LISTA-NEGRA y los puntúa. **Es un EMBUDO, no un oráculo**
  (D16): `PERSEGUIR` = vale una lectura puerta-0, NUNCA "tiene un bug" — el discriminador real
  (cobertura del control) solo se ve leyendo el código. **Guardrail (D37): SELECCIONA y TRÍA, nunca
  encuentra-y-envía** — no clona, no escanea, no reporta. Alimenta al razonador; no lo reemplaza.
  Validado contra verdad-terreno del corpus (incluye los hits, excluye lo sobre-auditado).
  Filtro MEDIDO: subrecursado ≠ pocas-estrellas ([[nexus-modelo-dast-equivocado-selec-es-el-cuello]]).
- **Puerta de TIPO (`tipo_no_app`, añadida 2026-10-21 tras la 1ª corrida real):** demota a `Evitar` lo que
  NO es app web multi-tenant auditable — research de paper (casó "language models"), SDK/CLI/MCP-server,
  scraper/automatización de pruebas, cliente de escritorio, repo-demo. Nació porque la 1ª corrida midió
  **11/23 PERSEGUIR que ni eran apps**. **Sesgo D21 INVERTIDO**: excluir una app real = falso negativo =
  perder un hit, así que es CONSERVADOR (solo señal FUERTE; lo ambiguo sigue). Mide 9/11 cazados, 0 falsos
  positivos sobre hits/apps del corpus. El detector de ofuscación/edición-comercial (PasPapan) queda de
  follow-up: necesita fetch profundo y rinde 1/23 (construir con más evidencia, D37/D16).

## Build y puerta (el único verde: local, sin CI)

```bash
cargo test                                # unit + integración (stubs reales) + simulación (D28)
cargo clippy --all-targets -- -D warnings # la PUERTA: warn escala a error
```

- **Toda sonda nace con su pareja y el rojo falla por la vía real** (D33): el mutante casi
  siempre es la regla anterior. Núcleo PURO separado del driver HTTP; E2E arranca servidor
  real (axum) o los stubs de binario.
- **Features MÍNIMAS** (protocolo solo-local): reqwest sin `full`, axum con `["http1",
  "json","tokio"]`. Métodos «obvios» pueden no existir — `reqwest::form`,
  `axum::extract::Query`/`Form` están gateados; hay vía sin la feature
  ([[nexus-features-minimas-gatean-metodos]]). Añadir una feature es decisión aparte.
- `Cargo.toml`: `opt-level = "z"` (binario por tamaño) y puerta de clippy
  `redundant_clone`/`needless_collect = deny`.

## Titularidad

MIT — Copyright (c) 2026 Juan Carlos Isaza. Herramienta de investigación de seguridad
autorizada. Proyecto de venta: **no** publicado en registro (protocolo solo-local).
