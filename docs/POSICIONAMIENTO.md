<!-- SPDX-License-Identifier: LicenseRef-Propietario -->
# Posicionamiento — por qué el edge no es la amplitud de técnicas

> Nota estratégica (2026-09-05). Insumo para el portafolio y para la skill
> `razonador`. Fundada en dos estudios propios del fuente (numasec, 4 cazadores
> OSS) y en dos señales externas frescas (XBOW, "AI slop"), leídas como dato.
> Complementa `docs/METODOS.md` (el catálogo de capacidad) respondiendo a la
> pregunta distinta: de todo lo que se puede hacer, **¿qué de verdad paga?**

## El eje que decide un hallazgo pagable

No es *cuántas* técnicas se ejecutan. Es dónde cae el método en un solo eje:

- **Amplitud** — emparejar contra un catálogo de clases **conocidas** y confirmar
  por **presencia** (regex de secreto, código de estado, `body.includes("<script")`).
  Barre ancho y barato. En un objetivo maduro sale seco: el defensor ya cerró lo
  conocido, que es justo lo que el catálogo empareja. Su subproducto es ruido.
- **Profundidad** — **razonar el sistema**: modelar la frontera de confianza,
  fijar el invariante de autorización, e intentar **refutarlo**; confirmar por
  **ejecución diferencial** (un control positivo que debe filtrar y uno negativo
  que no, p. ej. parte=200 / tercero=200 / inexistente=404). Muerde donde el
  catálogo no llega: la lógica propia del objetivo.

nexus contiene los dos lados. Sus 17 fases son un barrido multivector contra **un
mismo objetivo** (diverso en clase de bug, único en objetivo): `autz`, `auth`,
`ssrf`, `xss`, `smuggling`, `takeover`, `config`… cada una rompe una frontera
distinta y consume una rebanada distinta de la superficie. Pero ~12 de esas 17
(config, TLS, cabeceras, takeover, `fase_dast`) son **amplitud**; el edge real
son las 2-3 que van por ejecución diferencial (`autz` keyless, `xss` real,
`autenticacion`), y sobre todo la skill `razonador` que las dirige.

## Lo que el prior-art confirma

Cinco sistemas estudiados del fuente — **numasec** y los cuatro cazadores OSS
(Cybermes, Claude-BugHunter, GoSFinder, Agentic-Bug-Hunter) — comparten un
patrón: **80% de andamiaje excelente, 0% del 20% que da edge.** Su diversidad de
técnicas es alta y su oráculo es de **presencia disfrazada de rigor** (numasec
predica *"never LLM confidence as final proof"* y su código entrega un gate que
solo comprueba que el LLM escribió *algún* texto en el campo `replay`). Ninguno
razona invariante ni confirma contra estado real. Su amplitud no es un edge; es
la ausencia de uno, con buena ropa.

## Lo que el mercado externo confirma (2026)

Dos titulares opuestos son las dos caras del mismo eje:

- **Lo que aterriza — XBOW.** Primer puesto en el leaderboard de HackerOne (US),
  132 vulnerabilidades resueltas por los dueños, tres RCE en Bing (CVSS 9.8), una
  cadena de 48 pasos de blind SSRF a compromiso total. La cobertura de prensa
  insiste en que **no es un scanner de más técnicas**: es comprensión del
  objetivo, planificación de la cadena de ataque y adaptación dinámica —
  profundidad, industrializada con $237M.
- **Lo que el mercado expulsa — "AI slop".** El mantenedor de curl reporta que
  ~20% de los envíos son *slop* generado por IA y solo ~5% son reales (cuatro
  falsos por cada verdadero); el proyecto CycloneDX **cerró** su programa de
  recompensas por la avalancha; HackerOne y Bugcrowd despliegan gating por
  reputación y triaje con IA para filtrarlo. Ese slop es precisamente el producto
  del cazador autónomo **de amplitud con oráculo de presencia**.

La lección no es opinión interna: la amplitud commodity ya está siendo **filtrada
activamente** por las plataformas, con nombre y fecha.

## Determinación de posicionamiento

1. **No competimos por amplitud.** Es el lado del *slop*, que el mercado expulsa.
2. **No competimos por escala autónoma.** Ese terreno es de XBOW y su capital.
3. **Competimos por profundidad donde el capital no mira.** El único terreno que
   muerde sin infraestructura industrial: **selección de un objetivo poco
   auditado + oráculo diferencial por ejecución + firma humana** (el criterio
   jurídico del abogado como sello del hallazgo). Ahí XBOW no juega —barre lo
   grande y conocido— y el *slop* no llega —no razona—.

La evidencia propia lo respalda: los hallazgos reales recientes (Liberapay,
Discourse, Zitadel — este último con advisory público GHSA-j344-gqv4-84ff) no
salieron del barrido de las 17 fases, sino del `razonador` apuntado a un objetivo
concreto y confirmado por ejecución.

**En una frase:** la diversidad de técnicas es tabla de casino; el edge es
apuntar hondo donde nadie más miró y probarlo por ejecución.

---
*Fuentes externas (leídas como dato, 2026-09-05): TechRepublic, XBOW y CyberScoop
sobre el liderazgo de XBOW en HackerOne; TechCrunch (2025-07-24) y HeroDevs sobre
el "AI slop" (cifras de curl y el cierre de CycloneDX). Estudios propios:
`analisis/estudio-numasec.md`, memoria `estudio-cazadores-oss-2026-08-30`.*
