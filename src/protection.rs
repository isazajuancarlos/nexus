//! Sistema de protección anti-baneo de IP. Portado de `bounty/scanner.py`
//! (`ProtectionConfig` + cooldowns + backoff + salud de red + jitter).
//!
//! Objetivo (lo que pidió Juan): que los WAF/targets NO baneen la IP del VPS.
//! Palancas:
//!   1. Ritmo global acotado (rate_limit de nuclei) — está en Config.
//!   2. Cooldown entre programas y entre fases, CON jitter ±20% para no crear
//!      un patrón temporal detectable.
//!   3. Backoff exponencial ante fallos; pausa tras N fallos/errores seguidos.
//!   4. Chequeo de salud de red antes de golpear, y espera a que vuelva.
//!
//! Las partes computables (jitter, backoff) son funciones puras y deterministas
//! (el aleatorio se inyecta) para poder simular 100+ casos y probar que la regla
//! discrimina (directiva 8).

use std::time::Duration;

/// Configuración de protección. Defaults idénticos a bounty/.
#[derive(Debug, Clone)]
pub struct ProtectionConfig {
    pub program_cooldown: u64,        // s entre programas
    pub phase_cooldown: u64,          // s entre fases
    pub failure_backoff_base: u64,    // s, base del backoff (2 min)
    pub failure_backoff_max: u64,     // s, techo del backoff (30 min)
    pub max_consecutive_failures: u32,
    pub max_network_errors: u32,
    pub health_check_interval: u64,   // s
    pub health_check_hosts: Vec<String>,
    pub jitter_percent: u32,          // ±% sobre CADA espera
    pub user_agent: String,
}

impl Default for ProtectionConfig {
    fn default() -> Self {
        Self {
            program_cooldown: 60,
            phase_cooldown: 30,
            failure_backoff_base: 120,
            failure_backoff_max: 1800,
            max_consecutive_failures: 3,
            max_network_errors: 5,
            health_check_interval: 300,
            health_check_hosts: vec![
                "1.1.1.1:443".into(),
                "8.8.8.8:443".into(),
                "github.com:443".into(),
            ],
            jitter_percent: 20,
            user_agent: "NEXUS-BugBounty-Scanner/1.0 (Authorized Security Research)".into(),
        }
    }
}

/// Jitter determinista: aplica ±jitter_percent a `seconds`. `r` ∈ [0,1) se
/// inyecta (en producción viene de rand; en test, valores fijos). Función pura
/// → verificable. Anti-patrón: dos cooldowns nunca duran exactamente lo mismo.
pub fn jitter(seconds: f64, jitter_percent: u32, r: f64) -> f64 {
    let range = seconds * (jitter_percent as f64 / 100.0);
    // r∈[0,1) → offset∈[-range, +range)
    let offset = (r * 2.0 - 1.0) * range;
    (seconds + offset).max(0.0)
}

/// Backoff exponencial acotado: base * 2^(fallos-1), tope en `max`.
/// fallos=1 → base ; fallos=2 → 2*base ; ... hasta `max`. Función pura.
pub fn backoff(base: u64, max: u64, consecutive_failures: u32) -> u64 {
    if consecutive_failures == 0 {
        return 0;
    }
    // saturating para no desbordar con muchos fallos.
    let factor = 1u64.checked_shl(consecutive_failures - 1).unwrap_or(u64::MAX);
    base.saturating_mul(factor).min(max)
}

/// Timeout dinámico por fase de nuclei (portado): crece con hosts y nº de tags,
/// con un piso de 900 s para que una fase corta no se corte antes de tiempo.
pub fn phase_timeout(hosts: usize, tags: usize) -> u64 {
    let base = 600u64;
    let t = base + (hosts as u64) * 8 + (tags as u64) * 60;
    t.max(900)
}

/// Estado mutable de la protección durante una corrida. No es puro (cuenta
/// fallos), pero sus decisiones sí se derivan de las funciones puras de arriba.
#[derive(Debug)]
pub struct Guard {
    pub cfg: ProtectionConfig,
    consecutive_failures: u32,
    network_errors: u32,
}

impl Guard {
    pub fn new(cfg: ProtectionConfig) -> Self {
        Self { cfg, consecutive_failures: 0, network_errors: 0 }
    }

    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.network_errors = 0;
    }

    /// Registra un fallo y devuelve cuántos segundos hay que esperar (backoff).
    pub fn record_failure(&mut self) -> u64 {
        self.consecutive_failures += 1;
        backoff(
            self.cfg.failure_backoff_base,
            self.cfg.failure_backoff_max,
            self.consecutive_failures,
        )
    }

    pub fn record_network_error(&mut self) {
        self.network_errors += 1;
    }

    /// ¿Hay que pausar el escaneo por acumulación de fallos? (directiva de cierre:
    /// ante la duda, frenar; un baneo cuesta más que esperar).
    pub fn should_pause(&self) -> bool {
        self.consecutive_failures >= self.cfg.max_consecutive_failures
            || self.network_errors >= self.cfg.max_network_errors
    }

    /// Duración real de un cooldown, ya con jitter aplicado.
    pub fn cooldown(&self, seconds: u64, r: f64) -> Duration {
        Duration::from_secs_f64(jitter(seconds as f64, self.cfg.jitter_percent, r))
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }
}

/// ¿Este status HTTP es una señal de que el objetivo nos está frenando/bloqueando?
/// 429 (Too Many Requests) y 503 (Service Unavailable / WAF) son el «para» explícito.
/// NO se incluye 403: en el control de acceso un 403 es la respuesta ESPERADA de
/// un endpoint protegido, no un baneo. En un VPS COMPARTIDO, tratar el 429 como
/// éxito (como se hacía) es lo que degrada la IP de todos los proyectos.
pub fn es_senal_de_baneo(status: u16) -> bool {
    status == 429 || status == 503
}

/// Chequeo de salud de red: intenta un TCP connect a cada host de la lista.
/// Devuelve Ok(()) al primer host alcanzable; Err si todos fallan. Cruza la
/// frontera de red de verdad (directiva 28).
pub async fn check_network_health(hosts: &[String], timeout: Duration) -> crate::error::Result<()> {
    use tokio::net::TcpStream;
    for host in hosts {
        if let Ok(Ok(_)) = tokio::time::timeout(timeout, TcpStream::connect(host)).await {
            return Ok(());
        }
    }
    Err(crate::error::NexusError::NetworkDown(format!(
        "ningún host de salud alcanzable: {}",
        hosts.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_within_bounds_and_discriminates() {
        // r=0.5 → sin offset; extremos → ±20%.
        assert!((jitter(100.0, 20, 0.5) - 100.0).abs() < 1e-9);
        assert!((jitter(100.0, 20, 0.0) - 80.0).abs() < 1e-9); // -range
        assert!((jitter(100.0, 20, 1.0) - 120.0).abs() < 1e-9); // +range (r=1 teórico)
        // Discrimina: nunca negativo.
        assert_eq!(jitter(1.0, 500, 0.0), 0.0_f64.max(1.0 - 5.0));
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        assert_eq!(backoff(120, 1800, 0), 0);
        assert_eq!(backoff(120, 1800, 1), 120);
        assert_eq!(backoff(120, 1800, 2), 240);
        assert_eq!(backoff(120, 1800, 3), 480);
        assert_eq!(backoff(120, 1800, 4), 960);
        assert_eq!(backoff(120, 1800, 5), 1800); // topado (1920 → 1800)
        assert_eq!(backoff(120, 1800, 99), 1800); // sin overflow
    }

    #[test]
    fn phase_timeout_has_floor() {
        assert_eq!(phase_timeout(0, 0), 900); // piso
        assert_eq!(phase_timeout(100, 8), 600 + 800 + 480);
    }

    #[test]
    fn guard_pauses_after_threshold() {
        let mut g = Guard::new(ProtectionConfig::default());
        assert!(!g.should_pause());
        assert_eq!(g.record_failure(), 120);
        assert_eq!(g.record_failure(), 240);
        assert_eq!(g.record_failure(), 480);
        assert!(g.should_pause()); // 3 fallos
        g.record_success();
        assert!(!g.should_pause()); // reset
    }
}
