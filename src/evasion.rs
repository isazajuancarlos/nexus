//! Evasión anti-baneo adaptativa. Portado y mejorado de hack/ (EvasionConfig).
//!
//! Más allá de un tope de ritmo fijo, REACCIONA a las señales de WAF/429/403:
//! cuando una etapa reporta bloqueo, `note_block()` HALVA el ritmo efectivo y
//! hace crecer un retardo entre peticiones, de modo que el reintento NO es
//! idéntico a la petición que fue bloqueada — que es justo lo que dispara los
//! baneos de IP. `note_ok()` relaja despacio hacia la línea base.
//!
//! Añade rotación de User-Agent y soporte de proxy. Las funciones de aritmética
//! adaptativa son puras y testables; el estado compartido va tras un Mutex.

use std::sync::Mutex;

/// User-Agents realistas para mimetizarse (rotados por petición/herramienta).
pub const UA_POOL: [&str; 4] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
];

// --- Aritmética adaptativa (pura, testable) ---

/// Ritmo tras un bloqueo: se halva, con piso `min_rate`.
pub fn rate_after_block(eff_rate: u32, min_rate: u32) -> u32 {
    (eff_rate / 2).max(min_rate)
}
/// Retardo extra tras un bloqueo: se duplica (arranca en 0.5), techo 10s.
pub fn delay_after_block(extra_delay: f64) -> f64 {
    (if extra_delay <= 0.0 { 0.5 } else { extra_delay } * 2.0).min(10.0)
}
/// Ritmo tras una etapa limpia: sube 1.5× hacia la base.
pub fn rate_after_ok(eff_rate: u32, base_rate: u32) -> u32 {
    if eff_rate < base_rate {
        ((eff_rate as f64 * 1.5) as u32 + 1).min(base_rate)
    } else {
        eff_rate
    }
}
/// Retardo tras una etapa limpia: baja 0.5s hacia cero.
pub fn delay_after_ok(extra_delay: f64) -> f64 {
    (extra_delay - 0.5).max(0.0)
}

#[derive(Debug)]
struct State {
    eff_rate: u32,
    extra_delay: f64,
    blocks: u64,
}

/// Controlador de evasión compartido entre recon, scan y verificación.
#[derive(Debug)]
pub struct Evasion {
    base_rate: u32,
    min_rate: u32,
    user_agent: Option<String>, // UA fijo, o None para rotar el pool
    rotate_ua: bool,
    proxy: Option<String>,
    jitter_frac: f64,
    state: Mutex<State>,
}

impl Evasion {
    pub fn new(base_rate: u32, user_agent: Option<String>, proxy: Option<String>, rotate_ua: bool, jitter_frac: f64) -> Self {
        let base = base_rate.max(1);
        Self {
            base_rate: base,
            min_rate: 10,
            user_agent,
            rotate_ua,
            proxy: proxy.or_else(|| std::env::var("HTTP_PROXY").ok()).or_else(|| std::env::var("HTTPS_PROXY").ok()),
            jitter_frac: jitter_frac.max(0.0),
            state: Mutex::new(State { eff_rate: base, extra_delay: 0.0, blocks: 0 }),
        }
    }

    pub fn eff_rate(&self) -> u32 {
        self.state.lock().unwrap().eff_rate
    }
    pub fn extra_delay(&self) -> f64 {
        self.state.lock().unwrap().extra_delay
    }
    pub fn proxy(&self) -> Option<&str> {
        self.proxy.as_deref()
    }
    pub fn blocks(&self) -> u64 {
        self.state.lock().unwrap().blocks
    }

    /// Una etapa fue bloqueada (WAF/429/403): baja ritmo y sube retardo.
    pub fn note_block(&self) {
        let mut s = self.state.lock().unwrap();
        s.blocks += 1;
        s.eff_rate = rate_after_block(s.eff_rate, self.min_rate);
        s.extra_delay = delay_after_block(s.extra_delay);
        tracing::warn!("[evasión] bloqueo #{}: ritmo→{}/s, delay→{:.1}s", s.blocks, s.eff_rate, s.extra_delay);
    }
    /// Una etapa limpia: relaja hacia la base.
    pub fn note_ok(&self) {
        let mut s = self.state.lock().unwrap();
        s.eff_rate = rate_after_ok(s.eff_rate, self.base_rate);
        s.extra_delay = delay_after_ok(s.extra_delay);
    }

    /// User-Agent para esta petición (fijo o rotado). `r` ∈ [0,1) elige del pool.
    pub fn pick_ua(&self, r: f64) -> String {
        if let Some(ua) = &self.user_agent {
            return ua.clone();
        }
        if self.rotate_ua {
            let i = ((r * UA_POOL.len() as f64) as usize).min(UA_POOL.len() - 1);
            UA_POOL[i].to_string()
        } else {
            UA_POOL[0].to_string()
        }
    }

    /// Añade ±jitter a un cooldown para que la cadencia no sea perfectamente regular.
    pub fn jittered(&self, seconds: f64, r: f64) -> f64 {
        if seconds <= 0.0 || self.jitter_frac <= 0.0 {
            return seconds.max(0.0);
        }
        let offset = (r * 2.0 - 1.0) * self.jitter_frac * seconds;
        (seconds + offset).max(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_bloqueo_halva_y_el_ok_relaja() {
        // Halva con piso 10.
        assert_eq!(rate_after_block(100, 10), 50);
        assert_eq!(rate_after_block(15, 10), 10); // 7<10 → piso
        // Delay: (extra or 0.5)*2, techo 10.  0→1, 0.5→1, 8→10.
        assert_eq!(delay_after_block(0.0), 1.0);
        assert_eq!(delay_after_block(0.5), 1.0);
        assert_eq!(delay_after_block(2.0), 4.0);
        assert_eq!(delay_after_block(8.0), 10.0); // 16→techo 10
        // OK relaja hacia base.
        assert_eq!(rate_after_ok(50, 100), 76); // 50*1.5+1
        assert_eq!(rate_after_ok(100, 100), 100); // ya en base
        assert_eq!(delay_after_ok(2.0), 1.5);
        assert_eq!(delay_after_ok(0.3), 0.0);
    }

    #[test]
    fn el_estado_reacciona_a_los_bloqueos() {
        let e = Evasion::new(200, None, None, true, 0.2);
        assert_eq!(e.eff_rate(), 200);
        e.note_block();
        assert_eq!(e.eff_rate(), 100);
        assert!(e.extra_delay() > 0.0);
        assert_eq!(e.blocks(), 1);
        e.note_ok();
        assert!(e.eff_rate() > 100); // relajó
    }

    #[test]
    fn rota_user_agent_y_respeta_fijo() {
        let rot = Evasion::new(100, None, None, true, 0.0);
        assert_eq!(rot.pick_ua(0.0), UA_POOL[0]);
        assert_eq!(rot.pick_ua(0.99), UA_POOL[3]);
        let fixed = Evasion::new(100, Some("MiUA/1.0".into()), None, true, 0.0);
        assert_eq!(fixed.pick_ua(0.5), "MiUA/1.0");
    }
}
