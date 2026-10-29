//! Cooperative cancellation and small threading helpers.
//!
//! Jobs, model streams and subagents all need to be interruptible without
//! depending on async runtimes: a shared atomic flag is checked by I/O loops
//! that use short socket timeouts.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::{bail, Result};

#[derive(Debug, Clone, Default)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
}

impl CancelToken {
    pub fn new() -> Self {
        CancelToken {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Reset for reuse (e.g. when the user presses Ctrl+C once and continues).
    pub fn reset(&self) {
        self.flag.store(false, Ordering::SeqCst);
    }

    /// Convenience for loops: returns Err if cancellation was requested.
    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            bail!("cancelled");
        }
        Ok(())
    }
}

/// A deadline that can be shared with worker code.
#[derive(Debug, Clone)]
pub struct Deadline {
    start: Instant,
    limit: Duration,
}

impl Deadline {
    pub fn new(limit: Duration) -> Self {
        Deadline {
            start: Instant::now(),
            limit,
        }
    }

    pub fn expired(&self) -> bool {
        self.start.elapsed() >= self.limit
    }

    pub fn remaining(&self) -> Duration {
        self.limit.saturating_sub(self.start.elapsed())
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn check(&self) -> Result<()> {
        if self.expired() {
            bail!(
                "timed out after {}",
                crate::time::fmt_duration_ms(self.limit.as_millis() as u64)
            );
        }
        Ok(())
    }
}

/// Lock a mutex, recovering from poisoning (a panic in a worker thread must not
/// take down the interactive session).
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Spawn a named thread, falling back to an unnamed one on platforms that
/// reject empty/odd names.
pub fn spawn_named<F>(name: impl Into<String>, f: F) -> std::io::Result<std::thread::JoinHandle<()>>
where
    F: FnOnce() + Send + 'static,
{
    let name = name.into();
    std::thread::Builder::new().name(name).spawn(f)
}

/// A monotonically increasing sequence for ids within a process.
pub fn next_id() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_is_observable() {
        let t = CancelToken::new();
        assert!(!t.is_cancelled());
        assert!(t.check().is_ok());
        let t2 = t.clone();
        t2.cancel();
        assert!(t.is_cancelled());
        assert!(t.check().is_err());
        t.reset();
        assert!(!t.is_cancelled());
    }

    #[test]
    fn deadline_expires() {
        let d = Deadline::new(Duration::from_millis(10));
        assert!(!d.expired());
        std::thread::sleep(Duration::from_millis(20));
        assert!(d.expired());
        assert!(d.check().is_err());
    }

    #[test]
    fn poisoned_mutex_is_recovered() {
        let m = Arc::new(Mutex::new(1u32));
        let m2 = m.clone();
        let _ = std::thread::spawn(move || {
            let _g = m2.lock().unwrap();
            panic!("boom");
        })
        .join();
        *lock(&m) += 1;
        assert_eq!(*lock(&m), 2);
    }
}
