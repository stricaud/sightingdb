use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

/// A stop flag background workers can wait on.
///
/// Workers sleep on the condition variable rather than polling, so shutdown is
/// immediate instead of taking up to a full interval.
#[derive(Default)]
pub struct Shutdown {
    stopped: Mutex<bool>,
    changed: Condvar,
}

impl Shutdown {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Sleep for `period`, waking early if shutdown is requested.
    /// Returns `true` if the caller should stop.
    pub fn wait(&self, period: Duration) -> bool {
        let stopped = self.stopped.lock().unwrap_or_else(PoisonError::into_inner);
        if *stopped {
            return true;
        }
        let (stopped, _) = self
            .changed
            .wait_timeout(stopped, period)
            .unwrap_or_else(PoisonError::into_inner);
        *stopped
    }

    pub fn stop(&self) {
        *self.stopped.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.changed.notify_all();
    }
}

/// Run `task` every `period` on its own thread until shutdown.
///
/// These run on plain threads rather than on the Actix runtime: the work is
/// blocking (snapshots hit the disk), and keeping it off the request runtime
/// means a slow save cannot stall request handling.
pub fn spawn_interval<F>(
    name: &str,
    period: Duration,
    shutdown: Arc<Shutdown>,
    mut task: F,
) -> std::io::Result<JoinHandle<()>>
where
    F: FnMut() + Send + 'static,
{
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            while !shutdown.wait(period) {
                task();
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    #[test]
    fn a_worker_runs_until_it_is_stopped() {
        let shutdown = Shutdown::new();
        let runs = Arc::new(AtomicUsize::new(0));

        let handle = {
            let runs = Arc::clone(&runs);
            spawn_interval(
                "test-worker",
                Duration::from_millis(10),
                Arc::clone(&shutdown),
                move || {
                    runs.fetch_add(1, Ordering::Relaxed);
                },
            )
            .unwrap()
        };

        std::thread::sleep(Duration::from_millis(120));
        shutdown.stop();
        handle.join().unwrap();

        let count = runs.load(Ordering::Relaxed);
        assert!(count >= 2, "expected several runs, got {count}");
    }

    #[test]
    fn shutdown_does_not_wait_out_the_interval() {
        let shutdown = Shutdown::new();

        let handle = spawn_interval(
            "test-slow",
            Duration::from_secs(300),
            Arc::clone(&shutdown),
            || {},
        )
        .unwrap();

        let start = Instant::now();
        shutdown.stop();
        handle.join().unwrap();

        assert!(
            start.elapsed() < Duration::from_secs(5),
            "shutdown took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn stopping_before_the_first_tick_runs_nothing() {
        let shutdown = Shutdown::new();
        let runs = Arc::new(AtomicUsize::new(0));
        shutdown.stop();

        let handle = {
            let runs = Arc::clone(&runs);
            spawn_interval(
                "test-prestopped",
                Duration::from_millis(1),
                Arc::clone(&shutdown),
                move || {
                    runs.fetch_add(1, Ordering::Relaxed);
                },
            )
            .unwrap()
        };
        handle.join().unwrap();

        assert_eq!(runs.load(Ordering::Relaxed), 0);
    }
}
