// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//! Filesystem calls that a stop request must not wait behind.
//!
//! The start pass and the catalog load run synchronously, so the shutdown future cannot be
//! polled while a filesystem call blocks (a FIFO, or a mount that stalls). Those calls run on a
//! helper thread that the caller bounds with a deadline and the stop flag below.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// Set by the SIGTERM and SIGINT handler that `dd-procmgrd` installs first in `main`, and by
/// the Windows service stop. Before the runtime exists, the early handler is the only one, so a
/// signal delivered earlier is kept here. tokio's handler chains to it, so the flag also rises
/// for later signals.
static STOP: AtomicBool = AtomicBool::new(false);

/// Bound for one filesystem call. The daemon runs reloads and creates in its control loop, so
/// an unbounded call there would also block gRPC until shutdown.
#[cfg(not(test))]
pub(crate) const CALL_DEADLINE: Duration = Duration::from_secs(30);
/// Shorter in unit tests, where a stalled call is exercised directly.
#[cfg(test)]
pub(crate) const CALL_DEADLINE: Duration = Duration::from_secs(2);

/// How long a path stays refused after its reader was abandoned. Refusing it forever would
/// keep a path unreadable after its file is replaced, while a retry leaves at most one stuck
/// thread per path per interval.
const RETRY_AFTER: Duration = Duration::from_secs(60);

/// How often a waiting caller checks the stop flag and the deadline.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// A reader that its caller gave up on. The thread removes the entry when its call finally
/// returns, matching on `ticket` so it never removes a newer entry for the same path.
struct Abandoned {
    path: PathBuf,
    ticket: u64,
    since: Instant,
}

static ABANDONED: Mutex<Vec<Abandoned>> = Mutex::new(Vec::new());
static NEXT_TICKET: AtomicU64 = AtomicU64::new(0);

/// Records a stop request. Only an atomic store, so it is safe inside a signal handler.
pub(crate) fn request_stop() {
    STOP.store(true, Ordering::SeqCst);
}

/// Whether a stop request has arrived.
pub(crate) fn stop_requested_flag() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// Reads a config or environment file without outliving a stop request or [`CALL_DEADLINE`].
pub(crate) fn read_config_to_string(path: &Path) -> io::Result<String> {
    let owned = path.to_path_buf();
    bounded(path, move || std::fs::read_to_string(owned)).and_then(|result| result)
}

/// Runs a filesystem call for `path` on a helper thread, and waits for it for at most
/// [`CALL_DEADLINE`], or until a stop request. A call that gives up leaves its thread blocked,
/// and `path` is then refused for a while. A refusal, a timeout and a stop each return an error
/// that callers must treat as a hold, not as a missing file.
pub(crate) fn bounded<T: Send + 'static>(
    path: &Path,
    op: impl FnOnce() -> T + Send + 'static,
) -> io::Result<T> {
    bounded_with(path, CALL_DEADLINE, RETRY_AFTER, &STOP, op)
}

fn lock_abandoned() -> MutexGuard<'static, Vec<Abandoned>> {
    ABANDONED.lock().unwrap_or_else(PoisonError::into_inner)
}

fn bounded_with<T: Send + 'static>(
    path: &Path,
    deadline: Duration,
    retry_after: Duration,
    stop: &AtomicBool,
    op: impl FnOnce() -> T + Send + 'static,
) -> io::Result<T> {
    if stop.load(Ordering::SeqCst) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            format!("{}: stop requested, not reading", path.display()),
        ));
    }
    {
        let mut abandoned = lock_abandoned();
        abandoned.retain(|a| a.since.elapsed() < retry_after);
        if abandoned.iter().any(|a| a.path == path) {
            // TimedOut, not Other: callers treat every stall the same way, and this is one.
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "{}: an earlier read is still blocked, not starting another",
                    path.display()
                ),
            ));
        }
    }

    let (tx, rx) = mpsc::channel();
    let ticket = NEXT_TICKET.fetch_add(1, Ordering::SeqCst);
    thread::Builder::new()
        .name("fs-call".to_string())
        .spawn(move || {
            let result = op();
            // The lock is held across the send. A caller that gives up takes the same lock
            // before it records its entry, so it cannot record one for a call that finished.
            let mut abandoned = lock_abandoned();
            abandoned.retain(|a| a.ticket != ticket);
            let _ = tx.send(result);
        })?;

    let started = Instant::now();
    loop {
        match rx.recv_timeout(POLL_INTERVAL) {
            Ok(result) => return Ok(result),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other(format!(
                    "{}: reader thread ended without a result",
                    path.display()
                )));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let stopping = stop.load(Ordering::SeqCst);
                if !stopping && started.elapsed() < deadline {
                    continue;
                }
                let mut abandoned = lock_abandoned();
                // A result sent since the last poll wins over giving up. A reader that died
                // (a panic in `op`) never removes its entry, so it must not be recorded.
                match rx.try_recv() {
                    Ok(result) => return Ok(result),
                    Err(mpsc::TryRecvError::Disconnected) => {
                        return Err(io::Error::other(format!(
                            "{}: reader thread ended without a result",
                            path.display()
                        )));
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                }
                abandoned.push(Abandoned {
                    path: path.to_path_buf(),
                    ticket,
                    since: Instant::now(),
                });
                return Err(if stopping {
                    io::Error::new(
                        io::ErrorKind::Interrupted,
                        format!("{}: stop requested while reading", path.display()),
                    )
                } else {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("{}: no result within {deadline:?}", path.display()),
                    )
                });
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Arc;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("procmgr-stop-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mkfifo(path: &Path) {
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { nix::libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");
    }

    fn read(path: &Path, deadline: Duration, stop: &AtomicBool) -> io::Result<String> {
        let owned = path.to_path_buf();
        bounded_with(path, deadline, RETRY_AFTER, stop, move || {
            std::fs::read_to_string(owned)
        })
        .and_then(|result| result)
    }

    #[test]
    fn reads_a_regular_file() {
        let dir = scratch("regular");
        let file = dir.join("cfg.yaml");
        fs::write(&file, "command: /bin/true\n").unwrap();
        let stop = AtomicBool::new(false);
        assert_eq!(
            read(&file, Duration::from_secs(5), &stop).unwrap(),
            "command: /bin/true\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stop_already_requested_starts_no_call() {
        let stop = AtomicBool::new(true);
        let ran = Arc::new(AtomicBool::new(false));
        let ran_in_call = Arc::clone(&ran);
        let err = bounded_with(
            Path::new("/unused"),
            Duration::from_secs(5),
            RETRY_AFTER,
            &stop,
            move || ran_in_call.store(true, Ordering::SeqCst),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted, "{err}");
        assert!(!ran.load(Ordering::SeqCst), "the call must not run");
    }

    #[test]
    fn a_stop_interrupts_a_blocked_read() {
        let dir = scratch("interrupt");
        let fifo = dir.join("gate.fifo");
        mkfifo(&fifo);
        let stop = Arc::new(AtomicBool::new(false));
        let raiser = Arc::clone(&stop);
        let raise = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            raiser.store(true, Ordering::SeqCst);
        });
        let started = Instant::now();
        let err = read(&fifo, Duration::from_secs(30), &stop).unwrap_err();
        raise.join().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted, "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_finished_stalled_read_clears_its_entry() {
        let dir = scratch("clears");
        let fifo = dir.join("stalled.fifo");
        mkfifo(&fifo);
        let stop = AtomicBool::new(false);

        let err = read(&fifo, Duration::from_millis(100), &stop).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
        assert!(lock_abandoned().iter().any(|a| a.path == fifo));

        // Opening the writer returns the reader's open, and dropping it after a short hold gives
        // the reader EOF. A single reader released this way is reliable on macOS too.
        let writer = fs::OpenOptions::new().write(true).open(&fifo).unwrap();
        thread::sleep(Duration::from_millis(300));
        drop(writer);
        let deadline = Instant::now() + Duration::from_secs(10);
        while lock_abandoned().iter().any(|a| a.path == fifo) {
            assert!(Instant::now() < deadline, "entry was never cleared");
            thread::sleep(Duration::from_millis(20));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_refused_path_is_read_again_after_the_retry_interval() {
        let dir = scratch("retry");
        let path = dir.join("gate.yaml");
        mkfifo(&path);
        let stop = AtomicBool::new(false);
        let retry = Duration::from_millis(400);

        // This reader stays blocked on the FIFO inode. The point is that the path is refused
        // while it is stuck, then readable once the file is replaced. The refusal is a
        // TimedOut, so a caller treats it as a stall.
        let owned = path.clone();
        let err = bounded_with(&path, Duration::from_millis(100), retry, &stop, move || {
            std::fs::read_to_string(owned)
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
        let err = bounded_with(&path, Duration::from_secs(30), retry, &stop, || ()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
        assert!(err.to_string().contains("still blocked"), "{err}");

        fs::remove_file(&path).unwrap();
        fs::write(&path, "command: /bin/true\n").unwrap();
        thread::sleep(retry + Duration::from_millis(50));
        let owned = path.clone();
        let contents = bounded_with(&path, Duration::from_secs(5), retry, &stop, move || {
            std::fs::read_to_string(owned)
        })
        .and_then(|result| result)
        .unwrap();
        assert_eq!(contents, "command: /bin/true\n");
        let _ = fs::remove_dir_all(&dir);
    }
}
