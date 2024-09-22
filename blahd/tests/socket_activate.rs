use std::ffi::CString;
use std::fs::File;
use std::io::{Seek, Write};
use std::net::TcpListener;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::process::abort;
use std::ptr::null;
use std::time::Duration;

use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::libc::execve;
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{alarm, dup2, fork, getpid, ForkResult};
use rstest::rstest;
use tokio::io::stderr;

const TIMEOUT_SEC: u32 = 1;

const SERVER_EXE_PATH: &str = env!("CARGO_BIN_EXE_blahd");

const CONFIG: &str = r#"
[database]
in_memory = true
[listen]
systemd = true
[server]
base_url = "http://example.com"
"#;

#[rstest]
#[case::tcp(false)]
#[case::unix(true)]
fn socket_activate(#[case] unix_socket: bool) {
    let socket_dir;
    let (local_port, listener) = if unix_socket {
        socket_dir = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(socket_dir.path().join("socket")).unwrap();
        // Port is unused.
        (0, OwnedFd::from(listener))
    } else {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_port = listener.local_addr().unwrap().port();
        (local_port, OwnedFd::from(listener))
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // Remove `FD_CLOEXEC` since we want to send it to the child.
    fn remove_cloexec(fd: &impl AsFd) {
        let mut flags =
            FdFlag::from_bits_retain(fcntl(fd.as_fd().as_raw_fd(), FcntlArg::F_GETFD).unwrap());
        flags -= FdFlag::FD_CLOEXEC;
        fcntl(fd.as_fd().as_raw_fd(), FcntlArg::F_SETFD(flags)).unwrap();
    }
    remove_cloexec(&listener);
    remove_cloexec(&stderr());

    let server_exe_c = CString::new(SERVER_EXE_PATH).unwrap();

    // Intentionally no FD_CLOEXEC.
    let mut memfd = File::from(memfd_create(c"test-config", MemFdCreateFlag::empty()).unwrap());
    memfd.write_all(CONFIG.as_bytes()).unwrap();
    memfd.rewind().unwrap();

    // Inherit environment variables.
    let envs = std::env::vars()
        .filter(|(name, _)| !name.starts_with("LISTEN_"))
        .map(|(name, value)| CString::new(format!("{name}={value}")).unwrap())
        .collect::<Vec<_>>();
    let mut env_ptrs = envs
        .iter()
        .map(|s| s.as_ptr())
        .chain([c"LISTEN_FDS=1".as_ptr(), null(), null()])
        .collect::<Vec<_>>();

    // Unfortunately we have to deal with raw `fork(2)` here, because no library supports passing
    // child PID in environment variables for child.
    // SAFETY: Between `fork()` and `execve()`, all syscalls are async-signal-safe:
    // no memory allocation, no panic unwinding (always abort).
    match unsafe { fork().unwrap() } {
        ForkResult::Child => {
            // Ideally, we want `std::panic::always_abort()`, which is unstable yet.
            // WAIT: https://github.com/rust-lang/rust/issues/84438
            scopeguard::defer!(abort());

            // Don't leave an orphan process if something does wrong.
            alarm::set(TIMEOUT_SEC);

            // Ignore all errors here to stay safe, and lazy.
            let _ = dup2(2, 1); // stdout <- stderr
            let _ = dup2(memfd.as_raw_fd(), 0); // stdin <- config memfd
            let _ = dup2(listener.as_raw_fd(), 3); // listener fd
            let args = [
                c"blahd".as_ptr(),
                c"serve".as_ptr(),
                c"-c".as_ptr(),
                c"/proc/self/fd/0".as_ptr(),
                null(),
            ];
            let mut buf = [0u8; 64];
            let _ = write!(&mut buf[..], "LISTEN_PID={}\0", getpid().as_raw());
            let pos = env_ptrs.len() - 2;
            env_ptrs[pos] = buf.as_ptr().cast();

            // NB. Do raw libc call, not the wrapper fn that does allocation inside.
            // SAFETY: Valid NULL-terminated array of NULL-terminated strings.
            unsafe {
                execve(server_exe_c.as_ptr(), args.as_ptr(), env_ptrs.as_ptr());
                // If exec fail, the drop guard will abort the process anyway. Do nothing.
            }
        }
        ForkResult::Parent { child } => {
            let guard = scopeguard::guard((), |()| {
                let _ = kill(child, Signal::SIGTERM);
            });

            if !unix_socket {
                let resp = rt.block_on(async {
                    let url = format!("http://127.0.0.1:{local_port}/_blah/room?filter=public");
                    let fut = async {
                        reqwest::get(url)
                            .await
                            .unwrap()
                            .error_for_status()
                            .unwrap()
                            .text()
                            .await
                            .unwrap()
                    };
                    tokio::time::timeout(Duration::from_secs(TIMEOUT_SEC.into()), fut)
                        .await
                        .unwrap()
                });
                assert_eq!(resp, r#"{"rooms":[]}"#);
                // Trigger the killer.
                drop(guard);
            }

            let st = waitpid(child, None).unwrap();
            let expect_exit_code = if unix_socket {
                // Fail with unsupported error.
                1
            } else {
                // Graceful shutdown.
                0
            };
            assert!(
                matches!(st, WaitStatus::Exited(_, code) if code == expect_exit_code),
                "unexpected exit status {st:?}",
            );
        }
    }
}
