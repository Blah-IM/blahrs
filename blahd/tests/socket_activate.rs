#![expect(clippy::unwrap_used, reason = "allowed in tests")]
use std::env;
use std::mem::ManuallyDrop;
use std::net::TcpListener;
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::{net::UnixListener, process::CommandExt};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use futures_util::future::Either;
use http_body_util::BodyExt;
use hyper::StatusCode;
use libtest_mimic::{Arguments, Trial};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use rustix::process::{Pid, Signal};
use tokio::io::{AsyncRead, AsyncWrite};

const EXEC_HELPER_SENTINEL: &str = "--__exec_helper";
const WAIT_TIMEOUT: Duration = Duration::from_secs(3);
const SERVER_EXE_PATH: &str = env!("CARGO_BIN_EXE_blahd");

const CONFIG: &str = r#"
[database]
in_memory = true
[listen]
systemd = true
[server]
base_url = "http://example.com"
"#;

fn main() -> ExitCode {
    if env::args()
        .nth(1)
        .is_some_and(|s| s == EXEC_HELPER_SENTINEL)
    {
        exec_helper();
    }

    let args = Arguments::from_args();

    let tests = vec![
        Trial::test("tcp", || test_socket_activate(false)),
        Trial::test("unix", || test_socket_activate(true)),
    ];

    libtest_mimic::run(&args, tests).exit_code()
}

fn exec_helper() -> ! {
    // Don't leave an orphan process if something goes wrong.
    unsafe { libc::alarm(WAIT_TIMEOUT.as_secs() as u32 + 1) };

    let pid = rustix::process::getpid().as_raw_nonzero();
    let err = Command::new(SERVER_EXE_PATH)
        .args(env::args().skip(2))
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .env("LISTEN_PID", pid.to_string())
        .env("LISTEN_FDS", "1")
        .exec();
    panic!("failed to exec: {err}");
}

fn test_socket_activate(unix_socket: bool) -> Result<(), libtest_mimic::Failed> {
    let temp_dir = tempfile::tempdir().unwrap();

    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, CONFIG).unwrap();

    let socket_path = temp_dir.path().join("socket");
    let (local_port, listener) = if unix_socket {
        let listener = UnixListener::bind(&socket_path).unwrap();
        // Port is unused.
        (0, Either::Left(listener))
    } else {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_port = listener.local_addr().unwrap().port();
        (local_port, Either::Right(listener))
    };
    let listener_fd = match &listener {
        Either::Left(s) => s.as_fd(),
        Either::Right(s) => s.as_fd(),
    };

    // Remove CLOEXEC.
    {
        let flag = fcntl_getfd(listener_fd).unwrap();
        fcntl_setfd(listener_fd, flag - FdFlags::CLOEXEC).unwrap();
    }

    let mut cmd = Command::new(env::current_exe().unwrap());
    cmd.arg(EXEC_HELPER_SENTINEL)
        .args(["serve", "-c"])
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // SAFETY: dup2 is a syscall thus is async-signal safe.
    // `listener_fd` is alive during the pre_exec hook.
    // Fd 3 is created and not closed.
    unsafe {
        let listener_fd = std::mem::transmute::<BorrowedFd<'_>, BorrowedFd<'static>>(listener_fd);
        cmd.pre_exec(move || {
            let mut tgt_fd = ManuallyDrop::new(OwnedFd::from_raw_fd(3));
            rustix::io::dup2(listener_fd, &mut tgt_fd)?;
            Ok(())
        })
    };
    let mut child = cmd.spawn().unwrap();

    let uri = "/_blah/room?filter=public".to_owned();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let (st, resp) = rt.block_on(async {
        let fut = async move {
            match &listener {
                Either::Left(_) => {
                    let sock = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
                    send_get_request(sock, uri).await
                }
                Either::Right(_) => {
                    let sock = tokio::net::TcpStream::connect(("127.0.0.1", local_port))
                        .await
                        .unwrap();
                    send_get_request(sock, uri).await
                }
            }
        };
        tokio::time::timeout(WAIT_TIMEOUT, fut)
            .await
            .unwrap()
            .unwrap()
    });
    assert_eq!(st, StatusCode::OK);
    assert_eq!(resp, r#"{"rooms":[]}"#);

    rustix::process::kill_process(Pid::from_child(&child), Signal::TERM).unwrap();
    let st = child.wait().unwrap();
    assert!(st.success(), "unexpected exit status: {st:?}");

    Ok(())
}

// Ref: <https://github.com/seanmonstar/reqwest/issues/39#issuecomment-778716774>
async fn send_get_request(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    uri: String,
) -> anyhow::Result<(StatusCode, String)> {
    let stream = hyper_util::rt::TokioIo::new(stream);
    let (mut request_sender, connection) = hyper::client::conn::http1::Builder::new()
        .handshake(stream)
        .await?;
    tokio::task::spawn(connection);

    let request = hyper::Request::builder()
        .method("GET")
        .uri(uri)
        .header("Host", "example.com")
        .body(String::new())?;

    let response = request_sender.send_request(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    let body = String::from_utf8(body.to_vec())?;
    Ok((status, body))
}
