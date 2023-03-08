use std::fs::OpenOptions;
use std::path::Path;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use anyhow::Context;
use chrono::{DateTime, Utc};
use containerd_shim_wasm::sandbox::error::Error;
use containerd_shim_wasm::sandbox::exec;
use containerd_shim_wasm::sandbox::oci;
use containerd_shim_wasm::sandbox::{EngineGetter, Instance, InstanceConfig};
use log::{debug, error};
use nix::libc::{socketpair, AF_UNIX, SOCK_DGRAM};
use nix::sys::signal::SIGKILL;
use wasmtime::{Engine, Linker, Module, Store};
use wasmtime_wasi::{sync::file::File as WasiFile, WasiCtx, WasiCtxBuilder};

use super::error::WasmtimeError;
use super::oci_wasmtime;

type ExitCode = (Mutex<Option<(u32, DateTime<Utc>)>>, Condvar);
pub struct Wasi {
    exit_code: Arc<ExitCode>,
    engine: wasmtime::Engine,

    stdin: String,
    stdout: String,
    stderr: String,
    bundle: String,

    pidfd: Arc<Mutex<Option<exec::PidFD>>>,
    container_id: String,
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_maybe_open_stdio() -> Result<(), Error> {
        let f = maybe_open_stdio("")?;
        assert!(f.is_none());

        let f = maybe_open_stdio("/some/nonexistent/path")?;
        assert!(f.is_none());

        let dir = tempdir()?;
        let temp = File::create(dir.path().join("testfile"))?;
        drop(temp);
        let f = maybe_open_stdio(dir.path().join("testfile").as_path().to_str().unwrap())?;
        assert!(f.is_some());
        drop(f);

        Ok(())
    }
}

/// containerd can send an empty path or a non-existant path
/// In both these cases we should just assume that the stdio stream was not setup (intentionally)
/// Any other error is a real error.
pub fn maybe_open_stdio(path: &str) -> Result<Option<WasiFile>, Error> {
    if path.is_empty() {
        return Ok(None);
    }
    match oci_wasmtime::wasi_file(path, OpenOptions::new().read(true).write(true)) {
        Ok(f) => Ok(Some(f)),
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => Ok(None),
            _ => Err(err.into()),
        },
    }
}

fn load_spec(bundle: String) -> Result<oci::Spec, Error> {
    let mut spec = oci::load(Path::new(&bundle).join("config.json").to_str().unwrap())?;
    spec.canonicalize_rootfs(&bundle)
        .map_err(|e| Error::Others(format!("error canonicalizing rootfs in spec: {}", e)))?;
    Ok(spec)
}

pub fn prepare_module(
    engine: wasmtime::Engine,
    spec: &oci::Spec,
    stdin_path: String,
    stdout_path: String,
    stderr_path: String,
) -> Result<(WasiCtx, Module), WasmtimeError> {
    debug!("opening rootfs");
    let rootfs = oci_wasmtime::get_rootfs(spec)?;
    let args = oci::get_args(spec);
    let env = oci_wasmtime::env_to_wasi(spec);

    debug!("setting up wasi");
    let mut wasi_builder = WasiCtxBuilder::new()
        .args(args)?
        .envs(env.as_slice())?
        .preopened_dir(rootfs, "/")?;

    debug!("opening stdin");
    let stdin = maybe_open_stdio(&stdin_path).context("could not open stdin")?;
    if let Some(sin) = stdin {
        wasi_builder = wasi_builder.stdin(Box::new(sin));
    }

    debug!("opening stdout");
    let stdout = maybe_open_stdio(&stdout_path).context("could not open stdout")?;
    if let Some(sout) = stdout {
        wasi_builder = wasi_builder.stdout(Box::new(sout));
    }

    debug!("opening stderr");
    let stderr = maybe_open_stdio(&stderr_path).context("could not open stderr")?;
    if let Some(serr) = stderr {
        wasi_builder = wasi_builder.stderr(Box::new(serr));
    }

    debug!("building wasi context");
    let wctx = wasi_builder.build();
    debug!("wasi context ready");

    let mut cmd = args[0].clone();
    let stripped = args[0].strip_prefix(std::path::MAIN_SEPARATOR);
    if let Some(strpd) = stripped {
        cmd = strpd.to_string();
    }

    let mod_path = oci::get_root(spec).join(cmd);

    debug!("loading module from file");
    let module = Module::from_file(&engine, mod_path)
        .map_err(|err| Error::Others(format!("could not load module from file: {}", err)))?;

    Ok((wctx, module))
}

impl Instance for Wasi {
    type E = wasmtime::Engine;
    fn new(id: String, cfg: Option<&InstanceConfig<Self::E>>) -> Self {
        let cfg = cfg.unwrap(); // TODO: handle error
        Wasi {
            exit_code: Arc::new((Mutex::new(None), Condvar::new())),
            engine: cfg.get_engine(),
            stdin: cfg.get_stdin().unwrap_or_default(),
            stdout: cfg.get_stdout().unwrap_or_default(),
            stderr: cfg.get_stderr().unwrap_or_default(),
            bundle: cfg.get_bundle().unwrap_or_default(),
            pidfd: Arc::new(Mutex::new(None)),
            container_id: id,
        }
    }
    fn start(&self) -> Result<u32, Error> {
        let engine = self.engine.clone();
        let stdin = self.stdin.clone();
        let stdout = self.stdout.clone();
        let stderr = self.stderr.clone();

        debug!("starting instance");
        let mut linker = Linker::new(&engine);

        wasmtime_wasi::add_to_linker(&mut linker, |s| s)
            .map_err(|err| Error::Others(format!("error adding to linker: {}", err)))?;

        debug!("preparing module");
        let spec = load_spec(self.bundle.clone())?;

        let m = prepare_module(engine.clone(), &spec, stdin, stdout, stderr)
            .map_err(|e| Error::Others(format!("error setting up module: {}", e)))?;

        let mut store = Store::new(&engine, m.0);

        debug!("instantiating instance");
        let i = linker
            .instantiate(&mut store, &m.1)
            .map_err(|err| Error::Others(format!("error instantiating module: {}", err)))?;

        debug!("getting start function");
        let f = i.get_func(&mut store, "_start").ok_or_else(|| {
            Error::InvalidArgument("module does not have a wasi start function".to_string())
        })?;

        debug!("starting wasi instance");

        let cg = oci::get_cgroup(&spec)?;

        oci::setup_cgroup(cg.as_ref(), &spec)
            .map_err(|e| Error::Others(format!("error setting up cgroups: {}", e)))?;

        // Create a socket pair for handling the seccomp data transfer.
        let mut fds: [i32; 2] = [0, 0];
        unsafe {
            let ret = socketpair(AF_UNIX, SOCK_DGRAM, 0, fds.as_mut_ptr());
            if ret != 0 {
                return Err(Error::Others("Error calling socketpair".to_string()));
            }
        }

        let res = unsafe { exec::fork(Some(cg.as_ref())) }?;
        match res {
            exec::Context::Parent(tid, pidfd) => {
                let mut lr = self.pidfd.lock().unwrap();
                *lr = Some(pidfd.clone());

                debug!("started wasi instance with tid {}", tid);

                let code = self.exit_code.clone();

                let _ = thread::spawn(move || {
                    let (lock, cvar) = &*code;
                    let status = match pidfd.wait() {
                        Ok(status) => status,
                        Err(e) => {
                            error!("error waiting for pid {}: {}", tid, e);
                            cvar.notify_all();
                            return;
                        }
                    };

                    debug!("wasi instance exited with status {}", status.status);
                    let mut ec = lock.lock().unwrap();
                    *ec = Some((status.status, Utc::now()));
                    drop(ec);
                    cvar.notify_all();
                });
                if let Some(notify_path) = oci::is_seccomp_notify(&spec)? {
                    // This is only needed if client is going to send
                    // the seccomp notify fd.
                    let bundle = self.bundle.clone();
                    let container_id = self.container_id.clone();
                    let _ = thread::spawn(move || {
                        let send_container_process_state = |fd: u32| -> Result<(), Error> {
                            let state = oci::create_container_process_state(
                                &spec,
                                tid as i32,
                                bundle,
                                container_id,
                            )?;
                            // Send the state over to the recipient at the other end of the UDS.
                            oci::send_container_process_state_over_path(state, fd, notify_path)
                        };

                        let res = oci::receive_notify_fd(fds[1], send_container_process_state);
                        if res.is_err() {
                            error!("error receiving notify fd!");
                        }
                    });
                }
                Ok(tid)
            }
            exec::Context::Child => {
                // child process

                // Setup the seccomp filter.
                let notification_fd = oci::setup_seccomp(&spec);
                match notification_fd {
                    Ok(Some(fd)) => {
                        // There is an external approver process
                        // for seccomp requests. We need to send the
                        // notification fd over to the main process, so
                        // that it can in turn send the container process
                        // state over.

                        // Send seccomp notify fd to the main process. This
                        // is a synchronous call -- we need to wait for an ack
                        // for the seccomp external processing to be ready.
                        if oci::send_notify_fd(fd, fds[0]).is_err() {
                            std::process::exit(137);
                        }
                    }
                    Ok(None) => {
                        // There was no external processing for any seccomp action
                        // -- no need to do anything special.
                    }
                    Err(_) => std::process::exit(137),
                };

                // TODO: How to get exit code?
                // This was relatively straight forward in go, but wasi and wasmtime are totally separate things in rust.
                let _ret = match f.call(&mut store, &[], &mut []) {
                    Ok(_) => std::process::exit(0),
                    Err(_) => std::process::exit(137),
                };
            }
        }
    }

    fn kill(&self, signal: u32) -> Result<(), Error> {
        if signal != SIGKILL as u32 {
            return Err(Error::InvalidArgument(
                "only SIGKILL is supported".to_string(),
            ));
        }

        let lr = self.pidfd.lock().unwrap();
        let fd = lr
            .as_ref()
            .ok_or_else(|| Error::FailedPrecondition("module is not running".to_string()))?;
        fd.kill(signal as i32)
    }

    fn delete(&self) -> Result<(), Error> {
        let spec = match load_spec(self.bundle.clone()) {
            Ok(spec) => spec,
            Err(err) => {
                error!("Could not load spec, skipping cgroup cleanup: {}", err);
                return Ok(());
            }
        };
        let cg = oci::get_cgroup(&spec)?;
        cg.delete()?;
        Ok(())
    }

    fn wait(&self, channel: Sender<(u32, DateTime<Utc>)>) -> Result<(), Error> {
        let code = self.exit_code.clone();
        thread::spawn(move || {
            let (lock, cvar) = &*code;
            let mut exit = lock.lock().unwrap();
            while (*exit).is_none() {
                exit = cvar.wait(exit).unwrap();
            }
            let ec = (*exit).unwrap();
            channel.send(ec).unwrap();
        });

        Ok(())
    }
}

#[cfg(test)]
mod wasitest {
    use std::borrow::Cow;
    use std::fs::{create_dir, read_to_string, File};
    use std::io::prelude::*;
    use std::sync::mpsc::channel;
    use std::time::Duration;

    use libc::{prctl, PR_SET_NO_NEW_PRIVS};
    use oci_spec::runtime::{
        LinuxBuilder, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder, ProcessBuilder,
        RootBuilder, Spec, SpecBuilder,
    };
    use tempfile::{tempdir, TempDir};

    use super::*;

    // This is taken from https://github.com/bytecodealliance/wasmtime/blob/6a60e8363f50b936e4c4fc958cb9742314ff09f3/docs/WASI-tutorial.md?plain=1#L270-L298
    const WASI_HELLO_WAT: &[u8]= r#"(module
        ;; Import the required fd_write WASI function which will write the given io vectors to stdout
        ;; The function signature for fd_write is:
        ;; (File Descriptor, *iovs, iovs_len, nwritten) -> Returns number of bytes written
        (import "wasi_unstable" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))

        (memory 1)
        (export "memory" (memory 0))

        ;; Write 'hello world\n' to memory at an offset of 8 bytes
        ;; Note the trailing newline which is required for the text to appear
        (data (i32.const 8) "hello world\n")

        (func $main (export "_start")
            ;; Creating a new io vector within linear memory
            (i32.store (i32.const 0) (i32.const 8))  ;; iov.iov_base - This is a pointer to the start of the 'hello world\n' string
            (i32.store (i32.const 4) (i32.const 12))  ;; iov.iov_len - The length of the 'hello world\n' string

            (call $fd_write
                (i32.const 1) ;; file_descriptor - 1 for stdout
                (i32.const 0) ;; *iovs - The pointer to the iov array, which is stored at memory location 0
                (i32.const 1) ;; iovs_len - We're printing 1 string stored in an iov - so one.
                (i32.const 20) ;; nwritten - A place in memory to store the number of bytes written
            )
            drop ;; Discard the number of bytes written from the top of the stack
        )
    )
    "#.as_bytes();

    #[test]
    fn test_delete_after_create() {
        let i = Wasi::new(
            "".to_string(),
            Some(&InstanceConfig::new(Engine::default())),
        );
        i.delete().unwrap();
    }

    fn get_external_wasm_module(name: String) -> Result<Vec<u8>, Error> {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let target = Path::new(manifest_dir)
            .join("../../target/wasm32-wasi/debug")
            .join(name.clone());
        let ret = std::fs::read(target).map_err(|e| {
            super::Error::Others(format!(
                "failed to read requested Wasm module ({}): {}",
                name, e
            ))
        });
        return ret;
    }

    fn run_wasi_test_with_spec(
        dir: &TempDir,
        spec: &Spec,
        wasmbytes: Cow<[u8]>,
    ) -> Result<(u32, DateTime<Utc>), Error> {
        create_dir(dir.path().join("rootfs"))?;

        let mut f = File::create(dir.path().join("rootfs/file.wasm"))?;
        f.write_all(&wasmbytes)?;

        let stdout = File::create(dir.path().join("stdout"))?;
        drop(stdout);

        spec.save(dir.path().join("config.json"))?;

        let mut cfg = InstanceConfig::new(Wasi::new_engine()?);
        let cfg = cfg
            .set_bundle(dir.path().to_str().unwrap().to_string())
            .set_stdout(dir.path().join("stdout").to_str().unwrap().to_string());

        let wasi = Arc::new(Wasi::new("test".to_string(), Some(cfg)));

        wasi.start()?;

        let w = wasi.clone();
        let (tx, rx) = channel();
        thread::spawn(move || {
            w.wait(tx).unwrap();
        });

        let res = match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(res) => Ok(res),
            Err(e) => {
                wasi.kill(SIGKILL as u32).unwrap();
                return Err(Error::Others(format!(
                    "error waiting for module to finish: {0}",
                    e
                )));
            }
        };
        return res;
    }

    fn run_wasi_test(dir: &TempDir, wasmbytes: Cow<[u8]>) -> Result<(u32, DateTime<Utc>), Error> {
        let spec = SpecBuilder::default()
            .root(RootBuilder::default().path("rootfs").build()?)
            .process(
                ProcessBuilder::default()
                    .cwd("/")
                    .args(vec!["file.wasm".to_string()])
                    .build()?,
            )
            .build()?;

        run_wasi_test_with_spec(dir, &spec, wasmbytes)
    }

    #[test]
    fn test_wasi_with_external_hello_world() -> Result<(), Error> {
        let dir = tempdir()?;
        let path = dir.path();

        let wasmbytes = get_external_wasm_module("hello-world.wasm".to_string())?;
        let res = run_wasi_test(&dir, Cow::from(wasmbytes))?;

        assert_eq!(res.0, 0);

        let output = read_to_string(path.join("stdout"))?;
        assert_eq!(output, "hello world\n");

        Ok(())
    }

    #[test]
    fn test_seccomp_hello_world_pass() -> Result<(), Error> {
        let dir = tempdir()?;
        let path = dir.path();

        let wasmbytes = get_external_wasm_module("hello-world.wasm".to_string())?;
        unsafe {
            // seccomp requires either set_no_new_privs bit set or CAP_SYS_ADMIN.
            let ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            assert!(ret == 0);
        }

        // Logged syscalls: 20, 16, 131, 11, 231

        let spec = SpecBuilder::default()
            .root(RootBuilder::default().path("rootfs").build()?)
            .process(
                ProcessBuilder::default()
                    .cwd("/")
                    .args(vec!["file.wasm".to_string()])
                    .build()?,
            )
            .linux(
                LinuxBuilder::default()
                    .seccomp(
                        LinuxSeccompBuilder::default()
                            .default_action(LinuxSeccompAction::ScmpActAllow)
                            .architectures(vec![oci_spec::runtime::Arch::ScmpArchNative])
                            .syscalls(vec![LinuxSyscallBuilder::default()
                                .names(vec!["fcntl".to_string()]) // system call 72
                                .action(LinuxSeccompAction::ScmpActKillProcess)
                                .build()?])
                            .build()?,
                    )
                    .build()?,
            )
            .build()?;

        let res = run_wasi_test_with_spec(&dir, &spec, Cow::from(wasmbytes))?;

        assert_eq!(res.0, 0);

        let output = read_to_string(path.join("stdout"))?;
        assert_eq!(output, "hello world\n");

        Ok(())
    }

    #[test]
    fn test_seccomp_hello_world_fail() -> Result<(), Error> {
        let dir = tempdir()?;

        let wasmbytes = get_external_wasm_module("hello-world.wasm".to_string())?;
        unsafe {
            // seccomp requires either set_no_new_privs bit set or CAP_SYS_ADMIN.
            let ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            assert!(ret == 0);
        }

        // Logged syscalls: 20, 16, 131, 11, 231

        let spec = SpecBuilder::default()
            .root(RootBuilder::default().path("rootfs").build()?)
            .process(
                ProcessBuilder::default()
                    .cwd("/")
                    .args(vec!["file.wasm".to_string()])
                    .build()?,
            )
            .linux(
                LinuxBuilder::default()
                    .seccomp(
                        LinuxSeccompBuilder::default()
                            .default_action(LinuxSeccompAction::ScmpActAllow)
                            .architectures(vec![oci_spec::runtime::Arch::ScmpArchNative])
                            .syscalls(vec![LinuxSyscallBuilder::default()
                                .names(vec!["writev".to_string()]) // system call 20
                                .action(LinuxSeccompAction::ScmpActErrno)
                                .build()?])
                            .build()?,
                    )
                    .build()?,
            )
            .build()?;

        let res = run_wasi_test_with_spec(&dir, &spec, Cow::from(wasmbytes))?;

        assert_eq!(res.0, 137); // Returns an error

        Ok(())
    }

    #[ignore]
    #[test]
    fn test_seccomp_hello_world_notify() -> Result<(), Error> {
        // Test how seccomp works together with an external notification agent.
        // Configure the external agent to use socket /tmp/seccomp-agent.socket
        // and set it to either allow or decline (with error) "writev" system
        // call.

        let dir = tempdir()?;

        let wasmbytes = get_external_wasm_module("hello-world.wasm".to_string())?;
        unsafe {
            // seccomp requires either set_no_new_privs bit set or CAP_SYS_ADMIN.
            let ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            assert!(ret == 0);
        }

        // Logged syscalls: 20, 16, 131, 11, 231

        let spec = SpecBuilder::default()
            .root(RootBuilder::default().path("rootfs").build()?)
            .process(
                ProcessBuilder::default()
                    .cwd("/")
                    .args(vec!["file.wasm".to_string()])
                    .build()?,
            )
            .linux(
                LinuxBuilder::default()
                    .seccomp(
                        LinuxSeccompBuilder::default()
                            .default_action(LinuxSeccompAction::ScmpActAllow)
                            .architectures(vec![oci_spec::runtime::Arch::ScmpArchNative])
                            .syscalls(vec![LinuxSyscallBuilder::default()
                                .names(vec!["writev".to_string()]) // system call 20
                                .action(LinuxSeccompAction::ScmpActNotify)
                                .build()?])
                            .listener_path("/tmp/seccomp-agent.socket")
                            .build()?,
                    )
                    .build()?,
            )
            .build()?;

        let res = run_wasi_test_with_spec(&dir, &spec, Cow::from(wasmbytes))?;

        assert_eq!(res.0, 0); // Returns success or error, depending on how the external agent is configured

        Ok(())
    }

    #[test]
    fn test_wasi() -> Result<(), Error> {
        let dir = tempdir()?;
        create_dir(dir.path().join("rootfs"))?;

        let mut f = File::create(dir.path().join("rootfs/hello.wat"))?;
        f.write_all(WASI_HELLO_WAT)?;

        let stdout = File::create(dir.path().join("stdout"))?;
        drop(stdout);

        let spec = SpecBuilder::default()
            .root(RootBuilder::default().path("rootfs").build()?)
            .process(
                ProcessBuilder::default()
                    .cwd("/")
                    .args(vec!["hello.wat".to_string()])
                    .build()?,
            )
            .build()?;

        spec.save(dir.path().join("config.json"))?;

        let mut cfg = InstanceConfig::new(Engine::default());
        let cfg = cfg
            .set_bundle(dir.path().to_str().unwrap().to_string())
            .set_stdout(dir.path().join("stdout").to_str().unwrap().to_string());

        let wasi = Arc::new(Wasi::new("test".to_string(), Some(cfg)));

        wasi.start()?;

        let w = wasi.clone();
        let (tx, rx) = channel();
        thread::spawn(move || {
            w.wait(tx).unwrap();
        });

        let res = match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(res) => res,
            Err(e) => {
                wasi.kill(SIGKILL as u32).unwrap();
                return Err(Error::Others(format!(
                    "error waiting for module to finish: {0}",
                    e
                )));
            }
        };
        assert_eq!(res.0, 0);

        let output = read_to_string(dir.path().join("stdout"))?;
        assert_eq!(output, "hello world\n");

        Ok(())
    }
}

impl EngineGetter for Wasi {
    type E = wasmtime::Engine;
    fn new_engine() -> Result<Engine, Error> {
        let engine = Engine::default();
        Ok(engine)
    }
}
