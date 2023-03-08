//! Generic helpers for working with OCI specs that can be consumed by any runtime.

use std::fs::{self, File};
use std::os::unix::io;
use std::os::unix::net::UnixStream;
use std::os::unix::prelude::AsRawFd;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;

use super::cgroups;
use super::error::Result;
use anyhow::Context;
use libc::{
    iovec, msghdr, recvmsg, sendmsg, CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_SPACE, SCM_RIGHTS,
    SOL_SOCKET,
};
use libcontainer::container::{ContainerProcessState, ContainerStatus, State};
use libcontainer::seccomp::{initialize_seccomp, is_notify};
use nix::{sys::signal, unistd::Pid};
pub use oci_spec::runtime::Spec;
use serde_json as json;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Write};
use std::os::unix::process::CommandExt;
use std::process;

pub fn load(path: &str) -> Result<Spec> {
    let spec = Spec::load(path)?;
    Ok(spec)
}

pub fn get_root(spec: &Spec) -> &PathBuf {
    let root = spec.root().as_ref().unwrap();
    root.path()
}

pub fn get_args(spec: &Spec) -> &[String] {
    let p = match spec.process() {
        None => return &[],
        Some(p) => p,
    };

    match p.args() {
        None => &[],
        Some(args) => args.as_slice(),
    }
}

pub fn spec_from_file<P: AsRef<Path>>(path: P) -> Result<Spec> {
    let file = File::open(path)?;
    let cfg: Spec = json::from_reader(file)?;
    Ok(cfg)
}

struct NopCgroup {}

impl cgroups::Cgroup for NopCgroup {
    fn add_task(&self, _pid: u32) -> Result<()> {
        Ok(())
    }

    fn version(&self) -> cgroups::Version {
        cgroups::Version::V1
    }

    fn apply(&self, _res: Option<cgroups::Resources>) -> Result<()> {
        Ok(())
    }

    fn delete(&self) -> Result<()> {
        Ok(())
    }
}

pub fn get_cgroup(spec: &Spec) -> Result<Box<dyn cgroups::Cgroup>> {
    let linux = spec.linux();
    if linux.is_none() {
        return Ok(Box::new(NopCgroup {}));
    }

    match linux.as_ref().unwrap().cgroups_path() {
        None => Ok(Box::new(NopCgroup {})),
        Some(p) => cgroups::new(p.display().to_string()),
    }
}

pub fn setup_cgroup(cg: &dyn cgroups::Cgroup, spec: &Spec) -> Result<()> {
    if let Some(linux) = spec.linux() {
        if let Some(res) = linux.resources() {
            cg.apply(Some(res.clone())).map_err(|e| {
                super::Error::Others(format!(
                    "error applying cgroup settings from oci spec: cgroup version {}: {}",
                    cg.version(),
                    e
                ))
            })?;
        }
    }
    Ok(())
}

pub fn receive_notify_fd<F>(socket: i32, func: F) -> Result<()>
where
    F: FnOnce(u32) -> Result<()>,
{
    // Receive seccomp notification fd over the socket, pass
    // it (along with process info) to external processing
    // entity, and respond back with a single OK.

    const DATA_SIZE: usize = unsafe { CMSG_SPACE(4) as usize };

    // CMSG operations are unsafe, and sendmsg too.
    let mut data: [u8; DATA_SIZE] = [0; DATA_SIZE];
    let mut byte: [u8; 1] = [1];

    unsafe {
        let mut iovec = iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: byte.len(),
        };

        let mut recv_msg = msghdr {
            msg_name: null_mut(),
            msg_control: data.as_mut_ptr().cast(),
            msg_namelen: 0,
            msg_flags: 0,
            msg_controllen: CMSG_LEN(4) as usize,
            msg_iov: &mut iovec,
            msg_iovlen: 1,
        };

        let mut recv_cmsg = CMSG_FIRSTHDR(&recv_msg);
        (*recv_cmsg).cmsg_level = SOL_SOCKET;
        (*recv_cmsg).cmsg_type = SCM_RIGHTS;
        (*recv_cmsg).cmsg_len = CMSG_LEN(4) as usize;

        let ret = recvmsg(socket, &mut recv_msg, 0);
        if ret < 0 {
            return Err(super::Error::Others(format!(
                "Failed to receive notification fd: {}",
                Error::last_os_error()
            )));
        }

        let buf = CMSG_DATA(recv_cmsg);
        let mut bytes: [u8; 4] = [0; 4];

        for i in 0..4 {
            bytes[i] = *(buf.offset(i as isize));
        }

        let fd = u32::from_ne_bytes(bytes);

        // Send the fd over the UDS to the external process.
        // This is a closure for easier testing.

        func(fd)?;

        // Notify the runtime that it can go forward.

        let send_msg = msghdr {
            msg_name: null_mut(),
            msg_control: null_mut(),
            msg_namelen: 0,
            msg_flags: 0,
            msg_controllen: 0,
            msg_iov: &mut iovec,
            msg_iovlen: 1,
        };

        let ret = sendmsg(socket, &send_msg, 0);
        if ret < 0 {
            return Err(super::Error::Others(format!(
                "Failed to send notification ack: {}",
                Error::last_os_error()
            )));
        }
    }

    Ok(())
}

pub fn send_notify_fd(notification_fd: i32, socket: i32) -> Result<()> {
    let mut byte: [u8; 1] = [1];

    let mut iovec = iovec {
        iov_base: byte.as_mut_ptr() as *mut _,
        iov_len: byte.len(),
    };

    unsafe {
        const DATA_SIZE: usize = unsafe { CMSG_SPACE(4) as usize };

        // CMSG operations are unsafe, and sendmsg too.
        let mut data: [u8; DATA_SIZE] = [0; DATA_SIZE];

        let send_msg = msghdr {
            msg_name: null_mut(),
            msg_control: data.as_mut_ptr().cast(),
            msg_namelen: 0,
            msg_flags: 0,
            msg_controllen: CMSG_LEN(4) as usize,
            msg_iov: &mut iovec,
            msg_iovlen: 1,
        };

        let send_cmsg = CMSG_FIRSTHDR(&send_msg);
        (*send_cmsg).cmsg_level = SOL_SOCKET;
        (*send_cmsg).cmsg_type = SCM_RIGHTS;
        (*send_cmsg).cmsg_len = CMSG_LEN(4) as usize;
        let buf = CMSG_DATA(send_cmsg);
        let bytes = u32::to_ne_bytes(notification_fd as u32);

        for (i, b) in bytes.iter().enumerate() {
            *(buf.offset(i as isize)) = *b;
        }

        let ret = sendmsg(socket, &send_msg, 0);
        if ret < 0 {
            return Err(super::Error::Others(format!(
                "Failed to send notification fd: {}",
                Error::last_os_error()
            )));
        }
    }

    // Message is sent, now wait for response.

    let mut recv_msg = msghdr {
        msg_name: null_mut(),
        msg_control: null_mut(),
        msg_namelen: 0,
        msg_flags: 0,
        msg_controllen: 0,
        msg_iov: &mut iovec,
        msg_iovlen: 1,
    };

    unsafe {
        let ret = recvmsg(socket, &mut recv_msg, 0);
        if ret < 0 {
            return Err(super::Error::Others(format!(
                "Failed to receive notification reply: {}",
                Error::last_os_error()
            )));
        }
    }

    Ok(())
}

pub fn create_container_process_state(
    spec: &Spec,
    pid: i32,
    bundle: String,
    container_id: String,
) -> Result<ContainerProcessState> {
    let b = fs::canonicalize(Path::new(&bundle))?;

    let seccomp = match spec.linux() {
        None => Err(super::Error::Others(
            "No Linux configuration in spec".to_string(),
        )),
        Some(linux) => Ok(linux.seccomp()),
    }?;

    let metadata = match seccomp {
        Some(seccomp_conf) => match seccomp_conf.listener_metadata() {
            None => "".to_string(),
            Some(metadata) => metadata.to_owned(),
        },
        None => "".to_string(),
    };

    let mut state = ContainerProcessState {
        oci_version: spec.version().to_string(),
        fds: Vec::new(),
        pid: pid,
        metadata: metadata,
        state: State::new(
            container_id.as_str(),
            ContainerStatus::Creating,
            Some(pid),
            b,
        ),
    };
    state.fds.push("seccompFd".to_string());
    Ok(state)
}

pub fn send_container_process_state_over_path(
    state: ContainerProcessState,
    notification_fd: u32,
    notify_path: PathBuf,
) -> Result<()> {
    // connect to the socket
    let sock = UnixStream::connect(notify_path)?;
    let socket_fd = sock.as_raw_fd();

    // JSON representation of the ContainerProcessState
    let mut json = serde_json::to_vec(&state)?;
    let mut iovec = iovec {
        iov_base: json.as_mut_ptr() as *mut _,
        iov_len: json.len(),
    };

    unsafe {
        const DATA_SIZE: usize = unsafe { CMSG_SPACE(4) as usize };

        // CMSG operations are unsafe, and sendmsg too.
        let mut data: [u8; DATA_SIZE] = [0; DATA_SIZE];

        let send_msg = msghdr {
            msg_name: null_mut(),
            msg_control: data.as_mut_ptr().cast(),
            msg_namelen: 0,
            msg_flags: 0,
            msg_controllen: CMSG_LEN(4) as usize,
            msg_iov: &mut iovec,
            msg_iovlen: 1,
        };

        let send_cmsg = CMSG_FIRSTHDR(&send_msg);
        (*send_cmsg).cmsg_level = SOL_SOCKET;
        (*send_cmsg).cmsg_type = SCM_RIGHTS;
        (*send_cmsg).cmsg_len = CMSG_LEN(4) as usize;
        let buf = CMSG_DATA(send_cmsg);
        let bytes = u32::to_ne_bytes(notification_fd as u32);

        for (i, b) in bytes.iter().enumerate() {
            *(buf.offset(i as isize)) = *b;
        }

        let ret = sendmsg(socket_fd, &send_msg, 0);
        if ret < 0 {
            return Err(super::Error::Others(format!(
                "Failed to send notification fd to external process: {}",
                Error::last_os_error()
            )));
        }
    }
    Ok(())
}

pub fn is_seccomp_notify(spec: &Spec) -> Result<Option<PathBuf>> {
    let seccomp = match spec.linux() {
        None => Err(super::Error::Others(
            "No Linux configuration in spec".to_string(),
        )),
        Some(linux) => Ok(linux.seccomp()),
    }?;

    match seccomp {
        None => Ok(None),
        Some(s) => match is_notify(s) {
            false => Ok(None),
            true => Ok(s.listener_path().to_owned()),
        },
    }
}

pub fn setup_seccomp(spec: &Spec) -> Result<Option<io::RawFd>> {
    let seccomp = match spec.linux() {
        None => Err(super::Error::Others(
            "No Linux configuration in spec".to_string(),
        )),
        Some(linux) => Ok(linux.seccomp()),
    }?;

    match seccomp {
        Some(seccomp_conf) => initialize_seccomp(seccomp_conf)
            .map_err(|err| super::Error::Others(format!("error initializing seccomp: {}", err))),
        None => Ok(None),
    }
}

fn parse_env(envs: &[String]) -> HashMap<String, String> {
    // make NAME=VALUE to HashMap<NAME, VALUE>.
    envs.iter()
        .filter_map(|e| {
            let mut split = e.split('=');

            split.next().map(|key| {
                let value = split.collect::<Vec<&str>>().join("=");
                (key.into(), value)
            })
        })
        .collect()
}

pub fn setup_prestart_hooks(hooks: &Option<oci_spec::runtime::Hooks>) -> Result<()> {
    if let Some(hooks) = hooks {
        let prestart_hooks = hooks.prestart().as_ref().unwrap();

        for hook in prestart_hooks {
            let mut hook_command = process::Command::new(hook.path());
            // Based on OCI spec, the first argument of the args vector is the
            // arg0, which can be different from the path.  For example, path
            // may be "/usr/bin/true" and arg0 is set to "true". However, rust
            // command differenciates arg0 from args, where rust command arg
            // doesn't include arg0. So we have to make the split arg0 from the
            // rest of args.
            if let Some((arg0, args)) = hook.args().as_ref().and_then(|a| a.split_first()) {
                log::debug!("run_hooks arg0: {:?}, args: {:?}", arg0, args);
                hook_command.arg0(arg0).args(args)
            } else {
                hook_command.arg0(&hook.path().display().to_string())
            };

            let envs: HashMap<String, String> = if let Some(env) = hook.env() {
                parse_env(env)
            } else {
                HashMap::new()
            };
            log::debug!("run_hooks envs: {:?}", envs);

            let mut hook_process = hook_command
                .env_clear()
                .envs(envs)
                .stdin(process::Stdio::piped())
                .spawn()
                .with_context(|| "Failed to execute hook")?;
            let hook_process_pid = Pid::from_raw(hook_process.id() as i32);

            if let Some(stdin) = &mut hook_process.stdin {
                // We want to ignore BrokenPipe here. A BrokenPipe indicates
                // either the hook is crashed/errored or it ran successfully.
                // Either way, this is an indication that the hook command
                // finished execution.  If the hook command was successful,
                // which we will check later in this function, we should not
                // fail this step here. We still want to check for all the other
                // error, in the case that the hook command is waiting for us to
                // write to stdin.
                let state = format!("{{ \"pid\": {} }}", std::process::id());
                if let Err(e) = stdin.write_all(state.as_bytes()) {
                    if e.kind() != ErrorKind::BrokenPipe {
                        // Not a broken pipe. The hook command may be waiting
                        // for us.
                        let _ = signal::kill(hook_process_pid, signal::Signal::SIGKILL);
                    }
                }
            }
            hook_process.wait()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod wasitest {
    use std::{
        fs,
        io::Read,
        os::unix::{
            net::UnixListener,
            prelude::{AsRawFd, FromRawFd},
        },
        sync::{Arc, Condvar, Mutex},
        thread,
    };

    use super::*;
    use libc::{socketpair, PF_LOCAL, SOCK_DGRAM};
    use oci_spec::runtime::LinuxSeccompAction::ScmpActNotify;
    use oci_spec::runtime::{
        LinuxBuilder, LinuxSeccompBuilder, LinuxSyscallBuilder, RootBuilder, SpecBuilder,
    };
    use tempfile::tempdir;

    #[test]
    fn test_notify_fd_passing() -> Result<()> {
        // Pass the notification fd over the internal socket. Test that
        // data can be written and read from the fd after it has been
        // delivered.

        fn write_to_fd(fd: u32) -> Result<()> {
            let mut file = unsafe { File::from_raw_fd(fd as i32) };
            write!(file, "Testing!")?;
            Ok(())
        }

        let mut socket_fds: [i32; 2] = [0, 0];
        unsafe {
            let ret = socketpair(PF_LOCAL, SOCK_DGRAM, 0, socket_fds.as_mut_ptr());
            assert!(ret == 0);
        }

        let dir = tempdir()?;
        let path = dir.path().join("testfile");
        let file = std::fs::File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path.clone())?;

        let fd = file.as_raw_fd();

        let _ = thread::spawn(move || {
            let res = receive_notify_fd(socket_fds[1], write_to_fd);
            assert!(!res.is_err(), "{}", format!("Error: {:?}", res));
        });

        send_notify_fd(fd, socket_fds[0])?;

        let data = fs::read_to_string(path)?;
        assert_eq!(data, "Testing!");

        Ok(())
    }

    #[test]
    fn test_notify_fd_passing_external() -> Result<()> {
        // Pass the notification fd over the internal socket (from runtime process
        // to shim process). After that create and pass the container process state
        // struct over to the "external" handler on the other side of the UDS named
        // in listenerPath.

        let rootfs_dir = tempdir()?;
        let rootfs_path = rootfs_dir.path();

        let socket_dir = tempdir()?;
        let uds_socket = socket_dir.path().join("test-uds"); // abstract unix domain socket

        let spec = SpecBuilder::default()
            .root(RootBuilder::default().path(rootfs_path).build()?)
            .linux(
                LinuxBuilder::default()
                    .seccomp(
                        LinuxSeccompBuilder::default()
                            .listener_path(uds_socket.as_path())
                            .listener_metadata("some_metadata")
                            .syscalls(vec![LinuxSyscallBuilder::default()
                                .names(vec!["ioctl".to_string()])
                                .action(ScmpActNotify)
                                .build()?])
                            .build()?,
                    )
                    .build()?,
            )
            .build()?;

        let seccomp_notify_path = is_seccomp_notify(&spec)?;
        assert!(seccomp_notify_path.is_some());

        let notify_path = seccomp_notify_path.unwrap();
        let bundle = rootfs_path.as_os_str().to_str().unwrap().to_string();
        let container_id = "container_id".to_string();
        let send_container_process_state = move |fd: u32| -> Result<()> {
            let state =
                create_container_process_state(&spec.clone(), 1234 as i32, bundle, container_id)?;
            // Send the state over to the recipient at the other end of the UDS.
            let ret = send_container_process_state_over_path(state, fd, notify_path);
            assert!(ret.is_ok());
            return ret;
        };

        let mut socket_fds: [i32; 2] = [0, 0];
        unsafe {
            let ret = socketpair(PF_LOCAL, SOCK_DGRAM, 0, socket_fds.as_mut_ptr());
            assert!(ret == 0);
        }

        // A file fd to pass over the sockets (this would be the seccomp notification fd
        // in the real world).
        let dir = tempdir()?;
        let path = dir.path().join("testfile");
        let file = std::fs::File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path.clone())?;
        let fd = file.as_raw_fd();

        // Create a condition variable to know when to finish the test.
        let condition1 = Arc::new((Mutex::new(false), Condvar::new()));
        let condition2 = Arc::clone(&condition1);

        // Start listening to the named UDS.
        let socket = UnixListener::bind(uds_socket.as_path())?;
        thread::spawn(move || {
            for conn in socket.incoming() {
                assert!(conn.is_ok());
                let mut c = conn.unwrap();
                let mut data = String::new();
                c.read_to_string(&mut data).unwrap();

                println!("{}", data);

                // Check that the container process state looks right.
                let state: ContainerProcessState = serde_json::from_str(&data).unwrap();
                assert_eq!(state.state.id, "container_id");
                assert_eq!(state.metadata, "some_metadata");

                let (lock, cvar) = &*condition2;
                let mut finished = lock.lock().unwrap();
                *finished = true;
                cvar.notify_one();
            }
        });

        let _ = thread::spawn(move || {
            let res = receive_notify_fd(socket_fds[1], send_container_process_state);
            assert!(!res.is_err(), "{}", format!("Error: {:?}", res));
        });

        send_notify_fd(fd, socket_fds[0])?;

        let (lock, cvar) = &*condition1;
        let mut finished = lock.lock().unwrap();
        while !*finished {
            finished = cvar.wait(finished).unwrap();
        }
        Ok(())
    }
}
