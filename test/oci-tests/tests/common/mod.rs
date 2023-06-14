use std::fs::{create_dir, File, OpenOptions, read_to_string};
use std::io::prelude::*;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use libc::SIGKILL;
use serde::{Deserialize, Serialize};
use tempfile::{TempDir, tempdir};

use oci_spec::runtime::Spec;

use containerd_shim_wasm::sandbox::instance::Wait;

use containerd_shim_wasm::sandbox::{EngineGetter, Error, Instance, InstanceConfig};
use containerd_shim_wasmedge::instance::{Wasi as WasmEdgeWasi, reset_stdio};
use containerd_shim_wasmtime::instance::Wasi as WasmtimeWasi;

#[derive(Serialize, Deserialize)]
struct Options {
    root: Option<PathBuf>,
}

pub static WASM_FILENAME: &str = "./file.wasm";

pub(crate) fn get_external_wasm_module(name: String) -> Result<Vec<u8>, Error> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let target = Path::new(manifest_dir)
        .join("../../target/wasm32-wasi/debug")
        .join(name.clone());
    std::fs::read(target).map_err(|e| {
            Error::Others(format!(
                "failed to read requested Wasm module ({}): {}. Perhaps you need to run 'make test/wasm-modules' first.",
                name, e
            ))
        })
}

fn run_wasmtime_test_with_spec(
    dir: &TempDir,
    spec: &Spec,
    wasmbytes: &[u8],
) -> Result<(u32, DateTime<Utc>), Error> {
    create_dir(dir.path().join("rootfs"))?;

    let wasm_path = dir.path().join("rootfs").join(WASM_FILENAME);
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o755)
        .open(wasm_path)?;
    f.write_all(wasmbytes)?;

    let stdout = File::create(dir.path().join("stdout"))?;
    drop(stdout);

    spec.save(dir.path().join("config.json"))?;

    let mut cfg = InstanceConfig::new(WasmtimeWasi::new_engine()?, "test_namespace".into());
    let cfg = cfg
        .set_bundle(dir.path().to_str().unwrap().to_string())
        .set_stdout(dir.path().join("stdout").to_str().unwrap().to_string());

    let wasi = Arc::new(WasmtimeWasi::new("test".to_string(), Some(cfg)));

    wasi.start()?;

    let (tx, rx) = channel();
    let waiter = Wait::new(tx);
    wasi.wait(&waiter).unwrap();

    let res = match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(res) => Ok(res),
        Err(e) => {
            wasi.kill(SIGKILL as u32).unwrap();
            return Err(Error::Others(format!(
                "error waiting for module to finish: {0}",
                e
            )));
        }
    };

    wasi.delete()?;
    res
}

fn run_wasmedge_test_with_spec(
    dir: &TempDir,
    spec: &Spec,
    wasmbytes: &[u8],
) -> Result<(u32, DateTime<Utc>), Error> {
    create_dir(dir.path().join("rootfs"))?;
    let rootdir = dir.path().join("runwasi");
    create_dir(&rootdir)?;
    let opts = Options {
        root: Some(rootdir),
    };
    let opts_file = OpenOptions::new()
        .read(true)
        .create(true)
        .truncate(true)
        .write(true)
        .open(dir.path().join("options.json"))?;
    write!(&opts_file, "{}", serde_json::to_string(&opts)?)?;

    let wasm_path = dir.path().join("rootfs").join(WASM_FILENAME);
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o755)
        .open(wasm_path)?;
    f.write_all(wasmbytes)?;

    let stdout = File::create(dir.path().join("stdout"))?;
    drop(stdout);

    spec.save(dir.path().join("config.json"))?;

    let mut cfg = InstanceConfig::new(WasmEdgeWasi::new_engine()?, "test_namespace".into());
    let cfg = cfg
        .set_bundle(dir.path().to_str().unwrap().to_string())
        .set_stdout(dir.path().join("stdout").to_str().unwrap().to_string());

    let wasi = Arc::new(WasmEdgeWasi::new("test".to_string(), Some(cfg)));

    wasi.start()?;

    let (tx, rx) = channel();
    let waiter = Wait::new(tx);
    wasi.wait(&waiter).unwrap();

    let res = match rx.recv_timeout(Duration::from_secs(600)) {
        Ok(res) => Ok(res),
        Err(e) => {
            wasi.kill(SIGKILL as u32).unwrap();
            return Err(Error::Others(format!(
                "error waiting for module to finish: {0}",
                e
            )));
        }
    };
    wasi.delete()?;
    res
}

pub(crate) fn run_wasmedge_test(spec: &Spec, bytes: &[u8]) -> Result<(String, u32), Error> {
    let dir = tempdir().unwrap();
    let path = dir.path();
    let res = run_wasmedge_test_with_spec(&dir, &spec, bytes)?;
    let output = read_to_string(path.join("stdout"))?;
    reset_stdio();
    Ok((output, res.0))
}

pub(crate) fn run_wasmtime_test(spec: &Spec, bytes: &[u8]) -> Result<(String, u32), Error> {
    let dir = tempdir().unwrap();
    let path = dir.path();
    let res = run_wasmtime_test_with_spec(&dir, &spec, bytes)?;
    let output = read_to_string(path.join("stdout"))?;
    Ok((output, res.0))
}
