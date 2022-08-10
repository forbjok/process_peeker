mod address;
mod module;
mod process;
mod win32util;

use std::{cell::RefCell, mem, rc::Rc, time::Duration};

use byteorder::{ByteOrder, LittleEndian};
use process::ConnectedProcess;
use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt};
use tracing::debug;
use winapi::{
    shared::minwindef::FALSE,
    um::{
        processthreadsapi::OpenProcess,
        winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

use self::process::Process;

pub type AddressPointer = u64;
pub use self::address::Address;

const PTR_SIZE: usize = mem::size_of::<AddressPointer>();

pub fn connect<F, R>(name: &str, mut f: F) -> Result<R, anyhow::Error>
where
    F: FnMut(ConnectedProcess) -> Result<R, anyhow::Error>,
{
    loop {
        if let Ok(v) = try_connect(name, &mut f) {
            return v;
        }

        std::thread::sleep(Duration::from_secs(5));
    }
}

pub fn try_connect<F, R>(name: &str, mut f: F) -> Result<Result<R, anyhow::Error>, anyhow::Error>
where
    F: FnMut(ConnectedProcess) -> Result<R, anyhow::Error>,
{
    debug!("Trying to connect to process: {}...", name);

    let sys = System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));

    let mut processes = sys.processes_by_name(name);

    if let Some(process) = processes.next() {
        let pid = process.pid();

        debug!("Process found: {}", pid);

        let process_handle = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid.as_u32()) };

        if process_handle.is_null() {
            return Err(anyhow::anyhow!("Opening process"));
        }

        let process = Rc::new(Process { handle: process_handle });

        let connected_process = ConnectedProcess {
            process,
            module_handles: RefCell::new(None),
            modules: RefCell::new(Vec::new()),
        };

        return Ok(f(connected_process));
    }

    Err(anyhow::anyhow!("Process not found"))
}

pub trait FromBytes
where
    Self: Sized,
{
    const SIZE: usize;

    fn from_bytes(bytes: &[u8]) -> Self;
}

impl FromBytes for u32 {
    const SIZE: usize = mem::size_of::<Self>();

    fn from_bytes(bytes: &[u8]) -> Self {
        LittleEndian::read_u32(bytes)
    }
}

impl FromBytes for i32 {
    const SIZE: usize = mem::size_of::<Self>();

    fn from_bytes(bytes: &[u8]) -> Self {
        LittleEndian::read_i32(bytes)
    }
}

impl FromBytes for u64 {
    const SIZE: usize = mem::size_of::<Self>();

    fn from_bytes(bytes: &[u8]) -> Self {
        LittleEndian::read_u64(bytes)
    }
}

impl FromBytes for i64 {
    const SIZE: usize = mem::size_of::<Self>();

    fn from_bytes(bytes: &[u8]) -> Self {
        LittleEndian::read_i64(bytes)
    }
}
