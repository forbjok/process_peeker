mod win32util;

use std::{mem, time::Duration};

use byteorder::{ByteOrder, LittleEndian};
use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt};
use tracing::debug;
use winapi::{
    ctypes::c_void,
    shared::{
        basetsd::SIZE_T,
        minwindef::{DWORD, FALSE, HMODULE, LPCVOID, MAX_PATH},
        ntdef::HANDLE,
    },
    um::{
        memoryapi::ReadProcessMemory,
        processthreadsapi::OpenProcess,
        psapi::{EnumProcessModules, GetModuleBaseNameW, GetModuleInformation, MODULEINFO},
        winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

use crate::win32util::wstring_to_string;

pub type AddressPointer = u64;

const PTR_SIZE: usize = mem::size_of::<AddressPointer>();

#[derive(Debug)]
pub struct Module {
    pub name: String,
    pub size: u32,
    pub base_address: AddressPointer,
}

pub struct ConnectedProcess {
    handle: HANDLE,
    modules: Vec<Module>,
}

impl ConnectedProcess {
    pub fn module(&self, module_name: &str) -> Option<&Module> {
        self.modules.iter().find(|m| m.name == module_name)
    }

    pub fn resolve_pointer_path(
        &self,
        base_address: AddressPointer,
        pointer_path: &[AddressPointer],
    ) -> Result<AddressPointer, anyhow::Error> {
        let mut address = base_address;
        let mut buf = [0u8; PTR_SIZE];
        let mut bytes_read: SIZE_T = 0;

        // Follow pointer path

        let mut ptr_path_iter = pointer_path.iter().peekable();
        while let Some(ptr_offset) = ptr_path_iter.next() {
            debug!("Address: {}, ptr_offset: {}", address as u64, *ptr_offset as u64);

            address += ptr_offset;

            if ptr_path_iter.peek().is_none() {
                break;
            }

            let result = unsafe {
                ReadProcessMemory(
                    self.handle,
                    address as LPCVOID,
                    buf.as_mut_ptr() as *mut c_void,
                    PTR_SIZE,
                    &mut bytes_read,
                )
            };

            if result == FALSE {
                return Err(anyhow::anyhow!("Reading process memory"));
            }

            address = LittleEndian::read_u64(&buf);
        }

        debug!("Final address: {}", address);

        Ok(address)
    }

    pub fn peek<T: FromBytes>(&self, address: AddressPointer) -> Result<T, anyhow::Error> {
        // Would have liked to use an array here, but that is currently
        // failing with "constant expression depends on a generic parameter".
        let mut buf = vec![0u8; T::SIZE];

        let mut bytes_read: SIZE_T = 0;

        let result = unsafe {
            ReadProcessMemory(
                self.handle,
                address as LPCVOID,
                buf.as_mut_ptr() as *mut c_void,
                T::SIZE,
                &mut bytes_read,
            )
        };

        if result == FALSE {
            return Err(anyhow::anyhow!("Reading process memory"));
        }

        Ok(T::from_bytes(&buf))
    }
}

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

        const MAX_MODULES: usize = 1024;

        let mut module_handles = [0 as HMODULE; MAX_MODULES];
        let mut cb_needed: DWORD = 0;

        let result = unsafe {
            EnumProcessModules(
                process_handle,
                module_handles.as_mut_ptr(),
                (module_handles.len() * mem::size_of::<HMODULE>()) as DWORD,
                &mut cb_needed,
            )
        };

        if result == FALSE {
            return Err(anyhow::anyhow!("Enumerating process modules"));
        }

        let module_count = (cb_needed as usize) / mem::size_of::<HMODULE>();

        let mut modules: Vec<Module> = Vec::with_capacity(module_count);

        let mut module_name = [0u16; MAX_PATH + 1];

        // Get module information
        for module_handle in &module_handles[0..module_count] {
            let result = unsafe {
                GetModuleBaseNameW(
                    process_handle,
                    *module_handle,
                    module_name.as_mut_ptr(),
                    MAX_PATH as DWORD + 1,
                )
            };

            if result == 0 {
                return Err(anyhow::anyhow!("Getting module base name"));
            }

            let name = wstring_to_string(&module_name);

            let mut module_info = mem::MaybeUninit::<MODULEINFO>::uninit();
            let result = unsafe {
                GetModuleInformation(
                    process_handle,
                    *module_handle,
                    module_info.as_mut_ptr(),
                    mem::size_of::<MODULEINFO>() as u32,
                )
            };

            if result == FALSE {
                return Err(anyhow::anyhow!("Getting module information"));
            }

            let module_info = unsafe { module_info.assume_init() };

            let size = module_info.SizeOfImage;
            let base_address = module_info.lpBaseOfDll as AddressPointer;

            modules.push(Module {
                name,
                size,
                base_address,
            });
        }

        let process = ConnectedProcess {
            handle: process_handle,
            modules,
        };

        return Ok(f(process));
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
