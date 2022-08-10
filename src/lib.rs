mod win32util;

use std::{cell::RefCell, fs, io::Read, marker::PhantomData, mem, path::PathBuf, rc::Rc, time::Duration};

use anyhow::Context;
use byteorder::{ByteOrder, LittleEndian};
use sha2::{Digest, Sha256};
use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt};
use tracing::debug;
use win32util::wstring_to_osstring;
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
        psapi::{EnumProcessModules, GetModuleBaseNameW, GetModuleFileNameExW, GetModuleInformation, MODULEINFO},
        winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

use crate::win32util::wstring_to_string;

pub type AddressPointer = u64;

const PTR_SIZE: usize = mem::size_of::<AddressPointer>();

#[derive(Debug)]
pub struct Module {
    process: ProcessRef,
    handle: HMODULE,
    pub name: String,
    pub size: u32,
    pub base_address: AddressPointer,
}

#[derive(Debug)]
pub struct Process {
    handle: HANDLE,
}

#[derive(Debug)]
pub struct Address<T: FromBytes> {
    process: ProcessRef,
    address: AddressPointer,
    _phantom_data: PhantomData<T>,
}

type ProcessRef = Rc<Process>;
type ModuleRef = Rc<Module>;

#[derive(Debug)]
pub struct ConnectedProcess {
    process: ProcessRef,
    module_handles: RefCell<Option<Vec<HMODULE>>>,
    modules: RefCell<Vec<ModuleRef>>,
}

impl ConnectedProcess {
    pub fn module(&self, module_name: &str) -> Result<Option<ModuleRef>, anyhow::Error> {
        if let Some(m) = self.modules.borrow().iter().find(|&m| m.name == module_name) {
            return Ok(Some(m.clone()));
        }

        if self.module_handles.borrow().is_none() {
            const MAX_MODULES: usize = 1024;

            let mut module_handles = vec![0 as HMODULE; MAX_MODULES];
            let mut cb_needed: DWORD = 0;

            let result = unsafe {
                EnumProcessModules(
                    self.process.handle,
                    module_handles.as_mut_ptr(),
                    (module_handles.len() * mem::size_of::<HMODULE>()) as DWORD,
                    &mut cb_needed,
                )
            };

            if result == FALSE {
                return Err(anyhow::anyhow!("Enumerating process modules"));
            }

            let module_count = (cb_needed as usize) / mem::size_of::<HMODULE>();

            module_handles.truncate(module_count);

            *self.module_handles.borrow_mut() = Some(module_handles);
        }

        let mut module_handles = self.module_handles.borrow_mut();
        let module_handles = module_handles.as_mut().unwrap();
        let mut modules = self.modules.borrow_mut();

        let requested_module_name = module_name;
        let mut module_name = [0u16; MAX_PATH + 1];

        // Get module information
        let module = loop {
            if module_handles.is_empty() {
                break None;
            }

            let module_handle = module_handles.remove(0);

            let result = unsafe {
                GetModuleBaseNameW(
                    self.process.handle,
                    module_handle,
                    module_name.as_mut_ptr(),
                    MAX_PATH as DWORD + 1,
                )
            };

            if result == 0 {
                return Err(anyhow::anyhow!("Getting module base name"));
            }

            let name = wstring_to_string(&module_name);

            let is_requested_module = name == requested_module_name;

            let mut module_info = mem::MaybeUninit::<MODULEINFO>::uninit();
            let result = unsafe {
                GetModuleInformation(
                    self.process.handle,
                    module_handle,
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

            let module = Rc::new(Module {
                process: self.process.clone(),
                handle: module_handle,
                name,
                size,
                base_address,
            });

            modules.push(module);

            if is_requested_module {
                break modules.last().cloned();
            }
        };

        Ok(module)
    }

    pub fn resolve_pointer_path<T: FromBytes>(
        &self,
        base_address: AddressPointer,
        pointer_path: &[AddressPointer],
    ) -> Result<Address<T>, anyhow::Error> {
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
                    self.process.handle,
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

        Ok(Address {
            process: self.process.clone(),
            address,
            _phantom_data: Default::default(),
        })
    }
}

impl Module {
    /// Get full path to module
    fn filename(&self) -> Result<PathBuf, anyhow::Error> {
        let mut module_filename = [0u16; MAX_PATH + 1];

        let result = unsafe {
            GetModuleFileNameExW(
                self.process.handle,
                self.handle,
                module_filename.as_mut_ptr(),
                MAX_PATH as DWORD + 1,
            )
        };

        if result == 0 {
            return Err(anyhow::anyhow!("Getting module base name"));
        }

        let filename = wstring_to_osstring(&module_filename);

        Ok(PathBuf::from(filename))
    }

    /// Calculate SHA256 hash of this module's binary
    pub fn hash_sha256(&self) -> Result<String, anyhow::Error> {
        const BUFFER_SIZE: usize = 524288;

        let path = self.filename()?;
        let mut file =
            fs::File::open(&path).with_context(|| format!("Opening file for hashing: {}", path.display()))?;

        let mut sha256 = Sha256::new();

        let mut buf = [0u8; BUFFER_SIZE];

        while let Ok(bytes) = file.read(&mut buf) {
            if bytes == 0 {
                break;
            }

            sha256.update(&buf[..bytes]);
        }

        let hash = sha256.finalize();

        let hash = hex::encode(hash);

        debug!("MODULE '{}' HASH: {}", self.name, &hash);

        Ok(hash)
    }
}

impl<T: FromBytes> Address<T> {
    pub fn peek(&self) -> Result<T, anyhow::Error> {
        // Would have liked to use an array here, but that is currently
        // failing with "constant expression depends on a generic parameter".
        let mut buf = vec![0u8; T::SIZE];

        let mut bytes_read: SIZE_T = 0;

        let result = unsafe {
            ReadProcessMemory(
                self.process.handle,
                self.address as LPCVOID,
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
