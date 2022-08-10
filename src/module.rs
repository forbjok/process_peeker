use std::{fs, io::Read, path::PathBuf, rc::Rc};

use anyhow::Context;
use byteorder::{ByteOrder, LittleEndian};
use sha2::{Digest, Sha256};
use tracing::debug;
use winapi::{
    ctypes::c_void,
    shared::{
        basetsd::SIZE_T,
        minwindef::{DWORD, FALSE, HMODULE, LPCVOID, MAX_PATH},
    },
    um::{memoryapi::ReadProcessMemory, psapi::GetModuleFileNameExW},
};

use crate::{
    address::{Address, AddressSpec},
    process::ProcessRef,
    win32util::wstring_to_osstring,
    AddressPointer, FromBytes, PTR_SIZE,
};

#[derive(Debug)]
pub struct Module {
    pub(crate) process: ProcessRef,
    pub(crate) handle: HMODULE,
    pub name: String,
    pub size: u32,
    pub base_address: AddressPointer,
}

pub type ModuleRef = Rc<Module>;

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

    pub fn resolve<T: FromBytes>(&self, address: &AddressSpec) -> Result<Address<T>, anyhow::Error> {
        match address {
            AddressSpec::Fixed(a) => self.resolve_fixed(*a),
            AddressSpec::PointerPath(pp) => self.resolve_pointer_path(pp),
        }
    }

    fn resolve_fixed<T: FromBytes>(&self, address: AddressPointer) -> Result<Address<T>, anyhow::Error> {
        Ok(Address {
            process: self.process.clone(),
            address,
            _phantom_data: Default::default(),
        })
    }

    fn resolve_pointer_path<T: FromBytes>(&self, pointer_path: &[AddressPointer]) -> Result<Address<T>, anyhow::Error> {
        let mut address = self.base_address;
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
