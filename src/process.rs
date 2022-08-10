use std::{cell::RefCell, mem, rc::Rc};

use winapi::{
    shared::{
        minwindef::{DWORD, FALSE, HMODULE, MAX_PATH},
        ntdef::HANDLE,
    },
    um::psapi::{EnumProcessModules, GetModuleBaseNameW, GetModuleInformation, MODULEINFO},
};

use crate::{
    module::{Module, ModuleRef},
    win32util::wstring_to_string,
    AddressPointer,
};

#[derive(Debug)]
pub(crate) struct Process {
    pub handle: HANDLE,
}

pub(crate) type ProcessRef = Rc<Process>;

#[derive(Debug)]
pub struct ConnectedProcess {
    pub(crate) process: ProcessRef,
    pub(crate) module_handles: RefCell<Option<Vec<HMODULE>>>,
    pub(crate) modules: RefCell<Vec<ModuleRef>>,
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
}
