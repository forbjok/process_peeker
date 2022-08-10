use std::marker::PhantomData;

use winapi::{
    ctypes::c_void,
    shared::{
        basetsd::SIZE_T,
        minwindef::{FALSE, LPCVOID},
    },
    um::memoryapi::ReadProcessMemory,
};

use crate::{process::ProcessRef, AddressPointer, FromBytes};

#[derive(Debug)]
pub enum Address {
    Fixed(AddressPointer),
    PointerPath(Vec<AddressPointer>),
}

#[derive(Debug)]
pub struct ResolvedAddress<T: FromBytes> {
    pub(crate) process: ProcessRef,
    pub(crate) address: AddressPointer,
    pub(crate) _phantom_data: PhantomData<T>,
}

impl<T: FromBytes> ResolvedAddress<T> {
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
