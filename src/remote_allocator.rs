use std::ffi::c_void;

use windows::Win32::System::{Diagnostics::Debug::{FlushInstructionCache, WriteProcessMemory}, Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE}};

use crate::remote_process::RemoteProcess;


pub trait RemoteAllocator {
    fn alloc(&self, size: usize, exec: bool) -> Result<*mut c_void, Box<dyn std::error::Error>>;
    fn write(&self, addr: *mut c_void, data: &[u8]) -> Result<(), Box<dyn std::error::Error>>;
    fn flush_icache(&self, addr: *const c_void, size: usize) -> Result<(), Box<dyn std::error::Error>>;
}

impl RemoteAllocator for RemoteProcess {
    fn alloc(&self, size: usize, exec: bool) -> Result<*mut c_void, Box<dyn std::error::Error>> {
        let prot = if exec { PAGE_EXECUTE_READWRITE } else { PAGE_READWRITE };
        let addr = unsafe {
            VirtualAllocEx(
                self.handle(),
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                prot,
            )
        };
        if addr.is_null() {
            return Err("Failed to allocate memory".into());
        }
        Ok(addr)
    }

    fn write(&self, addr: *mut c_void, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            WriteProcessMemory(
                self.handle(),
                addr,
                data.as_ptr() as *const c_void,
                data.len(),
                None
            )
        }?;
        Ok(())
    }

    fn flush_icache(&self, addr: *const c_void, size: usize) -> Result<(), Box<dyn std::error::Error>> {
        unsafe { FlushInstructionCache(self.handle(), Some(addr), size) }?;
        Ok(())
    }
}