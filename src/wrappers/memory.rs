use std::ffi::c_void;

use windows::Win32::{Foundation::HANDLE, System::{Diagnostics::Debug::{FlushInstructionCache, WriteProcessMemory}, Memory::{VirtualFreeEx, MEM_RELEASE}}};

pub struct AllocatedMemory {
    base_address: *mut c_void,
    size: usize,
    process_handle: HANDLE,
}

impl AllocatedMemory {
    pub fn new(
        base_address: *mut c_void,
        size: usize,
        process_handle: HANDLE
    ) -> Self {
        Self { base_address, size, process_handle }
    }

    pub fn as_ptr(&self) -> *mut c_void {
        self.base_address
    }
    
    pub fn write(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if data.len() > self.size {
            return Err("Data is larger than allocated memory block.".into());
        }
        unsafe {
            WriteProcessMemory(
                self.process_handle,
                self.base_address,
                data.as_ptr() as _,
                data.len(),
                None,
            )?;
        }
        Ok(())
    }

    pub fn flush_icache(&self) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            FlushInstructionCache(
                self.process_handle,
                Some(self.base_address),
                self.size
            )?;
        }
        Ok(())
    }

    pub fn write_struct<T: Sized>(&self, data: &T) -> Result<(), Box<dyn std::error::Error>> {
        let size = std::mem::size_of_val(data);
        if size > self.size {
            return Err("Struct is larger than allocated memory block.".into());
        }

        // this 'unsafe' is encapsulated and hidden from the caller
        // because we have proven its safe with the check above
        let bytes = unsafe {
            std::slice::from_raw_parts(data as *const T as *const u8, size)
        };
        
        self.write(bytes) 
    }
}

impl Drop for AllocatedMemory {
    fn drop(&mut self) {
        unsafe {
            let _ = VirtualFreeEx(self.process_handle, self.base_address, 0, MEM_RELEASE);
        }
    }
}

pub trait RemoteAllocator {
    fn alloc(&self, size: usize, exec: bool) -> Result<AllocatedMemory, Box<dyn std::error::Error>>;
}