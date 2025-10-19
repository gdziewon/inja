mod remote_process;
mod remote_thread;
mod remote_module;
mod remote_window;

use std::ffi::c_void;

pub use remote_process::RemoteProcess;
pub use remote_thread::RemoteThread;
pub use remote_module::RemoteModule;

pub trait HandleWrapper {
    type HandleType;

    fn handle(&self) -> Self::HandleType;
    fn handle_mut(&mut self) -> &mut Self::HandleType;
    fn into_handle(self) -> Self::HandleType;
}

pub trait RemoteAllocator {
    fn alloc(&self, size: usize, exec: bool) -> Result<*mut c_void, Box<dyn std::error::Error>>;
    fn write(&self, addr: *mut c_void, data: &[u8]) -> Result<(), Box<dyn std::error::Error>>;
    fn flush_icache(&self, addr: *const c_void, size: usize) -> Result<(), Box<dyn std::error::Error>>;
}