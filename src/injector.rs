use std::path::PathBuf;

use crate::wrappers::{Module as _, RemoteProcess};
use crate::executor::Executor;
use crate::ExecutionStrategy;

pub struct Injector {
    process: RemoteProcess,
}

impl Injector {
    pub fn new(process_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let process = RemoteProcess::from_name(process_name)?;
        Ok(Injector { process })
    }

    pub fn inject(&self, dll_path: &PathBuf, shellcode_execution_method: ExecutionStrategy) -> Result<(), Box<dyn std::error::Error>> {
        if !dll_path.exists() {
            return Err("dll doesnt exist".into());
        }

        let dll_str = dll_path
            .to_str()
            .ok_or_else(|| "Couldnt convert path to &str")?;

        let remote_module = self.process.get_module("kernel32.dll")?;
        let remote_func_addr = remote_module.get_func_addr("LoadLibraryW")?;
        let dll_path_mem_alloc = self.process.write_wide_string(dll_str)?;

        let executor = Executor::new(&self.process, remote_func_addr, &dll_path_mem_alloc);

        executor.execute(shellcode_execution_method)?;
        std::mem::forget(dll_path_mem_alloc); // todo: this is workaround, fix later
        Ok(())
    }
}