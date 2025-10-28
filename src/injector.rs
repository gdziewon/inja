use std::path::PathBuf;

use crate::wrappers::RemoteProcess;
use crate::executor::{Executor, ExecutionStrategy};
use crate::loader::{Loader, LoadStrategy};

pub struct Injector {
    process: RemoteProcess,
}

impl Injector {
    pub fn new(process_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let process = RemoteProcess::from_name(process_name)?;
        Ok(Injector { process })
    }

    pub fn inject(&self, dll_path: &PathBuf, shellcode_execution_method: ExecutionStrategy, dll_load_method: LoadStrategy) -> Result<(), Box<dyn std::error::Error>> {
        if !dll_path.exists() {
            return Err("dll doesnt exist".into());
        }

        let dll_str = dll_path
            .to_str()
            .ok_or_else(|| "Couldnt convert path to &str")?;

        let remote_func_addr = self.process.get_remote_func_address("kernel32.dll", "LoadLibraryW")?;
        let dll_path_malloc = self.process.write_wide_string(dll_str)?;

        let dll_load_sc0de = Loader::new(&self.process, dll_path_malloc).build_sc0de(dll_load_method);

        let executor = Executor::new(&self.process, remote_func_addr, dll_path_malloc);

        executor.execute(shellcode_execution_method)
    }
}