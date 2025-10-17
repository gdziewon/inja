use std::path::PathBuf;
use windows::Win32::{
    Foundation::CloseHandle,
    System::{
        Threading::WaitForSingleObject
    },
};

use crate::remote_process::RemoteProcess;
use crate::executor::{Executor, ShellcodeExecution};

pub struct Injector {
    process: RemoteProcess,
}

impl Injector {
    pub fn new(process_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let process = RemoteProcess::from_name(process_name)?;
        Ok(Injector { process })
    }

    pub fn inject(&self, dll_path: &PathBuf, shellcode_execution_method: ShellcodeExecution) -> Result<(), Box<dyn std::error::Error>> {
        if !dll_path.exists() {
            return Err("dll doesnt exist".into());
        }

        let dll_str = dll_path
            .to_str()
            .ok_or_else(|| "Couldnt convert path to &str")?;

        let remote_func_addr = self.process.get_remote_func_address("kernel32.dll", "LoadLibraryW")?;
        let dll_path_mem_alloc = self.process.write_wide_string(dll_str)?;

        let executor = Executor::new(&self.process, remote_func_addr, dll_path_mem_alloc);

        executor.execute(shellcode_execution_method.clone())
    }
}