use std::ffi::c_void;

use dynasmrt::{dynasm, DynasmApi};

use crate::{wrappers::RemoteProcess};

use super::LoadMethod;

pub(super) struct LdrLoadDllLoader;

impl LoadMethod for LdrLoadDllLoader {
    fn build_sc0de(target_process: &RemoteProcess, dll_path_malloc: *mut c_void) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let load_library_fn_ptr = target_process.get_remote_func_address("kernel32.dll", "LoadLibraryW")?;

        let mut ops: dynasmrt::Assembler<dynasmrt::x64::X64Relocation> = dynasmrt::x64::Assembler::new()?;

        dynasm!(ops
            ; .arch x64
            // TODO: Implement
            ; ret
        );

        let buf = ops.finalize().unwrap();
        println!("{:#04X?}, length: {}", buf.to_vec(), buf.to_vec().len());
        Ok(buf.to_vec())
    }
}