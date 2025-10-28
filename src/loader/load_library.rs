use std::ffi::c_void;

use dynasmrt::{dynasm, DynasmApi};

use crate::{wrappers::RemoteProcess};

use super::LoadMethod;

pub(super) struct LoadLibraryLoader;

impl LoadMethod for LoadLibraryLoader {
    fn build_sc0de(target_process: &RemoteProcess, dll_path_malloc: *mut c_void) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let load_library_fn_ptr = target_process.get_remote_func_address("kernel32.dll", "LoadLibraryW")?;

        let mut ops: dynasmrt::Assembler<dynasmrt::x64::X64Relocation> = dynasmrt::x64::Assembler::new()?;

        dynasm!(ops
            ; .arch x64
            ; sub rsp, 0x20 // shadow space
            ; sub rsp, 0x8  // align stack to 16 bytes (because call later pushes 8 bytes)

            ; mov rcx, QWORD dll_path_malloc as i64
            ; mov rax, QWORD load_library_fn_ptr as i64
            ; call rax

            ; add rsp, 0x28

            ; ret
        );

        let buf = ops.finalize().unwrap();
        println!("{:#04X?}, length: {}", buf.to_vec(), buf.to_vec().len());
        Ok(buf.to_vec())
    }
}