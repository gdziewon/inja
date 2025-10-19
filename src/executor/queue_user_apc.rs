use std::{ffi::{c_void}};

use dynasmrt::{dynasm, DynasmApi};

use crate::wrappers::{
    HandleWrapper as _, RemoteAllocator, RemoteModule, RemoteProcess, RemoteThread
};

use super::ExecutionMethod;
pub(super) struct QueueUserAPCExecutor;

impl ExecutionMethod for QueueUserAPCExecutor {
    fn execute(
        remote_process: &RemoteProcess,
        inject_func_addr: usize,
        dll_path_mem_alloc: *mut c_void,
    ) -> Result<(), Box<dyn std::error::Error>> {
        //let proc_handle_ptr = remote_process.handle().0 as *mut c_void;
        let stub = build_shcode(
            dll_path_mem_alloc as u64,
            inject_func_addr as u64,
        )?;

        let shcode_mem = remote_process.alloc(stub.len(), true)?;
        remote_process.write(shcode_mem, &stub)?;


        Ok(())
    }
}

fn build_shcode(
    dll_path_ptr: u64,
    inject_func_ptr: u64
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut ops: dynasmrt::Assembler<dynasmrt::x64::X64Relocation> = dynasmrt::x64::Assembler::new()?;

    dynasm!(ops
        ; .arch x64
        ; sub rsp, 0x28

        ; mov rcx, QWORD dll_path_ptr as i64
        ; mov rax, QWORD inject_func_ptr as i64
        ; call rax

        ; add rsp, 0x28

        ; ret
    );

    let buf = ops.finalize().unwrap();
    println!("{:#04X?}, length: {}", buf.to_vec(), buf.to_vec().len());
    Ok(buf.to_vec())
}