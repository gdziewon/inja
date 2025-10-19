use std::ffi::c_void;

use dynasmrt::{dynasm, DynasmApi};

use crate::wrappers::{
    RemoteAllocator as _,
    RemoteProcess
};

use super::ExecutionMethod;

pub(super) struct ThreadHijackingExecutor;

impl ExecutionMethod for ThreadHijackingExecutor {
    fn execute(
        remote_process: &RemoteProcess,
        inject_func_addr: usize,
        dll_path_mem_alloc: *mut c_void,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut remote_thread = remote_process.get_remote_thread()?;
        remote_thread.suspend()?;

        let mut context = remote_thread.get_context()?;
        let stub = build_shcode(
            dll_path_mem_alloc as u64,
            inject_func_addr as u64,
            context.get().Rip
        )?;

        let shellcode_mem = remote_process.alloc(stub.len(), true)?;
        remote_process.write(shellcode_mem, &stub)?;
        remote_process.flush_icache(shellcode_mem, stub.len())?;

        context.get_mut().Rip = shellcode_mem as u64;

        remote_thread.set_context(&context)?;

        remote_thread.resume()?;

        Ok(())
    }
}

fn build_shcode(
    dll_path_ptr: u64,
    inject_func_ptr: u64,
    original_rip: u64
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut ops = dynasmrt::x64::Assembler::new()?;

    dynasm!(ops
        ; .arch x64
        ; pushfq  // save flags

        ; push rax  // push registers
        ; push rcx
        ; sub rsp, 0x20 // shadow space + alignment

        ; mov rcx, QWORD dll_path_ptr as i64  // inject
        ; mov rax, QWORD inject_func_ptr as i64
        ; call rax

        ; add rsp, 0x20 // cleanup stack
        ; pop rcx
        ; pop rax

        ; popfq  // restore flags

        ; mov rax, QWORD original_rip as i64 // jump back to original RIP
        ; jmp rax
    );

    let buf = ops.finalize().unwrap();
    println!("{:#04X?}, length: {}", buf.to_vec(), buf.to_vec().len());
    Ok(buf.to_vec())
}