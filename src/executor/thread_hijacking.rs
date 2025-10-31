use dynasmrt::{dynasm, DynasmApi};

use crate::wrappers::{
    AllocatedMemory, RemoteAllocator as _, RemoteProcess
};

use super::ExecutionMethod;

pub(super) struct ThreadHijackingExecutor;

impl ExecutionMethod for ThreadHijackingExecutor {
    fn execute(
        remote_process: &RemoteProcess,
        inject_func_addr: usize,
        dll_path_mem_alloc: &AllocatedMemory,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut threads = remote_process.get_threads()?; // todo: look for a better thread
        println!("Found {} threads", threads.len());
        let mut remote_thread = threads.pop().ok_or("No threads found")?;
        remote_thread.suspend()?;

        let mut context = remote_thread.get_context()?;
        let stub = build_shcode(
            dll_path_mem_alloc.as_ptr() as u64,
            inject_func_addr as u64,
            context.get().Rip
        )?;

        let shellcode_mem = remote_process.alloc(stub.len(), true)?;
        shellcode_mem.write(&stub)?;
        shellcode_mem.flush_icache()?;

        context.get_mut().Rip = shellcode_mem.as_ptr() as u64;

        remote_thread.set_context(&context)?;

        remote_thread.resume()?;

        std::mem::forget(shellcode_mem); // todo: this is workaround, fix later

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