use dynasmrt::{dynasm, DynasmApi};
use windows::Win32::{Foundation::PAPCFUNC};

use crate::wrappers::{
    AllocatedMemory, RemoteAllocator, RemoteProcess
};

use super::ExecutionMethod;
pub(super) struct QueueUserAPCExecutor;

type PapcFunc = unsafe extern "system" fn(usize);

impl ExecutionMethod for QueueUserAPCExecutor {
    fn execute(
        remote_process: &RemoteProcess,
        inject_func_addr: usize,
        dll_path_mem_alloc: &AllocatedMemory,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 1. get & enumerate threads of remote proc
        let threads = remote_process.get_threads()?;
        println!("Found {} threads", threads.len());

        // 2. build shellcode
        let stub = build_shcode(
            dll_path_mem_alloc.as_ptr() as u64,
            inject_func_addr as u64,
        )?;
        println!("Built shellcode with length: {}", stub.len());

        // 3. alloc & write shellcode to remote proc
        let shellcode_alloc = remote_process.alloc(stub.len(), true)?;
        shellcode_alloc.write(&stub)?;

        println!("Wrote shellcode to remote process at address: {:p}", shellcode_alloc.as_ptr());

        // 4.1 cast shellcode to fn pointer
        let p_thread_start_func: PapcFunc = unsafe { std::mem::transmute(shellcode_alloc.as_ptr()) };

        println!("Created thread start function pointer: {p_thread_start_func:p}");

        // 4.2 Queue APC to each thread
        for remote_thread in threads { // todo: should we do it on all threads?
            let p_apc_func: PAPCFUNC = Some(p_thread_start_func);
            remote_thread.queue_user_apc(p_apc_func, 0)?;
        }

        std::mem::forget(shellcode_alloc); // todo: this is workaround, fix later

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
        ; sub rsp, 0x20 // shadow space
        ; sub rsp, 0x8  // align stack to 16 bytes (because call later pushes 8 bytes)

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