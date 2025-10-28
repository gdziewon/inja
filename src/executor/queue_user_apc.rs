use std::{ffi::{c_void}};

use dynasmrt::{dynasm, DynasmApi};
use windows::Win32::{Foundation::PAPCFUNC, System::Threading::THREAD_SET_CONTEXT};

use crate::wrappers::{
    HandleWrapper as _, RemoteAllocator, RemoteModule, RemoteProcess, RemoteThread
};

use super::ExecutionMethod;
pub(super) struct QueueUserAPCExecutor;

impl ExecutionMethod for QueueUserAPCExecutor {
    fn execute(
        remote_process: &RemoteProcess,
        inject_func_addr: usize,
        dll_path_malloc: *mut c_void,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 1. get & enumerate threads of remote proc
        let thread_ids = remote_process.get_thread_ids()?;

        // 2. build shellcode
        let stub = build_shcode(
            dll_path_malloc as u64,
            inject_func_addr as u64,
        )?;

        // 3. alloc & write shellcode to remote proc
        let shcode_mem = remote_process.alloc(stub.len(), true)?;
        remote_process.write(shcode_mem, &stub)?;

        // 4.1 cast shellcode to fn pointer
        let p_thread_start_func: Option<unsafe extern "system" fn(usize)> = unsafe { std::mem::transmute(shcode_mem) };

        // 4.2 Queue APC to each thread
        for tid in thread_ids { // TODO: improve selection of thread, discover DLL reinjection ability, what are we not cleaning up?
            let remote_thread = RemoteThread::open(tid, THREAD_SET_CONTEXT)?;
            
            let p_apc_func: PAPCFUNC = Some(p_thread_start_func.unwrap());   
            remote_thread.queue_user_apc(p_apc_func, 0)?;
        }

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