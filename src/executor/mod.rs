use crate::wrappers::{RemoteProcess};

mod create_remote_thread;
mod nt_create_thread_ex;
mod thread_hijacking;
mod set_windows_hook_ex;
mod kernel_callback_table;
mod queue_user_apc;

use create_remote_thread::CreateRemoteThreadExecutor;
use nt_create_thread_ex::NtCreateThreadExExecutor;
use set_windows_hook_ex::SetWindowsHookExExecutor;
use thread_hijacking::ThreadHijackingExecutor;
use kernel_callback_table::KernelCallbackTableExecutor;
use queue_user_apc::QueueUserAPCExecutor;

#[derive(Debug)]
pub enum ExecutionStrategy {
    CreateRemoteThread,
    NtCreateThreadEx,
    ThreadHijacking,
    SetWindowsHookEx,
    KernelCallbackTable,
    QueueUserAPC
}

pub trait ExecutionMethod {
    fn execute(
        remote_process: &RemoteProcess,
        shellcode_to_exec: &Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

pub struct Executor<'a> {
    remote_process: &'a RemoteProcess,
    shellcode_to_exec: &'a Vec<u8>,
}

impl Executor<'_> {
    pub fn new<'a>(
        remote_process: &'a RemoteProcess,
        shellcode_to_exec: &'a Vec<u8>,
    ) -> Executor<'a> {
        Executor {
            remote_process,
            shellcode_to_exec,
        }
    }

    pub fn execute(&self, shellcode_execution_method: ExecutionStrategy) -> Result<(), Box<dyn std::error::Error>> {
        match shellcode_execution_method {
            ExecutionStrategy::CreateRemoteThread => CreateRemoteThreadExecutor::execute(
                self.remote_process,
                self.shellcode_to_exec,
            ),
            ExecutionStrategy::NtCreateThreadEx => NtCreateThreadExExecutor::execute(
                self.remote_process,
                self.shellcode_to_exec,
            ),
            ExecutionStrategy::ThreadHijacking => ThreadHijackingExecutor::execute(
                self.remote_process,
                self.shellcode_to_exec,
            ),
            ExecutionStrategy::SetWindowsHookEx => SetWindowsHookExExecutor::execute(
                self.remote_process,
                self.shellcode_to_exec,
            ),
            ExecutionStrategy::KernelCallbackTable => KernelCallbackTableExecutor::execute(
                self.remote_process,
                self.shellcode_to_exec,
            ),
            ExecutionStrategy::QueueUserAPC => QueueUserAPCExecutor::execute(
                self.remote_process,
                self.shellcode_to_exec,
            ),
        }
    }
}