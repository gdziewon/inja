use crate::wrappers::{AllocatedMemory, RemoteProcess};

mod create_remote_thread;
mod nt_create_thread_ex;
mod thread_hijacking;
mod set_windows_hook_ex;
mod kernel_callback_table;
mod queue_user_apc;
mod fake_veh;

use create_remote_thread::CreateRemoteThreadExecutor;
use nt_create_thread_ex::NtCreateThreadExExecutor;
use set_windows_hook_ex::SetWindowsHookExExecutor;
use thread_hijacking::ThreadHijackingExecutor;
use kernel_callback_table::KernelCallbackTableExecutor;
use queue_user_apc::QueueUserAPCExecutor;
use fake_veh::FakeVeh;
use crate::ExecutionStrategy;

pub trait ExecutionMethod {
    fn execute(
        remote_process: &RemoteProcess,
        inject_func_addr: usize,
        dll_path_mem_alloc: &AllocatedMemory,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

pub struct Executor<'a> {
    remote_process: &'a RemoteProcess,
    inject_func_addr: usize,
    dll_path_mem_alloc: &'a AllocatedMemory,
}

impl Executor<'_> {
    pub fn new<'a>(
        remote_process: &'a RemoteProcess,
        inject_func_addr: usize,
        dll_path_mem_alloc: &'a AllocatedMemory,
    ) -> Executor<'a> {
        Executor {
            remote_process,
            inject_func_addr,
            dll_path_mem_alloc,
        }
    }

    pub fn execute(&self, shellcode_execution_method: ExecutionStrategy) -> Result<(), Box<dyn std::error::Error>> {
        match shellcode_execution_method {
            ExecutionStrategy::CreateRemoteThread => CreateRemoteThreadExecutor::execute(
                self.remote_process,
                self.inject_func_addr,
                self.dll_path_mem_alloc,
            ),
            ExecutionStrategy::NtCreateThreadEx => NtCreateThreadExExecutor::execute(
                self.remote_process,
                self.inject_func_addr,
                self.dll_path_mem_alloc,
            ),
            ExecutionStrategy::ThreadHijacking => ThreadHijackingExecutor::execute(
                self.remote_process,
                self.inject_func_addr,
                self.dll_path_mem_alloc,
            ),
            ExecutionStrategy::SetWindowsHookEx => SetWindowsHookExExecutor::execute(
                self.remote_process,
                self.inject_func_addr,
                self.dll_path_mem_alloc,
            ),
            ExecutionStrategy::KernelCallbackTable => KernelCallbackTableExecutor::execute(
                self.remote_process,
                self.inject_func_addr,
                self.dll_path_mem_alloc,
            ),
            ExecutionStrategy::QueueUserAPC => QueueUserAPCExecutor::execute(
                self.remote_process,
                self.inject_func_addr,
                self.dll_path_mem_alloc,
            ),
            ExecutionStrategy::FakeVeh => FakeVeh::execute(
                self.remote_process,
                self.inject_func_addr,
                self.dll_path_mem_alloc,
            ),
        }
    }
}