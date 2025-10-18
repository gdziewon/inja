use std::ffi::CString;
use std::thread::sleep;
use std::{ffi::c_void, ptr};

use dynasmrt::{dynasm, DynasmApi};

use windows::core::{w, BOOL, PCSTR};
use windows::Win32::Foundation::{CloseHandle, HMODULE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Threading::WaitForSingleObject;
use windows::Win32::UI::Input::KeyboardAndMouse::VK_SPACE;
use windows::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId, IsWindowVisible, SendMessageW, SetForegroundWindow, SetWindowsHookExW, UnhookWindowsHookEx, HHOOK, WH_CALLWNDPROC, WM_KEYDOWN, WM_KEYUP, WNDENUMPROC};
use windows::Win32::{
    Foundation::{HANDLE, NTSTATUS},
    System::{
        LibraryLoader::GetModuleHandleW,
        Threading::{CreateRemoteThread, THREAD_ALL_ACCESS}
    }
};
use windows::Wdk::Foundation::{OBJECT_ATTRIBUTES};
use crate::remote_allocator::RemoteAllocator as _;
use crate::remote_process::RemoteProcess;

#[derive(Debug)]
pub enum ShellcodeExecution {
    CreateRemoteThread,
    NtCreateThreadEx,
    ThreadHijacking,
    SetWindowsHookEx,
}

pub type NtCreateThreadEx = unsafe extern "system" fn(
    thread_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    process_handle: *mut c_void,
    start_routine: *mut c_void,
    argument: *mut c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_size: usize,
    maximum_stack_size: usize,
    attribute_list: *mut c_void,
) -> NTSTATUS;

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

    pub fn execute(&self, shellcode_execution_method: ShellcodeExecution) -> Result<(), Box<dyn std::error::Error>> {
        match shellcode_execution_method {
            ShellcodeExecution::CreateRemoteThread => self.execute_create_remote_thread(),
            ShellcodeExecution::NtCreateThreadEx => self.execute_nt_create_thread_ex(),
            ShellcodeExecution::ThreadHijacking => self.execute_thread_hijacking(),
            ShellcodeExecution::SetWindowsHookEx => self.execute_set_windows_hook_ex(),
        }
    }

    fn execute_create_remote_thread(&self) -> Result<(), Box<dyn std::error::Error>> {
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

        unsafe { WaitForSingleObject(thread, u32::MAX) };
        unsafe { CloseHandle(thread) }?;

        Ok(())
    }

    fn execute_nt_create_thread_ex(&self) -> Result<(), Box<dyn std::error::Error>> {
        let ntdll = unsafe { GetModuleHandleW(w!("ntdll.dll"))? };
        let nt_func_name = CString::new("NtCreateThreadEx")?;
        let address = unsafe { GetProcAddress(ntdll, PCSTR(nt_func_name.as_ptr() as _)) };
        if address.is_none() {
            return Err("NtCreateThreadEx not found".into());
        }
        let create_thread_ex_func = unsafe { core::mem::transmute::<*mut core::ffi::c_void, NtCreateThreadEx>(address.unwrap() as *mut _) };
        let mut thread: HANDLE = HANDLE::default();
        let pthread: *mut *mut c_void = &mut thread.0;

        let ntstatus = unsafe { create_thread_ex_func(
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
        ) };

        if ntstatus.0 != 0 {
            return Err(format!("NtCreateThreadEx failed with NTSTATUS: {:#x}", ntstatus.0).into());
        }

        unsafe { WaitForSingleObject(thread, u32::MAX) };
        unsafe { CloseHandle(thread) }?;

        Ok(())
    }

    fn execute_thread_hijacking(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut remote_thread = self.remote_process.get_remote_thread(false)?;

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

        Ok(())
    }


    fn execute_set_windows_hook_ex(&self) -> Result<(), Box<dyn std::error::Error>> {
        let stub = create_next_hook_ex_shellcode(
            self.dll_path_mem_alloc as u64,
            self.inject_func_addr as u64,
        )?;

        let remote_shellcode = self.remote_process.alloc(stub.len(), true)?;
        self.remote_process.write(remote_shellcode, &stub)?;

        let enum_callback = WNDENUMPROC::Some(enum_windows_callback);
        let data = EnumWindowsData {
            target_pid: self.remote_process.pid(),
            remote_hook: HHOOK(remote_shellcode as *mut c_void),
            module: unsafe { LoadLibraryW(w!("user32.dll")) }?,
            installed_hooks: Vec::new(),
        };
        unsafe { EnumWindows(enum_callback, LPARAM(&data as *const _ as isize)) }?;

        println!("Installed {} hooks", data.installed_hooks.len());

        for HookData { hook_handle, window_handle } in &data.installed_hooks {
            unsafe {
                let space_key = WPARAM(VK_SPACE.0 as usize);
                let _ = SetForegroundWindow(*window_handle);
                SendMessageW(*window_handle, WM_KEYDOWN, Some(space_key), None);
                sleep(std::time::Duration::from_millis(10));
                SendMessageW(*window_handle, WM_KEYUP, Some(space_key), None);
                UnhookWindowsHookEx(*hook_handle)?;
            }
        }

        Ok(())
    }
}

struct EnumWindowsData {
    target_pid: u32,
    remote_hook: HHOOK,
    module: HMODULE,
    installed_hooks: Vec<HookData>,
}

struct HookData {
    hook_handle: HHOOK,
    window_handle: HWND,
}

fn create_next_hook_ex_shellcode(
    dll_path_ptr: u64,
    inject_func_ptr: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut ops: dynasmrt::Assembler<dynasmrt::x64::X64Relocation> = dynasmrt::x64::Assembler::new()?;

    dynasm!(ops
        ; .arch x64
        ; sub rsp, 0x28

        ; mov rcx, QWORD dll_path_ptr as i64  // inject
        ; mov rax, QWORD inject_func_ptr as i64
        ; call rax

        ; add rsp, 0x28

        ; xor rax, rax // return 0 from a hooked function

        ; ret
    );

    let buf = ops.finalize().unwrap();
    println!("{:#04X?}, length: {}", buf.to_vec(), buf.to_vec().len());
    Ok(buf.to_vec())
}

unsafe extern "system" fn enum_windows_callback(
    hwnd: HWND,
    lparam: LPARAM
) -> BOOL {
    let data = unsafe { &mut *(lparam.0 as *mut EnumWindowsData) };
    let pid = data.target_pid;
    let mut wnd_pid: u32 = 0;
    let wnd_tid = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut wnd_pid)) };
    if wnd_tid == 0 {
        return BOOL(1);
    }
    if wnd_pid != pid || !unsafe { IsWindowVisible(hwnd).as_bool() } {
        return BOOL(1);
    }

    let remote_hook: Option<unsafe extern "system" fn(i32, WPARAM, LPARAM) -> LRESULT> =
        unsafe { std::mem::transmute(data.remote_hook.0) };
    let hook = unsafe {
        SetWindowsHookExW(
            WH_CALLWNDPROC,
            remote_hook,
            Some(data.module.into()),
            wnd_tid
        )
    };
    if hook.is_ok() {
        data.installed_hooks.push(HookData {
            hook_handle: hook.unwrap(),
            window_handle: hwnd,
        });
    }

    BOOL(1)
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
