use std::{ffi::c_void, thread::sleep};

use dynasmrt::{dynasm, DynasmApi};
use windows::{core::{w, BOOL}, Win32::{Foundation::{HMODULE, HWND, LPARAM, LRESULT, WPARAM}, System::LibraryLoader::LoadLibraryW, UI::{Input::KeyboardAndMouse::VK_SPACE, WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId, IsWindowVisible, SendMessageW, SetForegroundWindow, SetWindowsHookExW, UnhookWindowsHookEx, HHOOK, WH_CALLWNDPROC, WM_KEYDOWN, WM_KEYUP, WNDENUMPROC}}}};

use crate::{remote_allocator::RemoteAllocator as _, remote_process::RemoteProcess};

use super::ExecutionMethod;

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

pub(super) struct SetWindowsHookExExecutor;

impl ExecutionMethod for SetWindowsHookExExecutor {
    fn execute(
        remote_process: &RemoteProcess,
        inject_func_addr: usize,
        dll_path_mem_alloc: *mut c_void,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let stub = create_next_hook_ex_shellcode(
            dll_path_mem_alloc as u64,
            inject_func_addr as u64,
        )?;

        let remote_shellcode = remote_process.alloc(stub.len(), true)?;
        remote_process.write(remote_shellcode, &stub)?;

        let enum_callback = WNDENUMPROC::Some(enum_windows_callback);
        let data = EnumWindowsData {
            target_pid: remote_process.pid(),
            remote_hook: HHOOK(remote_shellcode as *mut c_void),
            module: unsafe { LoadLibraryW(w!("user32.dll")) }?,
            installed_hooks: Vec::new(),
        };
        unsafe { EnumWindows(enum_callback, LPARAM(&data as *const _ as isize)) }?;

        println!("Installed {} hooks", data.installed_hooks.len());

        // todo: hook and window wrappers?
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