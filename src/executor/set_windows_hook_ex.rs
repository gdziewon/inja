use std::{ffi::c_void, thread::sleep};

use dynasmrt::{dynasm, DynasmApi};
use windows::{Win32::{Foundation::{LPARAM, LRESULT, WPARAM}, UI::{Input::KeyboardAndMouse::VK_SPACE, WindowsAndMessaging::{WH_CALLWNDPROC, WM_KEYDOWN, WM_KEYUP}}}};

use crate::wrappers::{
    RemoteAllocator as _,
    HandleWrapper as _,
    RemoteProcess,
    RemoteModule,
    Hook
};
use super::ExecutionMethod;

pub(super) struct SetWindowsHookExExecutor;

impl ExecutionMethod for SetWindowsHookExExecutor {
    fn execute(
        remote_process: &RemoteProcess,
        inject_func_addr: usize,
        dll_path_malloc: *mut c_void,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let stub = build_shcode(
            dll_path_malloc as u64,
            inject_func_addr as u64,
        )?;

        let shellcode_mem = remote_process.alloc(stub.len(), true)?;
        remote_process.write(shellcode_mem, &stub)?;

        let windows = remote_process.get_windows()?;
        println!("Found {} windows in target process", windows.len());

        let remote_hook: Hook = unsafe { std::mem::transmute(shellcode_mem) };
        let module = RemoteModule::new("user32.dll")?;

        for window in &windows {
            let hook = window.set_windows_hook_ex(
                WH_CALLWNDPROC,
                Some(remote_hook),
                Some(&module),
            );
            if hook.is_err() {
                println!("Failed to install hook on window {:?} (thread id: {}): {:?}", window.handle(), window.tid(), hook.err());
                continue;
            }

            println!("Installed hook on window {:?} (thread id: {})", window.handle(), window.tid());
            let space_key = WPARAM(VK_SPACE.0 as usize);
            window.set_foreground()?;
            window.send_msg(WM_KEYDOWN, Some(space_key), None);
            sleep(std::time::Duration::from_millis(10));
            window.send_msg(WM_KEYUP, Some(space_key), None);
        }

        Ok(())
    }
}

fn build_shcode(
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