use windows::Win32::{Foundation::{HWND, LPARAM, LRESULT, WPARAM}, UI::WindowsAndMessaging::{GetWindowThreadProcessId, IsWindowVisible, SendMessageW, SetForegroundWindow, SetWindowsHookExW, UnhookWindowsHookEx, HHOOK, WINDOWS_HOOK_ID}};

use crate::wrappers::{HandleWrapper, LocalModule};

pub type Hook = unsafe extern "system" fn(i32, WPARAM, LPARAM) -> LRESULT;

pub struct RemoteHook {
    hook: HHOOK,
}

impl Drop for RemoteHook {
    fn drop(&mut self) {
        unsafe {
            let _ = UnhookWindowsHookEx(self.hook);
        }
    }
}

trait Window : HandleWrapper {}

#[derive(Default)]
pub struct RemoteWindow {
    hwnd: HWND,
    pid: u32,
    tid: u32,
}

impl Window for RemoteWindow {}

impl From<HWND> for RemoteWindow {
    fn from(hwnd: HWND) -> Self {
        let mut pid: u32 = 0;
        let tid = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };

        Self { hwnd, pid, tid }
    }
}

impl HandleWrapper for RemoteWindow {
    type HandleType = HWND;

    fn handle(&self) -> Self::HandleType {
        self.hwnd
    }

    fn handle_mut(&mut self) -> &mut Self::HandleType {
        &mut self.hwnd
    }
}

impl RemoteWindow {
    pub fn set_windows_hook_ex(&self, hook_id: WINDOWS_HOOK_ID, hook_func: Option<Hook>, module: Option<&LocalModule>) -> Result<RemoteHook, Box<dyn std::error::Error>> {
        let hhook = unsafe {
            SetWindowsHookExW(
                hook_id,
                hook_func,
                module.map(|m| m.handle().into()),
                self.tid()
            )
        }?;

        Ok(RemoteHook { hook: hhook })
    }

    pub fn set_foreground(&self) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            SetForegroundWindow(self.hwnd)
        }
        .ok()
        .map_err(|e| e.into())
    }

    pub fn send_msg(&self, msg: u32, wparam: Option<WPARAM>, lparam: Option<LPARAM>) -> LRESULT {
        unsafe {
            SendMessageW(self.hwnd, msg, wparam, lparam)
        }
    }

    pub fn is_visible(&self) -> bool {
        unsafe { IsWindowVisible(self.hwnd).as_bool() }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn tid(&self) -> u32 {
        self.tid
    }
}