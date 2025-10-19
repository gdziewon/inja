use windows::Win32::{Foundation::{HWND, LPARAM, LRESULT, WPARAM}, UI::WindowsAndMessaging::{GetWindowThreadProcessId, IsWindowVisible, SendMessageW, SetForegroundWindow, SetWindowsHookExW, UnhookWindowsHookEx, HHOOK, WINDOWS_HOOK_ID}};

use crate::wrappers::{HandleWrapper, RemoteModule};

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

#[derive(Default)]
pub struct RemoteWindow {
    hwnd: HWND,
    pid: u32,
    tid: u32,
}

impl HandleWrapper for RemoteWindow {
    type HandleType = HWND;

    fn handle(&self) -> Self::HandleType {
        self.hwnd
    }

    fn handle_mut(&mut self) -> &mut Self::HandleType {
        &mut self.hwnd
    }

    fn into_handle(self) -> Self::HandleType {
        let h = self.hwnd;
        std::mem::forget(self);
        h
    }
}

impl RemoteWindow {
    pub fn from_handle(hwnd: HWND) -> Result<Self, Box<dyn std::error::Error>> {
        let mut pid: u32 = 0;
        let tid = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };

        if tid == 0 {
            return Err("Failed to get window thread/process ID".into());
        }

        Ok(Self {
            hwnd,
            pid,
            tid,
        })
    }

    pub fn set_windows_hook_ex(&self, hook_id: WINDOWS_HOOK_ID, hook_func: Option<Hook>, module: Option<&RemoteModule>) -> Result<RemoteHook, Box<dyn std::error::Error>> {
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