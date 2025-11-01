mod window;
mod process;
mod module;
mod thread;
mod snapshot;
mod memory;
mod structs;

pub use process::RemoteProcess;
pub use thread::RemoteThread;
pub use memory::{AllocatedMemory, RemoteAllocator};
pub use snapshot::{ModuleSnapshot, ProcessSnapshot, ThreadSnapshot};
pub use module::{LocalModule, Module, RemoteModule};
pub use window::Hook;
pub use structs::*;

pub trait HandleWrapper
{
    type HandleType;

    fn handle(&self) -> Self::HandleType;
    fn handle_mut(&mut self) -> &mut Self::HandleType;
}