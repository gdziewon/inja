pub mod local_process;
pub mod remote_process;

pub use local_process::LocalProcess;
pub use remote_process::RemoteProcess;

pub trait Process: crate::wrappers::HandleWrapper {}