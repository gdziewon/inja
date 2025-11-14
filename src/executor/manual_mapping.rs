use dynasmrt::{dynasm, DynasmApi};

use crate::wrappers::{
    AllocatedMemory, RemoteAllocator, RemoteProcess, LocalProcess
};

use super::ExecutionMethod;
pub(super) struct ManualMapExecutor;

impl ExecutionMethod for ManualMapExecutor {
    fn execute(
        remote_process: &RemoteProcess,
        inject_func_addr: usize,
        dll_path_mem_alloc: &AllocatedMemory,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !is_correct_target_arch(remote_process)? {
            return Err("unable to manual map; target process binary architecture differs from injector's".into())
        }

        let stub = build_shcode(
            dll_path_mem_alloc.as_ptr() as u64,
            inject_func_addr as u64,
        )?;

        Ok(())
    }
}

// TBD: Should this fn be used for every method
fn is_correct_target_arch(remote_process: &RemoteProcess) -> Result<bool, Box<dyn std::error::Error>> {
    let inja_process = LocalProcess::new();

    let is_target_same_arch = inja_process.is_wow64()? == remote_process.is_wow64()?;
    Ok(is_target_same_arch)
}

fn build_shcode(
    dll_path_ptr: u64,
    inject_func_ptr: u64
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut ops: dynasmrt::Assembler<dynasmrt::x64::X64Relocation> = dynasmrt::x64::Assembler::new()?;

    dynasm!(ops
        ; .arch x64
        ; sub rsp, 0x20 // shadow space
        ; sub rsp, 0x8  // align stack to 16 bytes (because call later pushes 8 bytes)

        ; mov rcx, QWORD dll_path_ptr as i64
        ; mov rax, QWORD inject_func_ptr as i64
        ; call rax

        ; add rsp, 0x28

        ; ret
    );

    let buf = ops.finalize().unwrap();
    println!("{:#04X?}, length: {}", buf.to_vec(), buf.to_vec().len());
    Ok(buf.to_vec())
}