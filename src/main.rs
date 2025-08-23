mod injector;
mod executor;
mod utils;
mod remote_process;
mod remote_allocator;
mod remote_thread;

use std::path::PathBuf;
use clap::Parser;


use crate::executor::ShellcodeExecution;
use crate::injector::Injector;

#[derive(Parser, Debug)]
struct Args {
    dll_path: PathBuf,
    process_name: String
}


fn main() {
    let args = Args::parse();
    let injector = Injector::new(&args.process_name).unwrap();
    injector.inject(&args.dll_path, ShellcodeExecution::ThreadHijacking).unwrap();
}
