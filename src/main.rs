mod injector;
mod executor;
mod utils;

use std::path::PathBuf;
use clap::Parser;


use crate::executor::ShellcodeExecution;
use crate::injector::inject;

#[derive(Parser, Debug)]
struct Args {
    dll_path: PathBuf,
    process_name: String
}


fn main() {
    let args = Args::parse();

    inject(&args.dll_path, &args.process_name, ShellcodeExecution::NtCreateThreadEx).unwrap();
}
