mod injector;
mod executor;
mod utils;
mod wrappers;

use core::fmt;
use std::{path::PathBuf, process::exit};
use clap::{Parser, ValueEnum};


use crate::injector::Injector;

#[derive(Parser, Debug)]
struct Args {
    dll_path: PathBuf, // gotta resolve it into full path

    process_name: String,

    #[clap(
        short = 'e',
        long = "exec",
        value_parser,
        default_value_t = ExecutionStrategy::CreateRemoteThread
    )]
    execution_method: ExecutionStrategy,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ExecutionStrategy {
    #[clap(name = "remote-thread")]
    CreateRemoteThread,
    #[clap(name = "nt-thread")]
    NtCreateThreadEx,
    #[clap(name = "hijack")]
    ThreadHijacking,
    #[clap(name = "hook")]
    SetWindowsHookEx,
    #[clap(name = "kct")]
    KernelCallbackTable,
    #[clap(name = "apc")]
    QueueUserAPC
}

impl fmt::Display for ExecutionStrategy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ExecutionStrategy::CreateRemoteThread => write!(f, "remote-thread"),
            ExecutionStrategy::NtCreateThreadEx => write!(f, "nt-thread"),
            ExecutionStrategy::ThreadHijacking => write!(f, "hijack"),
            ExecutionStrategy::SetWindowsHookEx => write!(f, "hook"),
            ExecutionStrategy::KernelCallbackTable => write!(f, "kct"),
            ExecutionStrategy::QueueUserAPC => write!(f, "apc"),
        }
    }
}

fn main() {
    let args = Args::parse();

    let absolute_dll_path = match args.dll_path.canonicalize() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error resolving DLL path {:?}: {}", args.dll_path, e);
            exit(1);
        }
    };

    let injector = match Injector::new(&args.process_name) {
        Ok(inj) => inj,
        Err(e) => {
            eprintln!("Error finding process '{}': {}", args.process_name, e);
            exit(1);
        }
    };

    println!(
        "Injecting {} into {} using strategy: {}",
        absolute_dll_path.display(),
        args.process_name,
        args.execution_method
    );

    if let Err(e) = injector.inject(&absolute_dll_path, args.execution_method) {
        eprintln!("Injection failed: {e}");
        exit(1);
    }

    println!("Injection successful (or trigger sent).");
}
