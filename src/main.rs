mod injector;
mod executor;
mod utils;
mod wrappers;

use std::path::PathBuf;
use clap::Parser;


use crate::executor::ExecutionStrategy;
use crate::injector::Injector;

#[derive(Parser, Debug)]
struct Args {
    dll_path: PathBuf, // gotta resolve it into full path
    process_name: String
}


fn main() {
    let args = Args::parse();
    let injector = Injector::new(&args.process_name).unwrap();
    // fixme - dont unwrap
    injector.inject(&args.dll_path.canonicalize().unwrap(), ExecutionStrategy::QueueUserAPC).unwrap();
    println!("{}", std::io::Error::last_os_error());
}
