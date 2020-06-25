#![feature(proc_macro_hygiene)]
pub mod common;
pub mod process;

// #[cfg(target_os = "linux")]
// pub mod process_linux;
// #[cfg(target_os = "linux")]
// pub use process_linux as process;

// #[cfg(windows)]
// pub mod process_windows;
// #[cfg(windows)]
// pub use process_windows as process;

// TODO create injector that searches for not allocated memory at the end of a module
// if the free memory is enough for the given shared library
// allocate memory there and create thread on the allocated memory
// between the new allocated memory and the first "real" mem there must be a buffer
