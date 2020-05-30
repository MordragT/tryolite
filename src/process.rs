use nix::sys::uio;
use nix::sys::uio::IoVec;
use nix::sys::uio::RemoteIoVec;
use nix::unistd::Pid;
pub use procfs::process::MMapPath;
use procfs::process::MemoryMap;
use procfs::process::Process;

pub struct ProcessManager {
    process: Process,
    maps: Vec<MemoryMap>,
}

impl ProcessManager {
    /// Creates a new ProcessManager
    pub fn new(name: &str) -> Result<ProcessManager, &str> {
        for process in procfs::process::all_processes().unwrap() {
            if process.stat.comm == name {
                println!("Process {} found.", name);
                let maps = process.maps().unwrap();
                return Ok(ProcessManager { process, maps });
            }
        }
        Err("Process not found")
    }

    /// Reads memory starting at the given offset-address
    pub fn read<T>(&self, address: usize) -> Result<Vec<u8>, &str> {
        let remote = [RemoteIoVec {
            base: address,
            len: std::mem::size_of::<T>(),
        }];
        let mut buffer = vec![0u8; std::mem::size_of::<T>()];
        let local = [IoVec::from_mut_slice(&mut buffer)];
        match uio::process_vm_readv(Pid::from_raw(self.process.pid), &local, &remote) {
            Ok(x) if x > 0 => return Ok(buffer),
            _ => return Err("Process memory could not be read."),
        }
    }

    /// Returns how many bytes were written
    pub fn write<T: Into<Vec<u8>>>(&self, address: usize, payload: T) -> Result<usize, &str> {
        let remote = [RemoteIoVec {
            base: address,
            len: std::mem::size_of::<T>(),
        }];
        let payload: Vec<u8> = payload.into();
        let local = [IoVec::from_slice(payload.as_slice())];
        match uio::process_vm_writev(Pid::from_raw(self.process.pid), &local, &remote) {
            Ok(x) if x > 0 => return Ok(x),
            _ => return Err("Process memory could not be written."),
        }
    }

    /// Finds a signature and returns its address
    pub fn find<T: Into<Vec<u8>>>(
        &self,
        signature: T,
        module: Option<MMapPath>,
    ) -> Result<usize, &str> {
        let (mut start, end) = match module {
            Some(module_path) => {
                let mut result = (0, 0);
                for map in self.maps.iter() {
                    if map.pathname == module_path {
                        result = (map.address.0 as usize, map.address.1 as usize);
                        break;
                    }
                }
                result
            }
            None => {
                let mut result = (0, 0);
                for map in self.maps.iter() {
                    if map.perms == "r-xp" {
                        result = (map.address.0 as usize, map.address.1 as usize);
                        break;
                    }
                }
                result
            }
        };

        let signature: Vec<u8> = signature.into();

        while start < end {
            match self.read::<T>(start) {
                Ok(mut vec) => {
                    let mut offset = std::mem::size_of::<T>();
                    while vec.len() >= signature.len() {
                        if vec.ends_with(signature.as_slice()) {
                            return Ok(start + offset);
                        }
                        vec.pop();
                        offset -= 1;
                    }
                    start += std::mem::size_of::<T>();
                }
                Err(_) => break,
            }
        }
        Err("Signature not found.")
    }
}
