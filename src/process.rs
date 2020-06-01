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
    buffer_size: usize,
}

impl ProcessManager {
    /// Creates a new ProcessManager
    pub fn new<T: Into<Vec<u8>>>(name: &str) -> Result<ProcessManager, &str> {
        for process in procfs::process::all_processes().unwrap() {
            if process.stat.comm == name {
                println!("Process {} found.", name);
                let maps = process.maps().unwrap();
                let buffer_size = std::mem::size_of::<T>() * 4;
                return Ok(ProcessManager {
                    process,
                    maps,
                    buffer_size,
                });
            }
        }
        Err("Process not found")
    }

    /// Reads memory starting at the given offset-address
    pub fn read<T: Into<Vec<u8>>>(&self, address: usize) -> Result<Vec<u8>, &str> {
        let remote = [RemoteIoVec {
            base: address,
            len: self.buffer_size,
        }];
        let mut buffer = vec![0u8; self.buffer_size];
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
            len: self.buffer_size,
        }];
        let payload: Vec<u8> = payload.into();
        let local = [IoVec::from_slice(payload.as_slice())];
        match uio::process_vm_writev(Pid::from_raw(self.process.pid), &local, &remote) {
            Ok(x) if x > 0 => return Ok(x),
            _ => return Err("Process memory could not be written."),
        }
    }

    /// Finds a signature and returns its address
    // TODO rewrite with iterator instead of vec pop
    pub fn find<T: Into<Vec<u8>>>(
        &self,
        signature: T,
        module: Option<MMapPath>,
    ) -> Result<usize, &str> {
        let (mut start, end) = self.find_module_address(module).unwrap();
        let signature: Vec<u8> = signature.into();

        while start < end {
            match self.read::<T>(start) {
                Ok(mut vec) => {
                    let mut offset = self.buffer_size;
                    while vec.len() >= signature.len() {
                        if vec.ends_with(signature.as_slice()) {
                            return Ok(start + offset);
                        }
                        vec.pop();
                        offset -= 1;
                    }
                    start += self.buffer_size;
                }
                Err(_) => break,
            }
        }
        Err("Signature not found.")
    }
    /// Supports wildcards with :: but only takes &str
    /// find_with_wildcard("00 :: a9 :: 00 :: 32")
    pub fn find_with_wildcard<T: Into<Vec<u8>>>(
        &self,
        signature: &str,
        module: Option<MMapPath>,
    ) -> Result<usize, &str> {
        let signatures = string_to_hex(signature).unwrap();
        let (start, end) = self.find_module_address(module).unwrap();

        for address in (start..end).step_by(self.buffer_size) {
            let mut vec = self.read::<T>(address).unwrap();
            let mut get_address = || {
                while !vec.is_empty() {
                    let mut sig_iter = signatures.iter().rev();
                    let mut vec_iter = vec.iter().rev();
                    let first = *sig_iter.next().unwrap();
                    let first_pos_rev = match vec_iter.position(|&x| x == first.0) {
                        Some(x) => x + 1,
                        None => return Err("Not found"),
                    };
                    let mut skip = first.1;
                    let mut offset = 0;
                    for element in vec_iter.take(first_pos_rev + first.1) {
                        if skip > 0 {
                            skip -= 1;
                            continue;
                        }
                        match sig_iter.next() {
                            None => {
                                // Vector has not poped till the first object but the last first object
                                // Therefor first_pos_rev is subtracted and the end should be returned
                                return Ok(
                                    address + vec.len() - offset - first_pos_rev + signatures.len()
                                );
                            }
                            Some(x) if &x.0 != element => {
                                break;
                            }
                            Some(x) => {
                                offset += 1;
                                skip = x.1;
                            }
                        }
                    }
                    for _ in 0..first_pos_rev {
                        vec.pop();
                        offset += 1;
                    }
                }
                Err("Not found")
            };

            if let Ok(address) = get_address() {
                return Ok(address);
            }
        }

        Err("Signature not found.")
    }

    /// Finds the start and end address of a module
    fn find_module_address(&self, module: Option<MMapPath>) -> Result<(usize, usize), &str> {
        match module {
            Some(module_path) => {
                for map in self.maps.iter() {
                    if map.pathname == module_path {
                        return Ok((map.address.0 as usize, map.address.1 as usize));
                    }
                }
                return Err("Module not found.");
            }
            None => {
                for map in self.maps.iter() {
                    if map.perms == "r-xp" {
                        return Ok((map.address.0 as usize, map.address.1 as usize));
                    }
                }
                return Err("Execution module not found.");
            }
        };
    }
}

pub fn string_to_hex(string: &str) -> Result<Vec<(u8, usize)>, &str> {
    let mut result = Vec::new();
    let mut offset = 0;
    for sig in string.split_whitespace() {
        if sig.len() != 2 {
            return Err("Input is wrong formatted.");
        }
        match usize::from_str_radix(sig, 16) {
            Ok(val) => {
                let sig_hex = *val.to_be_bytes().to_vec().last().unwrap();
                result.push((sig_hex, offset));
                offset = 0;
            }
            Err(_) => offset += 1,
        }
    }
    Ok(result)
}
