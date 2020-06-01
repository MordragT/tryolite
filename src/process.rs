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
    /// Supports wildcards with :: but only takes &str
    /// find_with_wildcard("00 :: a9 :: 00 :: 32")
    pub fn find_with_wildcard<T>(
        &self,
        signature: &str,
        module: Option<MMapPath>,
    ) -> Result<usize, &str> {
        let mut signatures = Vec::new();
        let mut offset = 0;
        for sig in signature.split_whitespace() {
            match usize::from_str_radix(sig, 16) {
                Ok(val) => {
                    let sig_hex = *val.to_be_bytes().to_vec().last().unwrap();
                    signatures.push((sig_hex, offset));
                    offset = 0;
                }
                Err(_) => offset += 1,
            }
        }
        let (mut start, end) = self.find_module_address(module).unwrap();

        while start < end {
            match self.read::<T>(start) {
                Err(_) => break,
                Ok(mut vec) => {
                    let mut get_address = || {
                        let mut offset: usize = 0;
                        while !vec.is_empty() {
                            let mut sig_iter = signatures.iter().rev();
                            let mut vec_iter = vec.iter().rev();
                            let first = *sig_iter.next().unwrap();
                            let first_pos_rev = match vec_iter.position(|&x| x == first.0) {
                                Some(x) => x + 1,
                                None => return Err("Not found"),
                            };

                            let mut skip = 0;
                            for element in vec_iter.skip(first_pos_rev + first.1) {
                                if skip > 0 {
                                    skip -= 1;
                                    continue;
                                }
                                match sig_iter.next() {
                                    None => {
                                        //println!("{:?}", vec);
                                        return Ok(start + vec.len() - 1);
                                    }
                                    Some(x) if &x.0 != element => {
                                        //println!("{:?}", first_pos_rev);
                                        break;
                                    }
                                    Some(x) => {
                                        offset += 1;
                                        skip = x.1;
                                    }
                                }
                            }
                            for _ in 0..first_pos_rev {
                                offset += 1;
                                vec.pop();
                            }
                        }
                        Err("Not found")
                    };

                    if let Ok(address) = get_address() {
                        return Ok(address);
                    }
                    start += std::mem::size_of::<Vec<u8>>();
                    //println!("{}", start);
                }
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
