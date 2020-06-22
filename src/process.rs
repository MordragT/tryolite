#[rustfmt::skip]
use {
    crate::common,
    crate::common::EndianRead,
    crate::impl_EndianRead,
    sysinfo::{SystemExt, ProcessExt, System},
};

#[rustfmt::skip]
#[cfg(target_os = "linux")]
use {
    nix::sys::uio,
    nix::sys::uio::IoVec,
    nix::sys::uio::RemoteIoVec,
    nix::unistd::Pid,
    procfs::process::Process as LinuxProcess,
};

#[cfg(target_os = "linux")]
pub use procfs::process::MMapPath;

#[rustfmt::skip]
#[cfg(target_os = "windows")]
use {
    winapi::um::memoryapi,
};
// TODO module mamnager based on MMapPath, like process_manager.heap.find(b"\xA3");
// TODO find similarities in memory
// TODO calculate module offset of address

impl_EndianRead!(u8, u16, u32, u64);
impl_EndianRead!(i8, i16, i32, i64);
impl_EndianRead!(usize, isize);

#[cfg(target_os = "linux")]
pub struct MemoryMapManager<'a> {
    pub address: (usize, usize),
    pub perms: String,
    pub pathname: MMapPath,
    process: &'a ProcessManager,
}

#[cfg(target_os = "linux")]
impl<'a> MemoryMapManager<'a> {
    /// Read bytes in the memory region at the specified offset
    pub fn read(&self, offset: usize) -> Result<Vec<u8>, &str> {
        let final_address = offset + self.address.0;
        if final_address >= self.address.1 {
            return Err("Address is out of range.");
        }
        self.process.read(final_address)
    }
    /// Read bytes in the memory region with a specified buffer length at the specified offset
    pub fn read_len(&self, offset: usize, buffer_len: usize) -> Result<Vec<u8>, &str> {
        let final_address = offset + self.address.0;
        if final_address >= self.address.1 {
            return Err("Address is out of range.");
        }
        self.process.read_len(final_address, buffer_len)
    }
    /// Read a 32 bit value as a specified type on the given offset
    pub fn read_32<T: EndianRead<Array = [u8; 4]>>(&self, offset: usize) -> Result<T, &str> {
        let final_address = offset + self.address.0;
        if final_address > self.address.1 {
            return Err("Address is out of range.");
        }
        self.process.read_32(final_address)
    }
    /// Writes bytes into the memory region
    pub fn write(&self, offset: usize, payload: &[u8]) -> Result<usize, &str> {
        let final_address = offset + self.address.0;
        if final_address >= self.address.1 {
            return Err("Address is out of range.");
        }
        self.process.write(final_address, payload)
    }
    /// Finds the signature in the memory region
    pub fn find_signature(&self, signature: &[u8]) -> Result<usize, &str> {
        self.process
            .find_signature(signature, self.address.0, self.address.1)
    }
    /// Finds the wildcard signature in the memory region
    pub fn find_wildcard(&self, signature: &str) -> Result<usize, &str> {
        self.process
            .find_wildcard(signature, self.address.0, self.address.1)
    }
    /// Finds the offset of a address in the Memory Map
    pub fn find_address_offset(&self, address: usize) -> Result<usize, &str> {
        if address <= self.address.0 || address >= self.address.1 {
            return Err("Address is out of range.");
        }
        Ok(address - self.address.0)
    }
    /// Finds the total address of an offset
    pub fn find_total_address(&self, offset: usize) -> Result<usize, &str> {
        let total = offset + self.address.0;
        if total > self.address.1 {
            return Err("Address is out of range.");
        }
        Ok(total)
    }
}
/// External Process Manager, uses kernel calls to change memory
pub struct ProcessManager {
    pub pid: i32,
    buffer_size: usize,
}

impl ProcessManager {
    /// Creates a new ProcessManager
    pub fn new<T: Into<Vec<u8>>>(name: &str) -> Result<ProcessManager, &str> {
        let system = System::new_all();
        let process_list = system.get_process_by_name(name);
        if !process_list.is_empty() {
            let pid = process_list[0].pid();
            println!("Process {} found with id: {}", name, pid);
            let buffer_size = std::mem::size_of::<T>() * 4;
            return Ok(ProcessManager { pid, buffer_size });
        }
        Err("Process not found")
    }
    /// Reads memory starting at the given offset-address
    pub fn read(&self, address: usize) -> Result<Vec<u8>, &str> {
        self.read_len(address, self.buffer_size)
    }

    /// Reads memory with the specified buffer_len
    #[cfg(target_os = "linux")]
    pub fn read_len(&self, address: usize, buffer_len: usize) -> Result<Vec<u8>, &str> {
        let remote = [RemoteIoVec {
            base: address,
            len: buffer_len,
        }];
        let mut buffer = vec![0u8; buffer_len];
        let local = [IoVec::from_mut_slice(&mut buffer)];
        match uio::process_vm_readv(Pid::from_raw(self.pid), &local, &remote) {
            Ok(x) if x > 0 => return Ok(buffer),
            _ => return Err("Process memory could not be read."),
        }
    }

    /// Reads memory with the specified buffer_len
    #[cfg(target_os = "windows")]
    pub fn read_len(&self, address: usize, buffer_len: usize) -> Result<Vec<u8>, &str> {}

    /// Read memory at the specified address and returns the type of the generic parameter
    pub fn read_32<T: EndianRead<Array = [u8; 4]>>(&self, address: usize) -> Result<T, &str> {
        match self.read_len(address, std::mem::size_of::<T>()) {
            Ok(buffer) => {
                let mut array = [0; 4];
                array.copy_from_slice(buffer.as_slice());
                return Ok(<T as EndianRead>::from_be_bytes(array));
            }
            Err(e) => return Err(e),
        };
    }

    /// Returns how many bytes were written
    #[cfg(target_os = "linux")]
    pub fn write(&self, address: usize, payload: &[u8]) -> Result<usize, &str> {
        let remote = [RemoteIoVec {
            base: address,
            len: self.buffer_size,
        }];
        let local = [IoVec::from_slice(payload)];
        match uio::process_vm_writev(Pid::from_raw(self.pid), &local, &remote) {
            Ok(x) if x > 0 => return Ok(x),
            _ => return Err("Process memory could not be written."),
        }
    }

    /// Returns how many bytes were written
    #[cfg(target_os = "windows")]
    pub fn write(&self, address: usize, payload: &[u8]) -> Result<usize, &str> {}

    /// Finds a signature
    /// Returns Address
    pub fn find_signature(
        &self,
        signature: &[u8],
        start_address: usize,
        end_address: usize,
    ) -> Result<usize, &str> {
        for address in (start_address..end_address).step_by(self.buffer_size) {
            let mut read_vec = self.read(address).unwrap();
            if let Some(x) = common::is_sub(&mut read_vec, &signature) {
                return Ok(start_address + x + signature.len());
            }
        }
        Err("Signature not found.")
    }

    /// Supports wildcards with :: but only takes &str
    /// find_with_wildcard("00 :: a9 :: 00 :: 32")
    /// Returns Address
    pub fn find_wildcard(
        &self,
        signature: &str,
        start_address: usize,
        end_address: usize,
    ) -> Result<usize, &str> {
        let signatures = wildcard_str_to_hex(signature).unwrap();

        for address in (start_address..end_address).step_by(self.buffer_size) {
            let mut vec = self.read(address).unwrap();
            while !vec.is_empty() {
                let mut sig_iter = signatures.iter().rev();
                let mut vec_iter = vec.iter().rev();
                let first = *sig_iter.next().unwrap();
                let first_pos_rev = match vec_iter.position(|&x| x == first.0) {
                    Some(x) => x + 1,
                    None => break,
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
        }

        Err("Signature not found.")
    }

    /// Listens on address for changes and creates signature after certain amount of changes
    // pub fn create_signatures(address: usize, changes: u8) -> Result<usize, &'static str> {
    //     Ok(0)
    // }

    /// Gets the memory region
    #[cfg(target_os = "linux")]
    pub fn new_memory_map_manager(
        &self,
        region: MMapPath,
        permissions: Option<&str>,
    ) -> Result<MemoryMapManager, &str> {
        let linux_process = LinuxProcess::new(self.pid).unwrap();
        match linux_process.maps().unwrap().iter().find(|&x| {
            if let Some(perms) = permissions {
                return x.pathname == region && x.perms == perms;
            }
            x.pathname == region
        }) {
            Some(memory_map) => {
                return Ok(MemoryMapManager {
                    address: (memory_map.address.0 as usize, memory_map.address.1 as usize),
                    perms: memory_map.perms.clone(),
                    pathname: memory_map.pathname.clone(),
                    process: self,
                })
            }
            None => return Err("Memory region not found."),
        }
    }
}

fn wildcard_str_to_hex(string: &str) -> Result<Vec<(u8, usize)>, &str> {
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
            Err(_) => {
                if sig != "::" {
                    return Err(
                        "Youre input contains non hexadecimal numbers apart from the wildcard :: .",
                    );
                }
                offset += 1
            }
        }
    }
    if result.len() == 0 {
        return Err("The signature needs atleast one hexadecimal number.");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_wildcard_str_to_hex() {
        assert_eq!(
            wildcard_str_to_hex("This is no hex string"),
            Err("Input is wrong formatted.")
        );
        assert_eq!(
            wildcard_str_to_hex(":: ::"),
            Err("The signature needs atleast one hexadecimal number.")
        );
        assert_eq!(
            wildcard_str_to_hex("   0f   :: 3f   ::      aa    "),
            Ok(vec![(0x0f, 0), (0x3f, 1), (0xaa, 1)])
        );
        assert_eq!(
            wildcard_str_to_hex("xx qq WW RR"),
            Err("Youre input contains non hexadecimal numbers apart from the wildcard :: .",)
        );
    }
}
