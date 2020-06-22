#[rustfmt::skip]
use {
    crate::process::ProcessManager,
    procfs::process::MMapPath,
    crate::common::EndianRead,
    procfs::process::Process as LinuxProcess,
};
#[cfg(target_os = "linux")]
pub struct MemoryModuleManager<'a> {
    pub address: (usize, usize),
    pub perms: String,
    pub pathname: MMapPath,
    process: &'a ProcessManager,
}

#[cfg(target_os = "linux")]
impl<'a> MemoryModuleManager<'a> {
    /// Creates new MemoryModuleManager
    pub fn new(
        region: MMapPath,
        permissions: Option<&str>,
        process: &'a ProcessManager,
    ) -> Result<MemoryModuleManager<'a>, &'a str> {
        let linux_process = LinuxProcess::new(process.pid).unwrap();
        match linux_process.maps().unwrap().iter().find(|&x| {
            if let Some(perms) = permissions {
                return x.pathname == region && x.perms == perms;
            }
            x.pathname == region
        }) {
            Some(memory_map) => {
                return Ok(MemoryModuleManager {
                    address: (memory_map.address.0 as usize, memory_map.address.1 as usize),
                    perms: memory_map.perms.clone(),
                    pathname: memory_map.pathname.clone(),
                    process,
                })
            }
            None => return Err("Memory region not found."),
        }
    }

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
