#[rustfmt::skip]
use {
    crate::common,
    crate::common::EndianRead,
    crate::impl_EndianRead,
    sysinfo::{SystemExt, ProcessExt, System},
    std::fs,
    std::fs::File,
    std::path::Path,
    std::io::prelude::*,
};

#[rustfmt::skip]
#[cfg(target_os = "linux")]
use {
    std::fs::OpenOptions,
    std::ptr,
    nix::sys::uio,
    nix::sys::uio::IoVec,
    nix::sys::uio::RemoteIoVec,
    nix::unistd::Pid,
    nix::sys::mman::{self, ProtFlags, MapFlags},
    nix::fcntl::OFlag,
    nix::sys::stat::Mode,
    nix::unistd,
    procfs::process::Process as LinuxProcess,
    regex::Regex,
    goblin::Object,
    std::path::PathBuf,
    nix::sys::signal::{self, Signal, SigevNotify, SigEvent},
    std::io::SeekFrom,
    dynasmrt::{DynasmApi, DynasmLabelApi, VecAssembler},
    dynasmrt::x64::X64Relocation,
    dynasm::dynasm,
};

#[rustfmt::skip]
#[cfg(target_os = "linux")]
pub use {
    procfs::process::MMapPath,
    memory_module::*,
};

#[rustfmt::skip]
#[cfg(target_os = "windows")]
use {
    winapi::um::memoryapi,
};

#[cfg(target_os = "linux")]
pub mod memory_module;

// TODO find similarities in memory
// TODO calculate module offset of address

impl_EndianRead!(u8, u16, u32, u64);
impl_EndianRead!(i8, i16, i32, i64);
impl_EndianRead!(usize, isize);

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
    /// Writes with a syscall, do not use it for cheats
    #[cfg(target_os = "linux")]
    pub fn write(&self, address: usize, payload: &[u8]) -> Result<usize, &str> {
        let remote = [RemoteIoVec {
            base: address,
            len: self.buffer_size,
        }];
        let local = [IoVec::from_slice(payload)];
        match uio::process_vm_writev(Pid::from_raw(self.pid), &local, &remote) {
            Ok(x) if x > 0 => return Ok(x),
            Err(e) => {
                println!("{:?}", e);
                return Err("Process memory could not be written.");
            }
            _ => return Err("Process memory could not be written."),
        }
    }

    /// Writes into the mem file of the proc filesystem
    #[cfg(target_os = "linux")]
    pub fn write_anon(&self, address: usize, payload: &[u8]) -> std::io::Result<()> {
        let mut mem_file = OpenOptions::new()
            .write(true)
            .open(format!("/proc/{}/mem", self.pid))
            .unwrap();
        mem_file.seek(SeekFrom::Start(address as u64))?;
        mem_file.write_all(payload)?;
        Ok(())
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
    ) -> Result<MemoryModuleManager, &str> {
        MemoryModuleManager::new(region, permissions, self)
    }

    /// Find memory module with given regex
    #[cfg(target_os = "linux")]
    pub fn find_regex(&self, regex: &str) -> Result<(PathBuf, usize), &str> {
        let linux_process = LinuxProcess::new(self.pid).unwrap();
        let re = Regex::new(regex).unwrap();
        let mut path = None;
        match linux_process.maps().unwrap().iter().find(|&x| {
            if let MMapPath::Path(path_buf) = &x.pathname {
                if re.is_match(path_buf.to_str().unwrap()) {
                    path = Some(path_buf.clone());
                    return true;
                }
            }
            return false;
        }) {
            Some(mem_map) => return Ok((path.unwrap(), mem_map.address.0 as usize)),
            None => return Err("Ld could not be found."),
        }
    }

    /// Injects a Shared Library
    #[cfg(target_os = "linux")]
    pub fn inject<P: AsRef<Path>>(&self, shared_library: P) {
        const STACK_BACKUP_SIZE: usize = 8 * 16;
        const STAGE_TWO_SIZE: u32 = 0x8000;

        let ld = self.find_regex(r".*/ld-.*\.so").unwrap();
        let librt = self.find_regex(r".*/librt-.*\.so").unwrap();

        let dl_open_address = ld.1 + find_elf_symbol(&ld.0, "_dl_open").unwrap();
        let shm_open_address = librt.1 + find_elf_symbol(&librt.0, "shm_open").unwrap();
        let shm_unlink_address = librt.1 + find_elf_symbol(&librt.0, "shm_unlink").unwrap();

        signal::kill(Pid::from_raw(self.pid), Signal::SIGSTOP).unwrap();

        // check if process really stopped ?
        std::thread::sleep_ms(500);

        let mut syscall_file = File::open(format!("/proc/{}/syscall", self.pid)).unwrap();
        let mut syscall_buffer = String::new();
        syscall_file.read_to_string(&mut syscall_buffer).unwrap();
        syscall_buffer.pop();
        let syscall_buffer: Vec<&str> = syscall_buffer.rsplit(" ").collect();

        let current_rip =
            usize::from_str_radix(syscall_buffer[0].trim_start_matches("0x"), 16).unwrap();
        let current_rsp =
            usize::from_str_radix(syscall_buffer[1].trim_start_matches("0x"), 16).unwrap();

        println!("Instruction Pointer: {:x}", current_rip);
        let mut ops: VecAssembler<X64Relocation> = VecAssembler::new(0x00);

        dynasm!(ops
            ; pushf
            ; push rax
            ; push rbx
            ; push rcx
            ; push rdx
            ; push rbp
            ; push rsi
            ; push rdi
            ; push r8
            ; push r9
            ; push r10
            ; push r11
            ; push r12
            ; push r13
            ; push r14
            ; push r15

            // Open shared memory object: stage two
            ; mov rdi, [>shared_object]
            ; mov rsi, 1
            ; mov rax, QWORD shm_open_address as i64
            ; call rax
            ; mov r14, rax

            // mmap it
            ; mov rax, 9
            ; xor rdi, rdi
            ; mov rsi, DWORD STAGE_TWO_SIZE as i32
            ; mov rdx, 0x7
            ; mov r10, 0x2
            ; mov r8, r14
            ; xor r9, r9
            ; syscall
            ; mov r15, rax

            // close the file
            ; mov rax, 3
            ; mov rdi, r14
            ; syscall

            // Unlink shared memory object
            ; mov rdi, [>shared_object]
            ; mov rax, QWORD shm_unlink_address as i64
            ; call rax

            ; shared_object:
            ; .bytes "/stage_two".as_bytes()
        );

        let shell_code_buf = ops.finalize().unwrap();

        let mut mem_file = File::open(format!("/proc/{}/mem", self.pid)).unwrap();
        mem_file.seek(SeekFrom::Start(current_rip as u64)).unwrap();
        let mut code_backup = vec![0; shell_code_buf.len()];
        mem_file.read_exact(code_backup.as_mut_slice()).unwrap();

        mem_file
            .seek(SeekFrom::Start(
                current_rsp as u64 - STACK_BACKUP_SIZE as u64,
            ))
            .unwrap();
        let mut stack_backup = vec![0; STACK_BACKUP_SIZE];
        mem_file.read_exact(stack_backup.as_mut_slice()).unwrap();

        let mut ops: VecAssembler<X64Relocation> = VecAssembler::new(0x00);

        dynasm!(ops
            ; cld
            ; fxsave [>moar_regs]

            // Open /proc/self/mem
            ; mov rax, 2
            ; lea rdi, [>proc_self_mem]
            ; mov rsi, 2
            ; xor rdx, rdx
            ; syscall
            ; mov r15, rax

            // seek to code
            ; mov rax, 8
            ; mov rdi, r15
            ; mov rsi, QWORD current_rip as i64
            ; xor rdx, rdx
            ; syscall

            // restore code
            ; mov rax, 1
            ; mov rdi, r15
            ; lea rsi, [>old_code]
            ; mov rdx, code_backup.len() as _
            ; syscall

            // close /proc/self/mem
            ; mov rax, 3
            ; mov rdi, r15
            ; syscall

            // move pushed regs to our new stack
            ; lea rdi, [>new_stack_base - (STACK_BACKUP_SIZE as isize)]
            ; mov rsi, QWORD (current_rsp - STACK_BACKUP_SIZE) as i64
            ; mov rcx, DWORD STACK_BACKUP_SIZE as i32
            ; rep movsb

            // restore original stack
            ; mov rdi, QWORD (current_rsp - STACK_BACKUP_SIZE) as i64
            ; lea rsi, [>old_stack]
            ; mov rcx, DWORD STACK_BACKUP_SIZE as i32
            ; rep movsb

            ; lea rsp, [>new_stack_base - (STACK_BACKUP_SIZE as isize)]

            // call _dl_open
            ; lea rdi, [>lib_path]
            ; mov rsi, 2
            ; xor rcx, rcx
            ; mov rax, QWORD dl_open_address as i64
            ; call rax

            ; fxrstor [>moar_regs]
            ; pop r15
            ; pop r14
            ; pop r13
            ; pop r12
            ; pop r11
            ; pop r10
            ; pop r9
            ; pop r8
            ; pop rdi
            ; pop rsi
            ; pop rbp
            ; pop rdx
            ; pop rcx
            ; pop rdx
            ; pop rax
            ; popf
            ; mov rsp, QWORD current_rsp as i64
            ; jmp QWORD [>old_rip]

            ; old_rip:
            ; .qword current_rip as i64

            ; old_code:
            ; .bytes code_backup.as_slice()

            ; old_stack:
            ; .bytes stack_backup.as_slice()
            ; .align 16

            ; moar_regs:
            //; .space 512

            ; lib_path:
            ; .bytes shared_library.as_ref().to_str().unwrap().as_bytes()

            ; proc_self_mem:
            ; .bytes "/proc/self/mem".as_bytes()

            ; new_stack:
            ; .align 0x8000

            ; new_stack_base:
        );

        let injection_buf = ops.finalize().unwrap();

        let shared_fd =
            mman::shm_open("/stage_two", OFlag::O_CREAT | OFlag::O_RDWR, Mode::S_IWUSR).unwrap();
        unistd::ftruncate(shared_fd, injection_buf.len() as i64).unwrap();
        let shared_data = unsafe {
            mman::mmap(
                0 as *mut std::ffi::c_void,
                injection_buf.len(),
                ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                shared_fd,
                0,
            )
            .unwrap()
        };
        unsafe {
            ptr::copy_nonoverlapping(
                injection_buf.as_ptr(),
                shared_data as *mut u8,
                injection_buf.len(),
            );
            mman::munmap(shared_data, injection_buf.len()).unwrap();
            unistd::close(shared_fd).unwrap();
        }

        self.write_anon(current_rip, shell_code_buf.as_slice())
            .unwrap();
        signal::kill(Pid::from_raw(self.pid), Signal::SIGCONT).unwrap();

        println!("Injection was succesfull");
    }
}

/// Searches for Symbol in Elf File and Returns its offset
#[cfg(target_os = "linux")]
pub fn find_elf_symbol<P: AsRef<Path>>(elf_path: P, sym_name: &str) -> Result<usize, &'static str> {
    let buffer = std::fs::read(elf_path).unwrap();
    let elf_option = match Object::parse(&buffer).unwrap() {
        Object::Elf(elf) => Some(elf),
        _ => None,
    };
    if let Some(elf) = elf_option {
        for sym in elf.syms.iter() {
            if let Some(Ok(name)) = elf.strtab.get(sym.st_name) {
                if name == sym_name {
                    return Ok(sym.st_value as usize);
                }
            }
        }
        for sym in elf.dynsyms.iter() {
            if let Some(Ok(name)) = elf.dynstrtab.get(sym.st_name) {
                if name == sym_name {
                    return Ok(sym.st_value as usize);
                }
            }
        }
    } else {
        return Err("The given file was no Elf file.");
    }
    Err("Could not find Symbol.")
}

/// Compiles given Assembler-Code and returns File to the binary
// pub fn compile(code: &str, out: Option<&str>) -> Result<File, std::io::Error> {
//     let mut code_file = File::create("/tmp/code.s").unwrap();
//     code_file.write(code.as_bytes()).unwrap();
//     let binary_name = match out {
//         Some(name) => String::from(name),
//         _ => format!("binary{}", rand::random::<u16>()),
//     };
//     cc::Build::new()
//         .file("/tmp/code.s")
//         .out_dir("/tmp/")
//         .host("x86_64-unknown-linux-gnu")
//         .target("x86_64-unknown-linux-gnu")
//         .opt_level(3)
//         .compile(binary_name.as_str());
//     fs::remove_file("/tmp/code.s").unwrap();
//     File::open(format!("/tmp/lib{}.a", binary_name))
// }

pub fn wildcard_str_to_hex(string: &str) -> Result<Vec<(u8, usize)>, &str> {
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
