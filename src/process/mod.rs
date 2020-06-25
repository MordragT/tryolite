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
    nix::sys::uio,
    nix::sys::uio::IoVec,
    nix::sys::uio::RemoteIoVec,
    nix::unistd::Pid,
    procfs::process::Process as LinuxProcess,
    regex::Regex,
    goblin::Object,
    std::path::PathBuf,
    nix::sys::signal::{self, Signal},
    std::io::SeekFrom,
    dynasmrt::{DynasmApi, DynasmLabelApi},
    dynasmrt::x64::Assembler,
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
    ) -> Result<MemoryModuleManager, &str> {
        MemoryModuleManager::new(region, permissions, self)
    }

    #[cfg(target_os = "linux")]
    pub fn find_ld(&self) -> Result<(PathBuf, usize), &str> {
        let linux_process = LinuxProcess::new(self.pid).unwrap();
        let re = Regex::new(r".*/ld-.*\.so").unwrap();
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
    pub fn inject<P: AsRef<Path> + std::fmt::Display>(&self, shared_library: P) {
        const STACK_BACKUP_SIZE: usize = 8 * 16;
        const STAGE_TWO_SIZE: u32 = 0x8000;
        let ld = self.find_ld().unwrap();
        let dl_open_address = ld.1 + find_elf_symbol(&ld.0, "_dl_open").unwrap();
        signal::kill(Pid::from_raw(self.pid), Signal::SIGSTOP).unwrap();
        // check if process really stopped ?
        let mut syscall_file = File::open(format!("/proc/{}/syscall", self.pid)).unwrap();
        let mut syscall_buffer = String::new();
        syscall_file.read_to_string(&mut syscall_buffer).unwrap();
        syscall_buffer.pop();
        let syscall_buffer: Vec<&str> = syscall_buffer.rsplit(" ").collect();
        println!("{:?}", syscall_buffer);
        let current_rip =
            usize::from_str_radix(syscall_buffer[0].trim_start_matches("0x"), 16).unwrap();
        let current_rsp =
            usize::from_str_radix(syscall_buffer[1].trim_start_matches("0x"), 16).unwrap();

        let mut ops = Assembler::new().unwrap();

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

            ; mov rax, 2
            ; lea rdi, [>path]
            ; xor rsi, rsi
            ; xor rdx, rdx
            ; syscall
            ; mov r14, rax

            ; mov rax, 9
            ; xor rdi, rdi
            ; mov rsi, STAGE_TWO_SIZE as _
            ; mov rdx, 0x7
            ; mov r10, 0x2
            ; mov r8, r14
            ; xor r9, r9
            ; syscall
            ; mov r15, rax

            ; mov rax, 3
            ; mov rdi, r14
            ; syscall

            ; mov rax, 87
            ; lea rdi, [>path]
            ; syscall

            ; jmp r15
            ; path:
            ; .bytes "/tmp/stage_two.bin".as_bytes()
        );

        let shell_code_buf = ops.finalize().unwrap();

        println!("{:?}", shell_code_buf);

        // let mut shell_code_bin = compile(shell_code.as_str(), None).unwrap();
        // let mut shell_code_buf = Vec::new();
        // shell_code_bin.read_to_end(&mut shell_code_buf).unwrap();

        let mut mem_file = File::open(format!("/proc/{}/mem", self.pid)).unwrap();
        mem_file.seek(SeekFrom::Start(current_rip as u64)).unwrap();
        let mut code_backup = vec![0; shell_code_buf.len()];
        mem_file.read_exact(code_backup.as_mut_slice()).unwrap();
        let mut code_fmt = format!("{:?}", code_backup);
        code_fmt.pop();
        code_fmt.remove(0);

        mem_file
            .seek(SeekFrom::Start(
                current_rsp as u64 - STACK_BACKUP_SIZE as u64,
            ))
            .unwrap();
        let mut stack_backup = vec![0; STACK_BACKUP_SIZE];
        mem_file.read_exact(stack_backup.as_mut_slice()).unwrap();
        let mut stack_fmt = format!("{:?}", stack_backup);
        stack_fmt.pop();
        stack_fmt.remove(0);

        // let mut mem_file = File::open(format!("/proc/{}/mem", self.pid)).unwrap();
        // mem_file.seek(SeekFrom::Start(rip as u64)).unwrap();
        // mem_file.write_all(shell_code_buf.as_slice()).unwrap();

        dynasm!(ops
            ; cld
            ; fxsave [>moar_regs]

            ; mov rax, 2
            ; lea rdi, [>proc_self_mem]
            ; mov rsi, 2
            ; xor rdx, rdx
            ; syscall
            ; mov r15, rax

            ; mov rax, 8
            ; mov rdi, r15
            ; mov rsi, current_rip as _
            ; xor rdx, rdx
            ; syscall

            ; mov rax, 1
            ; mov rdi, r15
            ; lea rsi, [>old_code]
            ; mov rdx, code_backup.len() as _
            ; syscall

            ; mov rax, 3
            ; mov rdi, r15
            ; syscall

            ; lea rdi, [>new_stack_base - (STACK_BACKUP_SIZE as isize)]
            ; mov rsi, current_rsp - STACK_BACKUP_SIZE as _
            ; mov rcx, STACK_BACKUP_SIZE as _
            ; rep movsb

            ; mov rdi, current_rsp - STACK_BACKUP_SIZE as _
            ; lea rsi, [>old_stack]
            ; mov rcx, STACK_BACKUP_SIZE as _
            ; rep movsb
            ; lea rsp, [>new_stack_base - (STACK_BACKUP_SIZE as isize)]

            ; lea rdi, [>lib_path]
            ; mov rsi, 2
            ; xor rcx, rcx
            ; mov rax, dl_open_address as _
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
            ; mov rsp, rsp
            ; jmp >old_rip

            ; old_rip:
            ; .qword current_rip as _

            ; old_code:
            ; .bytes code_backup.as_slice()

            ; old_stack:
            ; .bytes stack_backup.as_slice()
            ; .align 16

            ; moar_regs:
            ; .space 512

            ; lib_path:
            ; .bytes shared_library.as_bytes()

            ; proc_self_mem:
            ; .bytes "/proc/self/mem".as_bytes()

            ; new_stack:
            ; .align 0x8000

            ; new_stack_base:
        );
        // code_bak = code_fmt,
        // stack_bak = stack_fmt,
        // lib_path = shared_library,
        // rip = rip,
        // rsp = rsp,
        // backup_len = code_backup.len(),
        // stack = STACK_BACKUP_SIZE,
        // rsp_stack = rsp - STACK_BACKUP_SIZE,
        // dl_open_addr = dl_open_address

        println!("{}", stage_two);

        let mut stage_two_bin = compile(stage_two.as_str(), Some("stage_two")).unwrap();
        let mut stage_two_buf = Vec::new();
        stage_two_bin.read_to_end(&mut stage_two_buf).unwrap();
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
