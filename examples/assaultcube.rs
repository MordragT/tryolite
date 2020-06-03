use std::path::PathBuf;
use tryolib::process::MMapPath;
use tryolib::process::ProcessManager;

fn main() {
    let process_manager = ProcessManager::new::<&[u8]>("ac_client").unwrap();

    let path = PathBuf::from(r"/usr/bin/ac_client");
    let memory_map = process_manager
        .new_memory_map_manager(MMapPath::Path(path), Some("r-xp"))
        .unwrap();
    println!("{:x}, {:x}", memory_map.address.0, memory_map.address.1);
    //let offset = memory_map.find_address_offset(0x0000561258f90e43).unwrap();
    //println!("{:x}", offset);

    // offset discovery showed, the offset=96e43
    let offset = 0x96e43;

    // 0x5653554cac40
    // 0x565354c52b20 + 0x2f0/4/8/c 0x300/4/8/c/10/14 0x38c
    // je 0x565351bb4e81/4760/4e81/4ea

    let address = memory_map.find_total_address(offset).unwrap();
    let res = nix::sys::ptrace::read(
        nix::unistd::Pid::from_raw(process_manager.process.pid()),
        address as *mut std::ffi::c_void,
    );

    println!("{:?}", res);

    let mut values = memory_map.read_len(offset, 7).unwrap();
    values.push(0);
    let mut array = [0; 8];
    array.copy_from_slice(values.as_slice());
    let offset_add = usize::from_be_bytes(array);
    println!("{:x}", offset_add);

    // let ptr = unsafe { *first_ptr } as *const usize;

    // println!("Address: {:x}, Pointer: {:?}", address, ptr);

    // let value = unsafe { *ptr };
    // println!("{}", value);

    //process_manager.find_address_offset(0x0000561258f90e43, MMapPath::P)
    //process_manager.read_len(0x0000561258f90e43, buffer_len)

    /*let wild = process_manager
        .find_with_wildcard::<&[u8]>("07 :: :: :: 05", Some(MMapPath::Heap))
        .unwrap();
    println!("{:X}", wild);

    let find = process_manager
        .find_signature_address(b"\x1d\xb5\x15\x97\x0b", MMapPath::Heap)
        .unwrap();
    println!("{:X}", find);

    //let _response = process_manager.read::<&[u8]>(0x5588369b6da8);

    //let _write = process_manager.write::<&[u8]>(find, b"\x00\x99\x99\x00");

    loop {
        process_manager.write::<&[u8]>(0x5588369b6da8, &20u32.to_le_bytes());
    }
    */
}
