use tryolib::process::MMapPath;
use tryolib::process::ProcessManager;

fn main() {
    let process_manager = ProcessManager::new("ac_client").unwrap();
    let response = process_manager.read::<u8>(0x5588369b6da8).unwrap();
    println!("{:?}", response);
    let find = process_manager
        .find::<&[u8]>(b"\xff\x8b??\xd9\xff\x51", Some(MMapPath::Heap))
        .unwrap();
    println!("{:X}", find);
    let write = process_manager
        .write::<&[u8]>(find, b"\xff\xff\xff\xff")
        .unwrap();
    println!("{}", write);

    loop {
        process_manager
            .write::<&[u8]>(0x5588369b6da8, &20u32.to_le_bytes())
            .unwrap();
    }
}
