use tryolib::process::MMapPath;
use tryolib::process::ProcessManager;

fn main() {
    let process_manager = ProcessManager::new("ac_client").unwrap();

    let find = process_manager
        .find::<&[u8]>(b"\x00\x05\x00\x03\x00\x07", Some(MMapPath::Heap))
        .unwrap();
    println!("{:X}", find);

    let wild = process_manager
        .find_with_wildcard::<Vec<u8>>("00 05 00 :: 00 07", Some(MMapPath::Heap))
        .unwrap();
    println!("{:X}", wild);

    /*
    let response = process_manager.read::<u8>(0x5588369b6da8).unwrap();
    println!("{:?}", response);

    let write = process_manager
        .write::<&[u8]>(find, b"\x00\x99\x99\x00")
        .unwrap();
    println!("{}", write);

    loop {
        process_manager
            .write::<&[u8]>(0x5588369b6da8, &20u32.to_le_bytes())
            .unwrap();
    }
    */
}
