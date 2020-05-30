mod process;

use process::MMapPath;
use process::ProcessManager;
//use procfs::process::MMapPath;

fn main() {
    let process_manager = ProcessManager::new("ac_client").unwrap();
    let response = process_manager.read::<u8>(0x5588369b6da8).unwrap();
    println!("{:?}", response);
    let find = process_manager
        .find::<&[u8]>(b"\xff\x8b\xff\xd9\xff\x51", Some(MMapPath::Heap))
        .unwrap();
    println!("{:X}", find);
    let write = process_manager.write(find, b"\xff\xff\xff\xff").unwrap();
    println!("{}", write);
}
