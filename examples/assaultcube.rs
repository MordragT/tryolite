use std::path::Path;
use std::path::PathBuf;
use tryolib::process::MMapPath;
use tryolib::process::ProcessManager;

fn main() {
    let process_manager = ProcessManager::new::<&[u8]>("ac_client").unwrap();
    process_manager.inject("/home/tom/Git/tryolite/examples/libmalloc.so");

    let path = PathBuf::from(r"/usr/bin/ac_client");
    let memory_map = process_manager
        .new_memory_map_manager(MMapPath::Path(path), Some("r-xp"))
        .unwrap();
    let find_wild = memory_map.find_wildcard("7e :: aa");
    println!("{:?}", find_wild);
}
