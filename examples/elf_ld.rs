use std::path::Path;
use tryolib::process;

fn main() {
    let address_offset =
        process::find_elf_symbol(Path::new("/usr/lib/ld-2.31.so"), "_dl_open").unwrap();
    println!("Address: {:x}", address_offset);
}
