# Tryolite

This is a rust library, to easily change the memory of processes on linux.
This library is under heavy development and i do not recommend using it.


## Usage

**Note** this example may not be up-to-date.
Consider looking at the code in `src/bin/main.rs`

```rust
use tryolib::process::MMapPath;
use tryolib::process::ProcessManager;

fn main() {
    let process_manager = ProcessManager::new("ac_client").unwrap();
    let response = process_manager.read::<u8>(0x5588369b6da8).unwrap();
    println!("{:?}", response);
    let find = process_manager
        .find::<&[u8]>(b"\xff\x8b\xff\xd9\xff\x51", Some(MMapPath::Heap))
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

```

## License

This project is published under the MIT license.