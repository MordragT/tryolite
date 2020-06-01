# Tryolite

This is a rust library, to easily change the memory of processes on linux.
This library is under heavy development and i do not recommend using it.


## Usage

**Note** this example may not be up-to-date.
Consider looking at the code in `examples/`

```rust
use tryolib::process::MMapPath;
use tryolib::process::ProcessManager;

fn main() {
    let process_manager = ProcessManager::new::<&[u8]>("ac_client").unwrap();

    let wild = process_manager
        .find_with_wildcard::<&[u8]>("d0 99 63 5b ad 55", Some(MMapPath::Heap))
        .unwrap();
    println!("{:X}", wild);

    let find = process_manager
        .find::<&[u8]>(b"\x1d\xb5\x15\x97\x0b", Some(MMapPath::Heap))
        .unwrap();
    println!("{:X}", find);

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
}
```

## Dependencies

- nix
- procfs

## License

This project is published under the MIT license.