# Tryolite

This is a rust library, to easily change the memory of processes on linux.
This library is under heavy development and i do not recommend using it.


## Usage

```rust
    use process::MMapPath;
    use process::ProcessManager;

    let process_manager = ProcessManager::new("ac_client").unwrap();
    
    // read at the specified address
    let response = process_manager.read::<u8>(0x5588369b6da8).unwrap();
    
    // find the signature in the specified memory region, returns an address
    let find = process_manager
        .find::<&[u8]>(b"\xff\x8b\xff\xd9\xff\x51", Some(MMapPath::Heap))
        .unwrap();
    println!("{:X}", find);

    // write directly after the specified address
    let write = process_manager.write(find, b"\xff\xff\xff\xff").unwrap();
    println!("{}", write);
```

## License

This project is published under the MIT license.