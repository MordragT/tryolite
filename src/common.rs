/// Checks if a stack is sub of another and returns the first appearance
pub fn is_sub<T: PartialEq>(mut haystack: &[T], needle: &[T]) -> Option<usize> {
    if needle.len() == 0 {
        return None;
    }
    let mut offset = 0;
    while !haystack.is_empty() {
        if haystack.starts_with(needle) {
            return Some(offset);
        }
        haystack = &haystack[1..];
        offset += 1;
    }
    None
}

pub trait EndianRead {
    type Array;
    fn from_le_bytes(bytes: Self::Array) -> Self;
    fn from_be_bytes(bytes: Self::Array) -> Self;
}

#[macro_export]
macro_rules! impl_EndianRead (( $($int:ident),* ) => {
    $(
        impl EndianRead for $int {
            type Array = [u8; std::mem::size_of::<Self>()];
            fn from_le_bytes(bytes: Self::Array) -> Self { Self::from_le_bytes(bytes) }
            fn from_be_bytes(bytes: Self::Array) -> Self { Self::from_be_bytes(bytes) }
        }
    )*
});
