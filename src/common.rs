/// Checks if a stack is sub of another and returns the first appearance
pub fn is_sub<T: PartialEq>(mut haystack: &[T], needle: &[T]) -> Option<usize> {
    if needle.len() == 0 {
        return Some(0);
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_is_sub() {
        assert_eq!(is_sub(&mut vec![3, 4, 5, 2, 8, 2], &vec![5, 2, 8]), Some(2));
        assert_eq!(is_sub(&mut vec![3, 7, 23, 7, 4, 3], &vec![3, 8]), None);
        assert_eq!(is_sub(&mut vec![], &vec![3, 2, 6]), None);
        assert_eq!(is_sub(&mut vec![2, 51, 3, 43, 7, 13, 4], &vec![]), Some(0));
    }
}
