pub fn bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("the operating system could not provide random bytes");
    buf
}

pub fn hex<const N: usize>() -> String {
    bytes::<N>().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_the_right_length_and_not_repeated() {
        let a = hex::<16>();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(a, hex::<16>());
    }

    #[test]
    fn bytes_are_not_all_zero() {
        assert_ne!(bytes::<32>(), [0u8; 32]);
    }
}
