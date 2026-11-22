#![no_main]
use libfuzzer_sys::fuzz_target;
use rs_auth::token::{Hs256Signer, TokenSigner};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let signer = Hs256Signer::new(
        b"fuzz-secret-fuzz-secret-fuzz-secret!!",
        "https://auth.example.com",
    );
    assert!(
        signer.verify(s).is_err(),
        "accepted a token it did not sign: {s:?}"
    );
});
