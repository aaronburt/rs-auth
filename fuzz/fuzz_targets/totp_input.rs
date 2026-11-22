#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(secret) = rs_auth::totp::decode_secret(s) {
        let again = rs_auth::totp::encode_secret(&secret);
        assert_eq!(rs_auth::totp::decode_secret(&again).ok(), Some(secret.clone()));
        let replay = rs_auth::totp::Replay::default();
        let _ = replay.accept("user", &secret, s, 1_700_000_000);
    }
    let _ = rs_auth::totp::parse_code(s);
});
