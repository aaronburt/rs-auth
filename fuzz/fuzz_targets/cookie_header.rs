#![no_main]
use libfuzzer_sys::fuzz_target;
use rs_auth::cookie::CookieJar;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let headers: Vec<&str> = s.split('\n').collect();
    let jar = CookieJar::parse(headers.iter().copied());
    for name in ["rs_auth_session", "__Host-rs_auth_csrf", "rs_auth_csrf", ""] {
        if let Some(v) = jar.get(name) {
            assert!(!name.is_empty());
            assert!(!v.contains(';'));
            assert!(!v.contains('\n'));
            assert_eq!(v, v.trim());
        }
    }
});
