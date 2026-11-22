#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let args: Vec<String> = s.split('\0').map(str::to_owned).collect();
    let _ = rs_auth::cli::parse_args(args);
});
