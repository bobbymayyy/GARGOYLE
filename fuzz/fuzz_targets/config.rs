#![no_main]

use gargoyle::config::Config;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(config) = toml::from_str::<Config>(text) {
        let _ = config.validate();
        let _ = config.to_pretty_toml();
    }
});
