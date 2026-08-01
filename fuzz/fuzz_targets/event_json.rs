#![no_main]

use gargoyle::event::Event;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(event) = serde_json::from_slice::<Event>(data) {
        let _ = serde_json::to_vec(&event);
    }
});
