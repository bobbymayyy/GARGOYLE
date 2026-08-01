use gargoyle::event::{EventFactory, Severity};
use std::collections::BTreeMap;

#[test]
fn event_serialization_uses_expected_schema_version() {
    let factory = EventFactory::new("test-agent".into(), "test-host".into(), BTreeMap::new());
    let event = factory.event("test", "test.event", Severity::Info, "schema smoke test");
    let value = serde_json::to_value(event).expect("serialize event");
    assert_eq!(value["schema_version"], "gargoyle.event/v2");
    assert_eq!(value["severity"], "info");
}
