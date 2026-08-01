use gargoyle::config::Config;

#[test]
fn default_configuration_round_trips_through_toml() {
    let original = Config::default();
    let encoded = original.to_pretty_toml().expect("serialize default config");
    let decoded: Config = toml::from_str(&encoded).expect("parse serialized config");
    decoded.validate().expect("round-tripped config is valid");
    assert_eq!(decoded.agent.queue_capacity, original.agent.queue_capacity);
}
