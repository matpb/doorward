mod common;

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "World: the gateway printed no setup code")]
async fn world_needs_the_setup_code() {
    common::world::World::start().await;
}

#[test]
fn helpers_are_pure() {
    assert_eq!(common::world::secret_for("demo"), "secret-demo");
}
