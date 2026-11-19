mod common;

#[tokio::test(flavor = "multi_thread")]
async fn world_starts_with_an_owner() {
    let w = common::world::World::start().await;
    assert_eq!(w.owner.get("/admin").await.status, 200);
}

#[test]
fn helpers_are_pure() {
    assert_eq!(common::world::secret_for("demo"), "secret-demo");
}
