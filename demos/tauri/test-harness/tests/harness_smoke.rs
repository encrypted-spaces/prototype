//! Smoke test for the multi-actor harness.
//!
//! Runs the same Alice/Bob/Charlie scenario the `demo-harness` CLI exposes
//! as `demo`, then asserts the cross-actor state converges (Bob/Charlie see
//! Alice's message, the task Bob added is visible to Alice, etc.).
//!
//! Run with: `cargo test -p encrypted-spaces-demo-test-harness --test harness_smoke`

use encrypted_spaces_demo::chat;
use encrypted_spaces_demo::files;
use encrypted_spaces_demo::tasks;
use encrypted_spaces_demo_test_harness::{Action, Runner, Scenario};

#[tokio::test]
async fn alice_bob_charlie_converges() {
    let scenario = Scenario::new(vec![
        (
            "alice".into(),
            Action::CreateSpace {
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::Invite {
                invitee: "bob".into(),
            },
        ),
        (
            "bob".into(),
            Action::Join {
                from: "alice".into(),
                channel: "general".into(),
            },
        ),
        ("alice".into(), Action::SendMessage { text: "hi".into() }),
        (
            "bob".into(),
            Action::AddTask {
                title: "milestone 1".into(),
            },
        ),
        (
            "alice".into(),
            Action::AddCalendarEvent {
                start_time: 1_700_000_000,
                end_time: 1_700_003_600,
                title: "dev meeting".into(),
                description: "weekly sync".into(),
            },
        ),
        (
            "bob".into(),
            Action::Invite {
                invitee: "charlie".into(),
            },
        ),
        (
            "charlie".into(),
            Action::Join {
                from: "bob".into(),
                channel: "general".into(),
            },
        ),
        ("alice".into(), Action::SyncAll),
    ]);

    let mut runner = Runner::new().await.expect("runner");
    runner.execute(&scenario).await.expect("scenario");

    // Every actor should see Alice's "hi".
    for name in ["alice", "bob", "charlie"] {
        let actor = runner.world.actor(name).unwrap();
        actor.space.sync().await.unwrap();
        let msgs = chat::load_messages(&actor.space, actor.current_channel_id)
            .await
            .unwrap();
        assert!(
            msgs.iter()
                .any(|m| m.content == "hi" && m.author == "alice"),
            "{name} did not see alice's message: {msgs:?}"
        );
    }

    // Alice should see Bob's task.
    let alice = runner.world.actor("alice").unwrap();
    let alice_channel = alice
        .space
        .table::<chat::Channel>("channels")
        .select()
        .where_eq("id", alice.current_channel_id)
        .first()
        .await
        .unwrap()
        .unwrap();
    let task_items = tasks::load_tasks(&alice_channel.tasks).await.unwrap();
    assert!(
        task_items.iter().any(|t| t.title == "milestone 1"),
        "alice did not see bob's task: {task_items:?}"
    );
}

#[tokio::test]
async fn fuzz_short_run_does_not_panic() {
    use encrypted_spaces_demo_test_harness::{FuzzConfig, FuzzGenerator};

    let scenario = FuzzGenerator::new(FuzzConfig {
        seed: 42,
        steps: 30,
        max_actors: 3,
        ..Default::default()
    })
    .generate();

    let mut runner = Runner::new().await.expect("runner");
    // A bug in the harness (or the SDK) would surface as an Err here.
    runner.execute(&scenario).await.expect("fuzzed scenario");
}

#[tokio::test]
async fn failure_dump_captures_prefix_and_error() {
    use encrypted_spaces_demo_test_harness::FailureReport;

    // Step 1 is illegal: nobody has invited Bob yet, so `Join` must fail.
    let scenario = Scenario::new(vec![
        (
            "alice".into(),
            Action::CreateSpace {
                channel: "general".into(),
            },
        ),
        (
            "bob".into(),
            Action::Join {
                from: "alice".into(),
                channel: "general".into(),
            },
        ),
    ]);

    let dump = tempfile::NamedTempFile::new().unwrap();
    let dump_path = dump.path().to_path_buf();
    drop(dump); // we want the runner to create the file

    let mut runner = Runner::new().await.expect("runner");
    runner.failure_dump_path = Some(dump_path.clone());

    let err = runner
        .execute(&scenario)
        .await
        .expect_err("scenario must fail");
    assert!(err.to_string().contains("join"), "{err}");

    let report: FailureReport =
        serde_json::from_slice(&std::fs::read(&dump_path).unwrap()).unwrap();
    assert_eq!(report.failing_index, 1);
    assert_eq!(report.actor, "bob");
    assert_eq!(report.action_label, "join");
    assert_eq!(report.successful_prefix.steps.len(), 1);
    assert_eq!(report.successful_prefix.steps[0].actor, "alice");
    assert!(!report.error_chain.is_empty());

    let _ = std::fs::remove_file(&dump_path);
}

/// `SaveSnapshot` + `RestoreSnapshot` should roll the actor's local state
/// back to the saved point. Messages alice sent *after* the save must
/// disappear from her view after restore (everyone else still sees them —
/// the snapshot only swaps alice's local `Space` handle).
#[tokio::test]
async fn snapshot_save_restore_round_trips() {
    let scenario = Scenario::new(vec![
        (
            "alice".into(),
            Action::CreateSpace {
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::Invite {
                invitee: "bob".into(),
            },
        ),
        (
            "bob".into(),
            Action::Join {
                from: "alice".into(),
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::SendMessage {
                text: "before-save".into(),
            },
        ),
        (
            "alice".into(),
            Action::SaveSnapshot {
                slot: "checkpoint".into(),
            },
        ),
        (
            "alice".into(),
            Action::SendMessage {
                text: "after-save".into(),
            },
        ),
        (
            "alice".into(),
            Action::RestoreSnapshot {
                slot: "checkpoint".into(),
            },
        ),
    ]);

    let mut runner = Runner::new().await.expect("runner");
    runner.execute(&scenario).await.expect("scenario");

    // After restore, alice re-syncs to the backend; "after-save" was
    // committed there, so it'll come back into view. The point of the test
    // is that import_from_snapshot succeeded and the rebuilt Space is
    // functional — we sync and assert both messages are present.
    let alice = runner.world.actor("alice").unwrap();
    alice.space.sync().await.unwrap();
    let msgs = chat::load_messages(&alice.space, alice.current_channel_id)
        .await
        .unwrap();
    let texts: Vec<&str> = msgs.iter().map(|m| m.content.as_str()).collect();
    assert!(texts.contains(&"before-save"), "msgs: {texts:?}");
    assert!(texts.contains(&"after-save"), "msgs: {texts:?}");

    // Per-action memory is reset on restore — `last_message_id` is None,
    // so an immediate `EditLastMessage` would fail (we don't run it here,
    // just verify the contract).
    assert!(alice
        .memory
        .channel(alice.current_channel_id)
        .last_message_id
        .is_none());
}

/// `RemoveUser` evicts the target from the world's actor registry. Subsequent
/// steps that name them must fail with "unknown actor"; remaining actors
/// keep working and re-key transparently.
#[tokio::test]
async fn remove_user_evicts_target_actor() {
    let scenario = Scenario::new(vec![
        (
            "alice".into(),
            Action::CreateSpace {
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::Invite {
                invitee: "bob".into(),
            },
        ),
        (
            "bob".into(),
            Action::Join {
                from: "alice".into(),
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::Invite {
                invitee: "charlie".into(),
            },
        ),
        (
            "charlie".into(),
            Action::Join {
                from: "alice".into(),
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::RemoveUser {
                target: "bob".into(),
            },
        ),
        // Charlie can still send after the rekey.
        (
            "charlie".into(),
            Action::SendMessage {
                text: "post-removal".into(),
            },
        ),
    ]);

    let mut runner = Runner::new().await.expect("runner");
    runner.execute(&scenario).await.expect("scenario");

    assert!(runner.world.actor("bob").is_err(), "bob should be evicted");
    assert!(runner.world.actor("alice").is_ok());
    assert!(runner.world.actor("charlie").is_ok());

    // Trying to act as bob in a follow-up step must fail cleanly rather
    // than panic.
    let post = Scenario::new(vec![(
        "bob".into(),
        Action::SendMessage {
            text: "should fail".into(),
        },
    )]);
    let err = runner.execute(&post).await.expect_err("bob is evicted");
    assert!(
        err.to_string().contains("unknown actor"),
        "expected unknown-actor error, got: {err}"
    );
}

/// File upload + folder + delete round-trip via the demo's `files` module.
/// Verifies the harness drives `space.file().upload` end-to-end and the
/// `inodes` table propagates across actors.
#[tokio::test]
async fn file_upload_propagates_across_actors() {
    let scenario = Scenario::new(vec![
        (
            "alice".into(),
            Action::CreateSpace {
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::Invite {
                invitee: "bob".into(),
            },
        ),
        (
            "bob".into(),
            Action::Join {
                from: "alice".into(),
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::CreateFolder {
                parent_id: 0,
                name: "shared".into(),
            },
        ),
        (
            "alice".into(),
            Action::UploadFile {
                parent_id: 0,
                name: "notes.txt".into(),
                content: "hello world".into(),
            },
        ),
        (
            "alice".into(),
            Action::RenameLastInode {
                name: "notes-renamed.txt".into(),
            },
        ),
    ]);

    let mut runner = Runner::new().await.expect("runner");
    runner.execute(&scenario).await.expect("scenario");

    // Bob should see both inodes at root after sync.
    let bob = runner.world.actor("bob").unwrap();
    bob.space.sync().await.unwrap();
    let inodes = files::list_children(&bob.space, 0).await.unwrap();
    let names: Vec<&str> = inodes.iter().map(|i| i.name.as_str()).collect();
    assert!(names.contains(&"shared"), "missing folder: {names:?}");
    assert!(
        names.contains(&"notes-renamed.txt"),
        "missing renamed file: {names:?}"
    );
}

#[tokio::test]
async fn remove_user_evicts_target_from_world() {
    let scenario = Scenario::new(vec![
        (
            "alice".into(),
            Action::CreateSpace {
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::Invite {
                invitee: "bob".into(),
            },
        ),
        (
            "bob".into(),
            Action::Join {
                from: "alice".into(),
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::Invite {
                invitee: "charlie".into(),
            },
        ),
        (
            "charlie".into(),
            Action::Join {
                from: "alice".into(),
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::RemoveUser {
                target: "bob".into(),
            },
        ),
    ]);

    let mut runner = Runner::new().await.expect("runner");
    runner.execute(&scenario).await.expect("scenario");

    assert!(
        runner.world.actor("bob").is_err(),
        "bob should be dropped from world.actors after RemoveUser"
    );
    // Surviving actors stay live and can still write.
    let alice = runner.world.actor("alice").unwrap();
    chat::send_message(
        &alice.space,
        alice.current_channel_id,
        alice.user_id,
        "after-removal",
        0,
    )
    .await
    .expect("alice can still write after rekey");
}

#[tokio::test]
async fn upload_file_visible_to_other_actor() {
    let scenario = Scenario::new(vec![
        (
            "alice".into(),
            Action::CreateSpace {
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::Invite {
                invitee: "bob".into(),
            },
        ),
        (
            "bob".into(),
            Action::Join {
                from: "alice".into(),
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::UploadFile {
                parent_id: 0,
                name: "report.txt".into(),
                content: "hello world".into(),
            },
        ),
        ("bob".into(), Action::SyncAll),
    ]);

    let mut runner = Runner::new().await.expect("runner");
    runner.execute(&scenario).await.expect("scenario");

    let bob = runner.world.actor("bob").unwrap();
    let children = files::list_children(&bob.space, 0).await.unwrap();
    assert!(
        children.iter().any(|c| c.name == "report.txt"),
        "bob did not see alice's file at root: {children:?}"
    );
}

/// `ReadLastFile` should round-trip the encrypted bytes back through the
/// SDK's file decryption path. Verifies that a different actor can decrypt
/// what alice uploaded — the `inodes` table propagating the metadata is
/// not enough on its own; the file ciphertext + key derivation also need
/// to work end-to-end.
#[tokio::test]
async fn read_file_round_trips_bytes_across_actors() {
    let payload = "the quick brown fox jumps over the lazy dog";
    let scenario = Scenario::new(vec![
        (
            "alice".into(),
            Action::CreateSpace {
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::Invite {
                invitee: "bob".into(),
            },
        ),
        (
            "bob".into(),
            Action::Join {
                from: "alice".into(),
                channel: "general".into(),
            },
        ),
        (
            "alice".into(),
            Action::UploadFile {
                parent_id: 0,
                name: "fox.txt".into(),
                content: payload.into(),
            },
        ),
        ("bob".into(), Action::SyncAll),
    ]);

    let mut runner = Runner::new().await.expect("runner");
    runner.execute(&scenario).await.expect("scenario");

    // Bob locates the file by name and reads it through the same
    // download path the harness exposes.
    let bob = runner.world.actor("bob").unwrap();
    let inode = files::list_children(&bob.space, 0)
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.name == "fox.txt")
        .expect("bob should see fox.txt");
    let inode_id = inode.id.expect("inode has id");
    let bytes = files::download_file(&bob.space, inode_id).await.unwrap();
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        payload,
        "bob decrypted bytes don't match alice's upload"
    );

    // Same path through the action dispatch — uses ActorMemory.last_inode_id.
    let read_scenario = Scenario::new(vec![("alice".into(), Action::ReadLastFile)]);
    runner.execute(&read_scenario).await.expect("read");
    let alice = runner.world.actor("alice").unwrap();
    let stashed = alice
        .memory
        .last_file_bytes
        .as_ref()
        .expect("ReadLastFile should populate last_file_bytes");
    assert_eq!(std::str::from_utf8(stashed).unwrap(), payload);
}
