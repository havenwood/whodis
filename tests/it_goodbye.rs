mod common;

use tokio_stream::StreamExt;
use whodis::browse::{Browser, Event};

use common::{send_fake_appletv_announcement, send_fake_appletv_goodbye, settle, test_mode};

#[tokio::test(flavor = "multi_thread")]
async fn goodbye_emits_event() {
    tracing_subscriber::fmt::try_init().ok();

    let browser = Browser::new(test_mode()).expect("browser");
    let cancel_browser = browser.cancel_token();
    let stream = browser.run();
    tokio::pin!(stream);

    // Give the browser time to bind and join the multicast group.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Announce the instance so the browser caches it.
    send_fake_appletv_announcement();

    // Wait for InstanceFound before sending goodbye.
    let deadline = tokio::time::Instant::now() + settle();
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if matches!(
            tokio::time::timeout(remaining, stream.next()).await,
            Ok(Some(Event::InstanceFound { .. }))
        ) {
            break;
        }
    }

    // Send a TTL=0 goodbye packet.
    send_fake_appletv_goodbye();

    let mut saw_goodbye = false;
    let deadline = tokio::time::Instant::now() + settle();
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, stream.next()).await {
            Ok(Some(Event::InstanceGoodbye { .. })) => {
                saw_goodbye = true;
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }

    cancel_browser.cancel();
    assert!(saw_goodbye, "expected goodbye event");
}
