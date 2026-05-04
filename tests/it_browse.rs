mod common;

use std::time::Duration;

use tokio_stream::StreamExt;
use whodis::browse::{Browser, Event};

use common::{send_fake_appletv_announcement, settle, test_mode};

#[tokio::test(flavor = "multi_thread")]
async fn browse_finds_responder() {
    tracing_subscriber::fmt::try_init().ok();

    let browser = Browser::new(test_mode()).expect("browser");
    let cancel_browser = browser.cancel_token();
    let stream = browser.run();
    tokio::pin!(stream);

    // Give the browser time to bind and join the multicast group.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send a fully-formed mDNS response (PTR + SRV + TXT) directly to the group.
    send_fake_appletv_announcement();

    let deadline = tokio::time::Instant::now() + settle();
    let mut found = false;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, stream.next()).await {
            Ok(Some(Event::InstanceFound { instance })) => {
                if instance.txt.contains_key("model") {
                    found = true;
                    break;
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }

    cancel_browser.cancel();
    assert!(found, "expected to find FakeATV via browse");
}
