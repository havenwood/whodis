use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use tracing::Subscriber;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use whodis::Authorization;

#[derive(Default, Clone)]
struct Capture {
    lines: Arc<Mutex<Vec<String>>>,
}

impl<S> tracing_subscriber::Layer<S> for Capture
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = StringVisitor::default();
        event.record(&mut visitor);
        if event.metadata().level() == &tracing::Level::WARN {
            self.lines.lock().expect("lock").push(visitor.0);
        }
    }
}

#[derive(Default)]
struct StringVisitor(String);
impl tracing::field::Visit for StringVisitor {
    fn record_debug(&mut self, _f: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        write!(self.0, "{value:?} ").ok();
    }
    fn record_str(&mut self, _f: &tracing::field::Field, value: &str) {
        self.0.push_str(value);
        self.0.push(' ');
    }
}

#[test]
fn empty_authorization_warns_once_for_aggressive_op() {
    let cap = Capture::default();
    let lines = cap.lines.clone();
    let subscriber = tracing_subscriber::registry().with(cap);
    tracing::subscriber::with_default(subscriber, || {
        let auth = Authorization::new();
        auth.warn_once_if_permissive("spoof");
        auth.warn_once_if_permissive("spoof");
    });
    let count = lines.lock().expect("lock").len();
    assert_eq!(count, 1, "expected exactly one warn");
}
