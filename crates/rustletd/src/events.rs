//! The event bus behind `GET /v1/events`: a broadcast channel for the live
//! events and a ring of the recent ones, for `since`.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use rustlet_spec::event::{Event, EventKind};
use tokio::sync::broadcast;

/// Events kept for `since`.
const RECENT: usize = 1024;

pub struct EventBus {
    tx: broadcast::Sender<Event>,
    recent: Mutex<VecDeque<Event>>,
}

impl Default for EventBus {
    fn default() -> EventBus {
        EventBus { tx: broadcast::channel(1024).0, recent: Mutex::new(VecDeque::with_capacity(RECENT)) }
    }
}

impl EventBus {
    pub fn emit(&self, kind: EventKind, action: &str, id: &str, attributes: BTreeMap<String, String>) {
        let event = Event {
            time: rustlet_shim::logfile::now(),
            kind,
            action: action.to_owned(),
            id: id.to_owned(),
            attributes,
        };
        tracing::debug!(?event, "event");
        let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        if recent.len() == RECENT {
            recent.pop_front();
        }
        recent.push_back(event.clone());
        // Under the same lock as `recent`: a subscriber sees each event once,
        // either replayed or live.
        let _ = self.tx.send(event);
    }

    /// The recent events (oldest first) and the live ones after them.
    pub fn subscribe(&self) -> (Vec<Event>, broadcast::Receiver<Event>) {
        let recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        (recent.iter().cloned().collect(), self.tx.subscribe())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replay_then_live_without_gaps_or_repeats() {
        let bus = EventBus::default();
        bus.emit(EventKind::Container, "create", "a", BTreeMap::new());
        let (recent, mut live) = bus.subscribe();
        bus.emit(EventKind::Container, "start", "a", BTreeMap::new());
        assert_eq!(recent.iter().map(|e| e.action.as_str()).collect::<Vec<_>>(), ["create"]);
        assert_eq!(live.recv().await.unwrap().action, "start");
        for i in 0..RECENT + 5 {
            bus.emit(EventKind::Image, "pull", &i.to_string(), BTreeMap::new());
        }
        assert_eq!(bus.subscribe().0.len(), RECENT);
    }
}
