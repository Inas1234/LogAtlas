use crate::model::{Event, EventId, Severity};

#[derive(Default)]
pub struct EventStore {
    events: Vec<Event>,
    next_id: u64,
}

impl EventStore {
    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Event> {
        self.events.iter()
    }

    pub fn get(&self, id: EventId) -> Option<&Event> {
        self.events.iter().find(|e| e.id == id)
    }

    pub fn first_id(&self) -> Option<EventId> {
        self.events.first().map(|e| e.id)
    }

    pub fn push(&mut self, mut event: Event) -> EventId {
        if event.id.0 == 0 {
            event.id = EventId(self.next_id.max(1));
        }
        self.next_id = self.next_id.max(event.id.0 + 1);
        let id = event.id;
        self.events.push(event);
        id
    }

    pub fn from_events(events: Vec<Event>) -> Self {
        let mut s = Self::default();
        for ev in events {
            s.push(ev);
        }
        s
    }

    pub fn demo() -> Self {
        let mut s = Self::default();

        s.push(Event {
            id: EventId(0),
            t_ms: 0,
            severity: Severity::Info,
            title: "Session start".into(),
            details: "UI scaffold is running. Minidump parsing will plug into this event stream."
                .into(),
            source: "runtime".into(),
        });

        s.push(Event {
            id: EventId(0),
            t_ms: 120,
            severity: Severity::Warning,
            title: "Suspicious module load".into(),
            details: "Placeholder example event. Later: correlate minidump modules, signatures, and known-bad hashes."
                .into(),
            source: "detector::modules".into(),
        });

        s.push(Event {
            id: EventId(0),
            t_ms: 260,
            severity: Severity::High,
            title: "Potential exploit indicator".into(),
            details:
                "Placeholder example event. Later: stack + memory heuristics to flag exploitation patterns."
                    .into(),
            source: "detector::heuristics".into(),
        });

        s
    }
}
