use anyhow::Result;
use encrypted_spaces_sdk::Space;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalendarEvent {
    pub id: Option<i64>,
    /// Unix timestamp (seconds since epoch) for event start
    pub start_time: i64,
    /// Unix timestamp (seconds since epoch) for event end, or 0 if unset
    pub end_time: i64,
    /// Event title
    pub title: String,
    /// Optional description / notes
    pub description: String,
}

pub async fn load_events(space: &Space) -> Result<Vec<CalendarEvent>> {
    let mut events: Vec<CalendarEvent> = space
        .table::<CalendarEvent>("calendar_events")
        .select()
        .all()
        .await?;
    // Sort client-side since columns are encrypted
    events.sort_by_key(|e| e.start_time);
    Ok(events)
}

pub async fn add_event(
    space: &Space,
    start_time: i64,
    end_time: i64,
    title: &str,
    description: &str,
) -> Result<CalendarEvent> {
    let event = CalendarEvent {
        id: None,
        start_time,
        end_time,
        title: title.to_string(),
        description: description.to_string(),
    };
    let id = space
        .table::<CalendarEvent>("calendar_events")
        .insert(&event)
        .execute()
        .await?;
    Ok(CalendarEvent {
        id: Some(id),
        ..event
    })
}

pub async fn update_event(
    space: &Space,
    event_id: i64,
    start_time: i64,
    end_time: i64,
    title: &str,
    description: &str,
) -> Result<bool> {
    let updated = space
        .table::<CalendarEvent>("calendar_events")
        .update()
        .set("start_time", start_time)
        .set("end_time", end_time)
        .set("title", title.to_string())
        .set("description", description.to_string())
        .where_eq("id", event_id)
        .execute()
        .await?;
    Ok(updated > 0)
}

pub async fn delete_event(space: &Space, event_id: i64) -> Result<bool> {
    let deleted = space
        .table::<CalendarEvent>("calendar_events")
        .delete()
        .where_eq("id", event_id)
        .execute()
        .await?;
    Ok(deleted > 0)
}
