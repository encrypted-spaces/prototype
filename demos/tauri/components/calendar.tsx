"use client";

import { useState, useEffect, useCallback } from "react";
import { useSpace, useSpaceDispatch } from "@/lib/store";
import * as api from "@/lib/api";
import type { CalendarItem } from "@/lib/types";

/** Get year/month grid info */
function getMonthData(year: number, month: number) {
  const firstDay = new Date(year, month, 1).getDay(); // 0=Sun
  const daysInMonth = new Date(year, month + 1, 0).getDate();
  return { firstDay, daysInMonth };
}

function formatDate(year: number, month: number, day: number): string {
  const m = String(month + 1).padStart(2, "0");
  const d = String(day).padStart(2, "0");
  return `${year}-${m}-${d}`;
}

/** Extract local date string "YYYY-MM-DD" from unix timestamp */
function tsToDateStr(ts: number): string {
  const d = new Date(ts * 1000);
  return formatDate(d.getFullYear(), d.getMonth(), d.getDate());
}

/** Extract local time string "HH:MM" from unix timestamp, or "" if midnight */
function tsToTimeStr(ts: number): string {
  const d = new Date(ts * 1000);
  const h = d.getHours();
  const m = d.getMinutes();
  if (h === 0 && m === 0) return "";
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
}

/** Combine a "YYYY-MM-DD" date and optional "HH:MM" time into a unix timestamp */
function dateTimeToTs(dateStr: string, timeStr: string): number {
  const [y, mo, da] = dateStr.split("-").map(Number);
  if (timeStr) {
    const [h, mi] = timeStr.split(":").map(Number);
    return Math.floor(new Date(y, mo - 1, da, h, mi).getTime() / 1000);
  }
  return Math.floor(new Date(y, mo - 1, da).getTime() / 1000);
}

/** Format a timestamp for display: "14:30" or "14:30–15:30" */
function formatTimeRange(startTs: number, endTs: number): string {
  const startT = tsToTimeStr(startTs);
  const endT = endTs ? tsToTimeStr(endTs) : "";
  if (!startT && !endT) return "";
  if (!startT) return "";
  if (!endT) return startT;
  return `${startT}–${endT}`;
}

const MONTH_NAMES = [
  "January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December",
];

const DAY_HEADERS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

export default function Calendar() {
  const { calendarEvents } = useSpace();
  const dispatch = useSpaceDispatch();

  const today = new Date();
  const [viewYear, setViewYear] = useState(today.getFullYear());
  const [viewMonth, setViewMonth] = useState(today.getMonth());
  const [selectedDate, setSelectedDate] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [editingEvent, setEditingEvent] = useState<CalendarItem | null>(null);
  const [expandedEventId, setExpandedEventId] = useState<number | null>(null);

  // Form fields
  const [formTitle, setFormTitle] = useState("");
  const [formDesc, setFormDesc] = useState("");
  const [formTime, setFormTime] = useState("");
  const [formEndTime, setFormEndTime] = useState("");
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Load events on mount
  useEffect(() => {
    api.getCalendarEvents().then((events) => {
      dispatch({ type: "setCalendarEvents", events });
    }).catch(() => {});
  }, [dispatch]);

  const { firstDay, daysInMonth } = getMonthData(viewYear, viewMonth);

  // Group events by local date
  const eventsByDate: Record<string, CalendarItem[]> = {};
  for (const ev of calendarEvents) {
    const dateKey = tsToDateStr(ev.start_time);
    if (!eventsByDate[dateKey]) eventsByDate[dateKey] = [];
    eventsByDate[dateKey].push(ev);
  }

  const prevMonth = useCallback(() => {
    if (viewMonth === 0) {
      setViewYear(viewYear - 1);
      setViewMonth(11);
    } else {
      setViewMonth(viewMonth - 1);
    }
  }, [viewYear, viewMonth]);

  const nextMonth = useCallback(() => {
    if (viewMonth === 11) {
      setViewYear(viewYear + 1);
      setViewMonth(0);
    } else {
      setViewMonth(viewMonth + 1);
    }
  }, [viewYear, viewMonth]);

  const goToday = useCallback(() => {
    const now = new Date();
    setViewYear(now.getFullYear());
    setViewMonth(now.getMonth());
  }, []);

  const openAddForm = (date: string) => {
    setSelectedDate(date);
    setEditingEvent(null);
    setFormTitle("");
    setFormDesc("");
    // Default to next half-hour, end 1h later
    const now = new Date();
    const mins = now.getMinutes();
    const roundedMins = mins < 30 ? 30 : 0;
    const startH = mins < 30 ? now.getHours() : (now.getHours() + 1) % 24;
    const startStr = `${String(startH).padStart(2, "0")}:${String(roundedMins).padStart(2, "0")}`;
    const endH = (startH + 1) % 24;
    const endStr = `${String(endH).padStart(2, "0")}:${String(roundedMins).padStart(2, "0")}`;
    setFormTime(startStr);
    setFormEndTime(endStr);
    setFormError(null);
    setShowForm(true);
  };

  const openEditForm = (ev: CalendarItem) => {
    setSelectedDate(tsToDateStr(ev.start_time));
    setEditingEvent(ev);
    setFormTitle(ev.title);
    setFormDesc(ev.description);
    setFormTime(tsToTimeStr(ev.start_time));
    setFormEndTime(ev.end_time ? tsToTimeStr(ev.end_time) : "");
    setShowForm(true);
  };

  const closeForm = () => {
    setShowForm(false);
    setEditingEvent(null);
    setFormTitle("");
    setFormDesc("");
    setFormTime("");
    setFormEndTime("");
    setFormError(null);
    setSaving(false);
  };

  const handleSave = async () => {
    if (saving || !formTitle.trim() || !selectedDate) return;
    setSaving(true);
    setFormError(null);
    try {
      const startTs = dateTimeToTs(selectedDate, formTime);
      const endTs = formEndTime ? dateTimeToTs(selectedDate, formEndTime) : 0;
      if (editingEvent && editingEvent.id !== null) {
        await api.updateCalendarEvent(editingEvent.id, startTs, endTs, formTitle.trim(), formDesc.trim());
      } else {
        await api.addCalendarEvent(startTs, endTs, formTitle.trim(), formDesc.trim());
      }
      const events = await api.getCalendarEvents();
      dispatch({ type: "setCalendarEvents", events });
      closeForm();
    } catch (err: any) {
      console.error("Calendar save failed:", err);
      setFormError(String(err?.message || err));
      setSaving(false);
    }
  };

  const handleDelete = async (eventId: number) => {
    try {
      await api.deleteCalendarEvent(eventId);
      const events = await api.getCalendarEvents();
      dispatch({ type: "setCalendarEvents", events });
    } catch (err) {
      console.error("Calendar delete failed:", err);
    }
  };

  // Build calendar grid cells
  const todayStr = formatDate(today.getFullYear(), today.getMonth(), today.getDate());
  const cells: React.ReactNode[] = [];

  // Empty cells before first day
  for (let i = 0; i < firstDay; i++) {
    cells.push(<div key={`empty-${i}`} className="cal-cell cal-cell-empty" />);
  }

  for (let day = 1; day <= daysInMonth; day++) {
    const dateStr = formatDate(viewYear, viewMonth, day);
    const dayEvents = eventsByDate[dateStr] || [];
    const isToday = dateStr === todayStr;
    const isSelected = dateStr === selectedDate && !showForm;

    cells.push(
      <div
        key={dateStr}
        className={`cal-cell ${isToday ? "cal-today" : ""} ${isSelected ? "cal-selected" : ""}`}
        onClick={() => setSelectedDate(dateStr)}
        onDoubleClick={() => openAddForm(dateStr)}
      >
        <span className={`cal-day-num ${isToday ? "cal-day-today" : ""}`}>{day}</span>
        {dayEvents.length > 0 && (
          <div className="cal-cell-events">
            {dayEvents.slice(0, 3).map((ev) => (
              <div key={ev.id} className="cal-event-dot" title={ev.title}>
                {ev.title}
              </div>
            ))}
            {dayEvents.length > 3 && (
              <span className="cal-more">+{dayEvents.length - 3} more</span>
            )}
          </div>
        )}
      </div>
    );
  }

  // Events for selected date
  const selectedEvents = selectedDate ? (eventsByDate[selectedDate] || []) : [];

  return (
    <div className="cal-container">
      {/* Header */}
      <div className="cal-header">
        <div className="cal-nav">
          <button className="cal-nav-btn" onClick={prevMonth}>&larr;</button>
          <span className="cal-title">
            {MONTH_NAMES[viewMonth]} {viewYear}
          </span>
          <button className="cal-nav-btn" onClick={nextMonth}>&rarr;</button>
          <button className="cal-today-btn" onClick={goToday}>Today</button>
        </div>
      </div>

      {/* Grid */}
      <div className="cal-grid-wrapper">
        <div className="cal-grid">
          {DAY_HEADERS.map((d) => (
            <div key={d} className="cal-day-header">{d}</div>
          ))}
          {cells}
        </div>
      </div>

      {/* Selected date detail panel */}
      {selectedDate && !showForm && (
        <div className="cal-detail">
          <div className="cal-detail-header">
            <span className="cal-detail-date">{selectedDate}</span>
            <button className="cal-add-btn" onClick={() => openAddForm(selectedDate)}>
              + Add Event
            </button>
          </div>
          {selectedEvents.length === 0 ? (
            <p className="cal-no-events">No events. Double-click a day or click &quot;+ Add Event&quot; to create one.</p>
          ) : (
            <div className="cal-event-list">
              {selectedEvents.map((ev) => {
                const isExpanded = expandedEventId === ev.id;
                return (
                  <div
                    key={ev.id}
                    className={`cal-event-item ${isExpanded ? "cal-event-expanded" : ""}`}
                    onClick={() => setExpandedEventId(isExpanded ? null : ev.id)}
                  >
                    <div className="cal-event-info">
                      <span className="cal-event-title">{(() => { const tr = formatTimeRange(ev.start_time, ev.end_time); return tr ? `${tr} — ${ev.title}` : ev.title; })()}</span>
                      {ev.description && (
                        <span className={isExpanded ? "cal-event-desc-full" : "cal-event-desc"}>
                          {ev.description}
                        </span>
                      )}
                    </div>
                    <div className="cal-event-actions">
                      <button className="cal-action-btn" onClick={(e) => { e.stopPropagation(); openEditForm(ev); }} title="Edit">✎</button>
                      <button className="cal-action-btn cal-delete-btn" onClick={(e) => { e.stopPropagation(); handleDelete(ev.id!); }} title="Delete">✕</button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Add/Edit form overlay */}
      {showForm && (
        <div className="cal-form">
          <div className="cal-form-header">
            <span>{editingEvent ? "Edit Event" : "New Event"}</span>
            <span className="cal-form-date">{selectedDate}</span>
          </div>
          <input
            className="cal-form-input"
            placeholder="Event title"
            value={formTitle}
            onChange={(e) => setFormTitle(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") handleSave(); }}
            autoFocus
          />
          <div className="cal-form-time-row">
            <label className="cal-form-time-label">
              <span>Start</span>
              <input
                className="cal-form-input cal-form-time"
                type="time"
                value={formTime}
                onChange={(e) => {
                  const v = e.target.value;
                  setFormTime(v);
                  if (v) {
                    const [h, m] = v.split(":").map(Number);
                    const endH = (h + 1) % 24;
                    setFormEndTime(`${String(endH).padStart(2, "0")}:${String(m).padStart(2, "0")}`);
                  }
                }}
              />
            </label>
            <label className="cal-form-time-label">
              <span>End</span>
              <input
                className="cal-form-input cal-form-time"
                type="time"
                value={formEndTime}
                onChange={(e) => setFormEndTime(e.target.value)}
              />
            </label>
          </div>
          <textarea
            className="cal-form-textarea"
            placeholder="Description (optional)"
            value={formDesc}
            onChange={(e) => setFormDesc(e.target.value)}
            rows={3}
          />
          {formError && <p className="cal-form-error">{formError}</p>}
          <div className="cal-form-actions">
            <button className="cal-form-cancel" onClick={closeForm} disabled={saving}>Cancel</button>
            <button className="cal-form-save" onClick={handleSave} disabled={saving || !formTitle.trim()}>
              {saving ? "Saving…" : editingEvent ? "Update" : "Add"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
