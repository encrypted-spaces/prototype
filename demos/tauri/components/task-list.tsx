"use client";

import { useState, useRef } from "react";
import { useSpace, useSpaceDispatch } from "@/lib/store";
import * as api from "@/lib/api";

export default function TaskList() {
  const { tasks } = useSpace();
  const dispatch = useSpaceDispatch();
  const inputRef = useRef<HTMLInputElement>(null);
  const [editingKey, setEditingKey] = useState<string | null>(null);
  const [editTitle, setEditTitle] = useState("");

  async function handleAdd() {
    const input = inputRef.current;
    if (!input) return;
    const title = input.value.trim();
    if (!title) return;
    input.value = "";
    try {
      await api.addTask(title);
      const tasks = await api.getTasks();
      dispatch({ type: "setTasks", tasks });
    } catch (err) {
      console.error("Failed to add task:", err);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter") {
      e.preventDefault();
      handleAdd();
    }
  }

  async function handleToggle(key: string) {
    try {
      await api.toggleTask(key);
      const tasks = await api.getTasks();
      dispatch({ type: "setTasks", tasks });
    } catch (err) {
      console.error("Failed to toggle task:", err);
    }
  }

  async function handleDelete(key: string) {
    try {
      await api.deleteTask(key);
      const tasks = await api.getTasks();
      dispatch({ type: "setTasks", tasks });
    } catch (err) {
      console.error("Failed to delete task:", err);
    }
  }

  function startEditing(key: string, title: string) {
    setEditingKey(key);
    setEditTitle(title);
  }

  async function handleEditSubmit(key: string) {
    const title = editTitle.trim();
    if (!title) {
      setEditingKey(null);
      return;
    }
    try {
      await api.updateTaskTitle(key, title);
      setEditingKey(null);
      const tasks = await api.getTasks();
      dispatch({ type: "setTasks", tasks });
    } catch (err) {
      console.error("Failed to update task:", err);
    }
  }

  const doneCount = tasks.filter((t) => t.done).length;

  return (
    <div className="task-section">
      <div className="task-header">
        <span className="task-header-label">Tasks</span>
        {tasks.length > 0 && (
          <span className="task-count">
            {doneCount}/{tasks.length}
          </span>
        )}
      </div>

      <div className="task-list">
        {tasks.map((task) => (
          <div key={task.key} className={`task-item ${task.done ? "done" : ""}`}>
            <button
              className="task-checkbox"
              onClick={() => handleToggle(task.key)}
              title={task.done ? "Mark incomplete" : "Mark complete"}
            >
              {task.done ? "✓" : ""}
            </button>

            {editingKey === task.key ? (
              <input
                className="task-edit-input"
                value={editTitle}
                onChange={(e) => setEditTitle(e.target.value)}
                onBlur={() => handleEditSubmit(task.key)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleEditSubmit(task.key);
                  if (e.key === "Escape") setEditingKey(null);
                }}
                autoFocus
              />
            ) : (
              <span
                className="task-title"
                onDoubleClick={() => startEditing(task.key, task.title)}
              >
                {task.title}
              </span>
            )}

            <button
              className="task-delete"
              onClick={() => handleDelete(task.key)}
              title="Delete task"
            >
              ×
            </button>
          </div>
        ))}
      </div>

      <div className="task-add-form">
        <input
          ref={inputRef}
          className="task-add-input"
          type="text"
          onKeyDown={handleKeyDown}
          placeholder="Add a task…"
        />
      </div>
    </div>
  );
}
