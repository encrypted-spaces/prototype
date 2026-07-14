import { useRef } from "react";
import { parseNdjson, type InspectorEvent } from "../types/events";

interface Props {
  onLoad: (events: InspectorEvent[], filename: string) => void;
}

export function FilePicker({ onLoad }: Props) {
  const inputRef = useRef<HTMLInputElement>(null);

  const handle = async (file: File) => {
    const text = await file.text();
    const events = parseNdjson(text);
    onLoad(events, file.name);
  };

  return (
    <div className="file-picker">
      <input
        ref={inputRef}
        type="file"
        accept=".ndjson,.jsonl,application/x-ndjson"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) handle(f);
        }}
      />
      <button onClick={() => inputRef.current?.click()}>Load NDJSON…</button>
    </div>
  );
}
