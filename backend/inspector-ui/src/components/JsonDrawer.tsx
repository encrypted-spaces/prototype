import type { InspectorEvent } from "../types/events";

interface Props {
  event: InspectorEvent | null;
  onClose: () => void;
}

export function JsonDrawer({ event, onClose }: Props) {
  if (!event) return null;
  const pretty = JSON.stringify(event, null, 2);
  return (
    <aside className="json-drawer">
      <div className="json-drawer-header">
        <span className={`kind-tag tag-${event.kind}`}>{event.kind}</span>
        <button className="close" onClick={onClose} title="Close drawer">×</button>
      </div>
      <pre className="json-body">{pretty}</pre>
    </aside>
  );
}
