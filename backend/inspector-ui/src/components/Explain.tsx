// Plain-English overlays for each panel. Toggled by the "Explain" button
// in the toolbar so a non-engineer can read what each panel is for without
// any other guidance. Keep these short — 1–3 sentences max.

interface Props {
  topic:
    | "wire"
    | "operations"
    | "tables"
    | "mmr"
    | "members"
    | "proofs";
}

const TEXT: Record<Props["topic"], { title: string; body: string }> = {
  wire: {
    title: "Every event the server sees",
    body:
      "Each row is one structured event emitted by the backend — requests, " +
      "state changes, proofs, membership ticks. Use this to follow what the " +
      "server actually did, in order. Use the Operations view for a less " +
      "noisy summary.",
  },
  operations: {
    title: "One card per user-facing action",
    body:
      "Raw events are grouped by request: a single 'Alice posted a message' " +
      "shows as one card. Expand a card to see the underlying state mutation, " +
      "changelog append, and any proof.",
  },
  tables: {
    title: "What the server stores",
    body:
      "Green columns are plaintext — indexable, queryable, visible to the " +
      "server. Locked columns are ciphertext: only members with the current " +
      "key epoch can decrypt them. The server holds opaque bytes.",
  },
  mmr: {
    title: "Append-only history",
    body:
      "Each changelog entry becomes a new leaf. Equal-height subtrees merge " +
      "into peaks — the 'mountain range' shape. Old entries are never " +
      "rewritten, and any past entry can be proven with a small inclusion " +
      "proof.",
  },
  members: {
    title: "Who can decrypt",
    body:
      "Only listed members hold the current group key. Each add or remove " +
      "ratchets the key epoch so removed members can't read future traffic " +
      "and new joiners can't read past traffic.",
  },
  proofs: {
    title: "Succinct verification",
    body:
      "Instead of trusting the server, clients verify each response against " +
      "the current root. Fast-forward proofs let a joining client skip " +
      "replaying every entry — one short proof replaces megabytes of history.",
  },
};

export function ExplainBanner({ topic }: Props) {
  const t = TEXT[topic];
  return (
    <div className="explain-banner">
      <div className="explain-title">{t.title}</div>
      <div className="explain-body">{t.body}</div>
    </div>
  );
}
