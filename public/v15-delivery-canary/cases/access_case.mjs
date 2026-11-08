// Synthetic local lab. No server, network, credentials, or external package.
const records = new Map([
  [1, { owner: 'alice', note: 'alice-only' }],
  [2, { owner: 'bob', note: 'bob-only' }],
]);

export function getNote(request) {
  if (!request.user) return { status: 401, body: null };
  const record = records.get(request.id);
  if (!record) return { status: 404, body: null };
  return { status: 200, body: record.note };
}

export function getNoteWithOwnerCheck(request) {
  if (!request.user) return { status: 401, body: null };
  const record = records.get(request.id);
  if (!record) return { status: 404, body: null };
  if (record.owner !== request.user) return { status: 403, body: null };
  return { status: 200, body: record.note };
}
