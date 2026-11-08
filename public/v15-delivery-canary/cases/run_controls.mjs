// Deterministic local control runner for the synthetic access case.
import assert from 'node:assert/strict';
import { getNote, getNoteWithOwnerCheck } from './access_case.mjs';

const own = getNote({ user: 'alice', id: 1 });
assert.deepEqual(own, { status: 200, body: 'alice-only' });
console.log('PASS own-record baseline: alice receives alice note');

const crossUser = getNote({ user: 'alice', id: 2 });
assert.deepEqual(crossUser, { status: 200, body: 'bob-only' });
console.log('PASS positive: alice receives bob note through missing owner check');

const blocked = getNoteWithOwnerCheck({ user: 'alice', id: 2 });
assert.deepEqual(blocked, { status: 403, body: null });
console.log('PASS negative: owner check denies the same cross-user request');

const anonymous = getNote({ user: null, id: 2 });
assert.deepEqual(anonymous, { status: 401, body: null });
console.log('PASS anonymous control: authentication check still applies');
