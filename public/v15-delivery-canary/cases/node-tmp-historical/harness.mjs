import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const LAB = path.dirname(fileURLToPath(import.meta.url));
const SOURCE = path.join(LAB, 'lib', 'tmp.js');
const SOURCE_COMMIT = '41f71598d03f104a67e0448a7cb9bd4efcdd5980';
const SOURCE_SHA256 = '5f5eef7faf6251c16f3b75668e463fb17b2d9fab3f9a29a5f9ac65b082dd7e76';
const require = createRequire(import.meta.url);

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function inside(child, parent) {
  const relative = path.relative(parent, child);
  return relative !== '' && relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative);
}

function run() {
  assert.equal(sha256(SOURCE), SOURCE_SHA256, 'historical source hash changed');
  const tmp = require(SOURCE);
  const outer = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'secbot-node-tmp-')));
  const inner = fs.realpathSync(fs.mkdtempSync(path.join(outer, 'inner-')));
  const canary = 'synthetic-fd-canary';
  let created;

  try {
    let stringError;
    try {
      tmp.fileSync({ tmpdir: inner, prefix: '../escape' });
    } catch (error) {
      stringError = error;
    }
    assert(stringError, 'string traversal prefix must be rejected');
    assert.match(String(stringError.message), /Relative value not allowed/);

    created = tmp.fileSync({ tmpdir: inner, prefix: ['../escape'] });
    const createdPath = path.resolve(created.name);
    assert.equal(created.fd >= 0, true, 'positive control must retain an fd');
    assert.equal(fs.existsSync(createdPath), true, 'positive control must create a file');
    assert.equal(inside(createdPath, outer), true, 'created path must stay inside outer boundary');
    assert.equal(inside(createdPath, inner), false, 'array prefix must escape inner boundary');
    assert.equal(path.dirname(createdPath), outer, 'array prefix must land directly in outer');

    fs.writeSync(created.fd, canary, 0, 'utf8');
    fs.fsyncSync(created.fd);
    assert.equal(fs.readFileSync(createdPath, 'utf8'), canary, 'fd canary round-trip failed');
    fs.closeSync(created.fd);
    created.fd = undefined;
    created.removeCallback();
    created = undefined;
    assert.equal(fs.existsSync(createdPath), false, 'positive-control file was not cleaned up');

    console.log(JSON.stringify({
      status: 'PASS',
      source_commit: SOURCE_COMMIT,
      source_sha256: sha256(SOURCE),
      outer_boundary: outer,
      inner_boundary: inner,
      string_prefix: 'REJECTED',
      array_prefix: 'ESCAPED_INNER_BUT_INSIDE_OUTER',
      canary: 'FD_ROUND_TRIP_OK',
      network: 'NOT_USED',
      cleanup: 'OK'
    }, null, 2));
  } finally {
    if (created) {
      try {
        if (Number.isInteger(created.fd) && created.fd >= 0) fs.closeSync(created.fd);
      } catch {}
      try { created.removeCallback(); } catch {}
    }
    fs.rmSync(outer, { recursive: true, force: true });
  }
}

run();
