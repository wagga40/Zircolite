import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { Db } from '../src/engine/db';
import { isSuperseded, QueryScheduler, type Sender } from '../src/engine/queries';
import { ident } from '../src/engine/sql';
import { loadTextIndex, textIndex } from '../src/engine/textIndex.svelte';
import { compile } from '../src/search/compile';
import { parse } from '../src/search/parse';
import { EMPTY } from '../src/state/hash';
import { QueryState } from '../src/state/query.svelte';
import { view } from '../src/state/view.svelte';
import { type Fixture, FIELDS, openFixture, schema } from './fixture';

// A link with a bare word opens before the index has loaded. Its queries go onto the index at once and
// wait for the file, on a real engine that has no fulltext view until the first of them opens it.

let fx: Fixture;
let dir: string;
let sent: string[] = [];

const FILE = { name: 'text.parquet', kind: 'index' as const, bytes: 1, sha256: 'x', chunks: ['data/text.parquet.0000.js'] };
const store = { take: () => new Blob([new Uint8Array([1])]) };
const scanOf = (query: string) => fx.uids(compile(parse(query), schema));
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

function scheduler(): QueryScheduler {
  const sender: Sender = {
    async send(sql: string) {
      sent.push(sql);
      const rows = await fx.rows(sql);
      return (async function* () {
        yield { toArray: () => rows.map((row) => ({ toJSON: () => row })) };
      })();
    },
    async cancelSent() {
      return false;
    },
  };
  return new QueryScheduler(sender);
}

/** The Db loadTextIndex sees, over a scheduler; the file is registered when `arrive` is called. */
function pageDb(s: QueryScheduler) {
  let arrive: () => void = () => {};
  const arrived = new Promise<void>((resolve) => {
    arrive = resolve;
  });
  const db: Pick<Db, 'register' | 'useTextIndex'> = {
    register: () => arrived,
    useTextIndex: (source) => s.useTextIndex(source),
  };
  return { db, arrive };
}

beforeAll(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zl-text-load-'));
  const text = `lower(concat_ws(chr(31), ${FIELDS.map((f) => `CAST(${ident(f.name)} AS VARCHAR)`).join(', ')}))`;
  fx = await openFixture([
    'DROP TABLE fulltext',
    `COPY (SELECT _zl_uid, ${text} AS _zl_text FROM events ORDER BY _zl_uid) TO '${dir.replaceAll("'", "''")}/text.parquet' (FORMAT parquet)`,
    `SET file_search_path = '${dir.replaceAll("'", "''")}'`,
  ]);
});

afterAll(() => {
  fx.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

afterEach(() => {
  view.apply(EMPTY);
  textIndex.status = 'absent';
  textIndex.error = null;
});

describe('a bare word while the index loads', () => {
  it('compiles onto the index, waits for the file, and answers exactly as the scan would', async () => {
    sent = [];
    const s = scheduler();
    const page = pageDb(s);
    const loading = loadTextIndex({ files: [FILE] }, store, page.db, async () => {});
    const query = new QueryState(schema, 6, true);
    view.q = 'powershell';
    expect(textIndex.status).toBe('loading');
    expect(query.where).toContain('fulltext');
    const answer = s.rows<{ _zl_uid: number }>(`SELECT _zl_uid FROM events WHERE ${query.where} ORDER BY _zl_uid`, { lane: 'table' });
    await tick();
    expect(sent).toEqual([]);
    page.arrive();
    await loading;
    expect(textIndex.status).toBe('ready');
    expect((await answer).map((row) => row._zl_uid)).toEqual(await scanOf('powershell'));
    expect(sent[0]).toMatch(/^CREATE OR REPLACE VIEW fulltext/);
  });

  it('rejects the waiting query when the load fails, and the recompiled scan answers', async () => {
    sent = [];
    const s = scheduler();
    let fail: (error: Error) => void = () => {};
    const load = () => new Promise<void>((_, reject) => {
      fail = reject;
    });
    const loading = loadTextIndex({ files: [FILE] }, store, pageDb(s).db, load);
    const query = new QueryState(schema, 6, true);
    view.q = 'powershell -error';
    const onIndex = query.where;
    const waiting = s.rows(`SELECT _zl_uid FROM events WHERE ${onIndex}`, { lane: 'table' });
    const watched = expect(waiting).rejects.toThrow('data/text.parquet.0000.js could not be loaded');
    await tick();
    fail(new Error('data/text.parquet.0000.js could not be loaded'));
    await loading;
    await watched;
    expect(textIndex.status).toBe('failed');
    expect(query.where).not.toBe(onIndex);
    expect(query.where).not.toContain('fulltext');
    const scan = await s.rows<{ _zl_uid: number }>(`SELECT _zl_uid FROM events WHERE ${query.where} ORDER BY _zl_uid`, { lane: 'table' });
    expect(scan.map((row) => row._zl_uid)).toEqual(await scanOf('powershell -error'));
    expect(sent.some((sql) => sql.includes('fulltext'))).toBe(false);
  });

  it('gives a Stop while it waits Superseded at once, and the page goes on', async () => {
    sent = [];
    const s = scheduler();
    const page = pageDb(s);
    const loading = loadTextIndex({ files: [FILE] }, store, page.db, async () => {});
    const query = new QueryState(schema, 6, true);
    view.q = 'whoami';
    const where = query.where;
    const waiting = s.rows(`SELECT count(*) AS n FROM events WHERE ${where}`, { lane: 'table' });
    const watched = expect(waiting).rejects.toSatisfy(isSuperseded);
    await tick();
    s.cancel();
    await watched;
    expect(await s.rows('SELECT count(*)::INTEGER AS n FROM events', { lane: 'other' })).toEqual([{ n: 6 }]);
    page.arrive();
    await loading;
    const again = await s.rows<{ _zl_uid: number }>(`SELECT _zl_uid FROM events WHERE ${where} ORDER BY _zl_uid`, { lane: 'table' });
    expect(again.map((row) => row._zl_uid)).toEqual(await scanOf('whoami'));
  });
});
