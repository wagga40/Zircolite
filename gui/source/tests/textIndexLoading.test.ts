import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { Db } from '../src/engine/db';
import { type Activity, isSuperseded, QueryScheduler, type Sender } from '../src/engine/queries';
import { ident } from '../src/engine/sql';
import { configureTextIndex, textIndex } from '../src/engine/textIndex.svelte';
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
const bytes = new Uint8Array([1]);
const scanOf = (query: string) => fx.uids(compile(parse(query), schema));
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

function scheduler(onActivity?: (activity: Activity) => void): QueryScheduler {
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
  return new QueryScheduler(sender, { onActivity });
}

/** The Db configureTextIndex sees, over a scheduler; the file is registered when `arrive` is called. */
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
  it('opens the page and serves field searches without reading index bytes', async () => {
    const s = scheduler();
    const page = pageDb(s);
    let reads = 0;
    configureTextIndex({ files: [FILE] }, page.db, async () => {
      reads++;
      return bytes;
    });
    const query = new QueryState(schema, 6, true);
    for (const q of ['', 'EventID:4624', 'Computer:*02*']) {
      view.q = q;
      await s.rows(`SELECT count(*) FROM events WHERE ${query.where}`);
    }
    expect(reads).toBe(0);
    expect(textIndex.status).toBe('available');
    expect(textIndex.loaded).toBe(0);
    view.q = 'powershell';
    expect(query.where).toContain('fulltext');
    expect(reads).toBe(0);
    page.arrive();
    const sql = `SELECT _zl_uid FROM events WHERE ${query.where} ORDER BY _zl_uid`;
    const [first, second] = await Promise.all([s.rows(sql), s.rows(sql)]);
    expect(first).toEqual(second);
    expect(first).toHaveLength((await scanOf('powershell')).length);
    expect(reads).toBe(1);
    expect(textIndex.status).toBe('ready');
  });

  it('can supersede a bare word before it requests its first chunk', async () => {
    const s = scheduler();
    let reads = 0;
    configureTextIndex({ files: [FILE] }, pageDb(s).db, async () => {
      reads++;
      return bytes;
    });
    const query = new QueryState(schema, 6, true);
    view.q = 'whoami';
    const first = s.rows(`SELECT count(*) FROM events WHERE ${query.where}`, { lane: 'table' });
    const second = s.rows('SELECT 1 AS n', { lane: 'table' });
    await expect(first).rejects.toSatisfy(isSuperseded);
    expect(await second).toEqual([{ n: 1 }]);
    expect(reads).toBe(0);
  });

  it('compiles onto the index, waits for the file, and answers exactly as the scan would', async () => {
    sent = [];
    const s = scheduler();
    const page = pageDb(s);
    configureTextIndex({ files: [FILE] }, page.db, async () => bytes);
    const query = new QueryState(schema, 6, true);
    view.q = 'powershell';
    expect(textIndex.status).toBe('available');
    expect(query.where).toContain('fulltext');
    const answer = s.rows<{ _zl_uid: number }>(`SELECT _zl_uid FROM events WHERE ${query.where} ORDER BY _zl_uid`, { lane: 'table' });
    await tick();
    expect(sent).toEqual([]);
    expect(textIndex.status).toBe('loading');
    page.arrive();
    expect((await answer).map((row) => row._zl_uid)).toEqual(await scanOf('powershell'));
    expect(textIndex.status).toBe('ready');
    expect(sent[0]).toMatch(/^CREATE OR REPLACE VIEW fulltext/);
  });

  it('says the query waits for the index, and how much of the file has loaded', async () => {
    const seen: Activity[] = [];
    const s = scheduler((activity) => seen.push(activity));
    const page = pageDb(s);
    const file = { ...FILE, chunks: ['data/text.parquet.0000.js', 'data/text.parquet.0001.js'] };
    let next: () => void = () => {};
    const load = async (sources: string[], loaded: () => void) => {
      for (const _ of sources) {
        await new Promise<void>((resolve) => {
          next = resolve;
        });
        loaded();
      }
      return bytes;
    };
    configureTextIndex({ files: [file] }, page.db, (file, progress) => load(file.chunks, progress));
    const query = new QueryState(schema, 6, true);
    view.q = 'powershell';
    const answer = s.rows(`SELECT _zl_uid FROM events WHERE ${query.where}`, { lane: 'table' });
    await tick();
    expect(seen.at(-1)).toEqual({ queries: 1, scan: null, waiting: true });
    expect(textIndex).toMatchObject({ status: 'loading', loaded: 0, total: 2 });
    next();
    await tick();
    expect(textIndex).toMatchObject({ loaded: 1, total: 2 });
    next();
    await tick();
    page.arrive();
    await answer;
    expect(textIndex).toMatchObject({ status: 'ready', loaded: 2, total: 2 });
    expect(seen.some((activity) => activity.waiting)).toBe(true);
    expect(seen.at(-1)).toEqual({ queries: 0, scan: null, waiting: false });
  });

  it('rejects the waiting query when the load fails, and the recompiled scan answers', async () => {
    sent = [];
    const s = scheduler();
    let fail: (error: Error) => void = () => {};
    const load = () => new Promise<Uint8Array>((_, reject) => {
      fail = reject;
    });
    configureTextIndex({ files: [FILE] }, pageDb(s).db, load);
    const query = new QueryState(schema, 6, true);
    view.q = 'powershell -error';
    const onIndex = query.where;
    const waiting = s.rows(`SELECT _zl_uid FROM events WHERE ${onIndex}`, { lane: 'table' });
    const watched = expect(waiting).rejects.toThrow('data/text.parquet.0000.js could not be loaded');
    await tick();
    fail(new Error('data/text.parquet.0000.js could not be loaded'));
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
    configureTextIndex({ files: [FILE] }, page.db, async () => bytes);
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
    const again = await s.rows<{ _zl_uid: number }>(`SELECT _zl_uid FROM events WHERE ${where} ORDER BY _zl_uid`, { lane: 'table' });
    expect(again.map((row) => row._zl_uid)).toEqual(await scanOf('whoami'));
  });
});
