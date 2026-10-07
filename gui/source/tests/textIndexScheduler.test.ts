import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { isSuperseded, QueryScheduler, type Sender } from '../src/engine/queries';
import { ident } from '../src/engine/sql';
import { compile } from '../src/search/compile';
import { parse } from '../src/search/parse';
import { type Fixture, FIELDS, openFixture, schema } from './fixture';

// The path every bare-word search takes in the viewer: the compiled predicate goes through the scheduler,
// which builds the matches in slices along the row groups of a real Parquet file, on a real engine.

let fx: Fixture;
let dir: string;
let sent: string[] = [];
let before: ((sql: string) => void | Promise<void>) | null = null;
let after: ((sql: string) => void) | null = null;

function scheduler(): QueryScheduler {
  const sender: Sender = {
    async send(sql: string) {
      sent.push(sql);
      if (before) await before(sql);
      const rows = await fx.rows(sql);
      if (after) after(sql);
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

const statements = (pattern: RegExp) => sent.filter((sql) => pattern.test(sql));
const scanning = /^(CREATE OR REPLACE TEMP|INSERT)/;
const through = (query: string) => compile(parse(query), schema, { textIndex: true });
const plain = (query: string) => compile(parse(query), schema);

beforeAll(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zl-text-'));
  const text = `lower(concat_ws(chr(31), ${FIELDS.map((f) => `CAST(${ident(f.name)} AS VARCHAR)`).join(', ')}))`;
  fx = await openFixture([
    `INSERT INTO events SELECT 10000000000 + i * 7, 2, NULL, NULL, 'Security', 4624 + (i % 5),
       CASE WHEN i % 3 = 0 THEN 'DC01' ELSE 'WS0' || (i % 9) END,
       CASE WHEN i % 11 = 0 THEN 'it''s 100%' WHEN i % 13 = 0 THEN '50_off' ELSE 'user' || i END,
       CASE WHEN i % 17 = 0 THEN 'C:\\Tools\\PowerShell.exe' ELSE 'C:\\Windows\\cmd.exe' END,
       CASE WHEN i % 19 = 0 THEN 'cmd /c whoami' WHEN i % 23 = 0 THEN 'x'' OR 1=1' ELSE NULL END,
       CASE WHEN i % 29 = 0 THEN 'ÀÉÎ' ELSE NULL END,
       CASE WHEN i % 31 = 0 THEN 'error' ELSE NULL END
     FROM range(20000) t(i)`,
    'DROP TABLE fulltext',
    `COPY (SELECT _zl_uid, ${text} AS _zl_text FROM events ORDER BY _zl_uid) TO '${dir.replaceAll("'", "''")}/text.parquet' (FORMAT parquet, ROW_GROUP_SIZE 2048)`,
    `SET file_search_path = '${dir.replaceAll("'", "''")}'`,
    "CREATE VIEW fulltext AS SELECT * FROM read_parquet('text.parquet')",
  ]);
});

afterAll(() => {
  fx.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('the index through the scheduler, on a real engine', () => {
  it('has several row groups, so the scan really is sliced', async () => {
    const [groups] = await fx.rows("SELECT count(DISTINCT row_group_id) AS n FROM parquet_metadata('text.parquet')");
    expect(Number(groups.n)).toBeGreaterThan(4);
  });

  it.each([
    'powershell', '"100% it\'s"', '50_off', 'WS02', 'cmd*whoami', '"x\' OR 1=1"', 'DC01 -powershell', 'error', '"C:\\Tools"', 'ÀÉÎ',
    'powershell OR whoami', '-powershell', '(powershell OR "it\'s") -whoami', 'power* shell', 'PowerShell', '"%"', '"_"',
    'dc01 powershell -error', '-(cmd OR error)', 'user1*', '*',
  ])('finds exactly what the scan finds for %s', async (query) => {
    sent = [];
    const rows = await scheduler().rows<{ _zl_uid: number }>(`SELECT _zl_uid FROM events WHERE ${through(query)} ORDER BY _zl_uid`);
    expect(rows.map((row) => row._zl_uid)).toEqual(await fx.uids(plain(query)));
    if (/[a-z]/i.test(query) && !query.startsWith('-')) expect(statements(/^INSERT/).length).toBeGreaterThan(0);
  });

  it('builds the matches once for the queries that share a word', async () => {
    sent = [];
    const s = scheduler();
    const where = through('powershell');
    await s.rows(`SELECT count(*) AS n FROM events WHERE ${where}`, { lane: 'strip' });
    await s.rows(`SELECT _zl_uid FROM events WHERE ${where}`, { lane: 'table' });
    expect(statements(/^CREATE OR REPLACE TEMP/)).toHaveLength(1);
    expect(statements(scanning).length).toBe(statements(/^INSERT/).length + 1);
    expect(statements(/^SELECT .* FROM events WHERE _zl_uid IN \(SELECT _zl_uid FROM _zl_tm_\d+\)/)).toHaveLength(2);
  });

  it('lets another lane finish a scan that one lane cancelled midway', async () => {
    sent = [];
    const s = scheduler();
    const where = through('powershell');
    let slices = 0;
    after = (sql) => {
      if (scanning.test(sql) && ++slices === 3) s.cancel('strip');
    };
    const stopped = s.rows(`SELECT count(*) AS n FROM events WHERE ${where}`, { lane: 'strip' });
    const table = s.rows<{ _zl_uid: number }>(`SELECT _zl_uid FROM events WHERE ${where} ORDER BY _zl_uid`, { lane: 'table' });
    await expect(stopped).rejects.toSatisfy(isSuperseded);
    after = null;
    expect((await table).map((row) => row._zl_uid)).toEqual(await fx.uids(plain('powershell')));
    expect(statements(/^CREATE OR REPLACE TEMP/)).toHaveLength(1);
  });

  it('gives the right count when a slice is interrupted before it commits, and the search is run again', async () => {
    sent = [];
    const s = scheduler();
    const where = through('whoami');
    let inserts = 0;
    before = (sql) => {
      if (/^INSERT/.test(sql) && ++inserts === 2) {
        s.cancel();
        throw new Error('INTERRUPT Error: Interrupted!');
      }
    };
    await expect(s.rows(`SELECT count(*) AS n FROM events WHERE ${where}`, { lane: 'table' })).rejects.toSatisfy(isSuperseded);
    before = null;
    const [again] = await s.rows<{ n: number }>(`SELECT count(*) AS n FROM events WHERE ${where}`, { lane: 'table' });
    const [scan] = await fx.rows(`SELECT count(*) AS n FROM events WHERE ${plain('whoami')}`);
    expect(Number(again.n)).toBe(Number(scan.n));
  });

  it('counts right after a slice committed but its result never arrived', async () => {
    sent = [];
    const s = scheduler();
    const where = through('error');
    let inserts = 0;
    after = (sql) => {
      if (/^INSERT/.test(sql) && ++inserts === 2) {
        s.cancel();
        throw new Error('the result was lost');
      }
    };
    await expect(s.rows(`SELECT count(*) AS n FROM events WHERE ${where}`, { lane: 'table' })).rejects.toSatisfy(isSuperseded);
    after = null;
    const [again] = await s.rows<{ n: number }>(`SELECT count(*) AS n FROM events WHERE ${where}`, { lane: 'table' });
    const [scan] = await fx.rows(`SELECT count(*) AS n FROM events WHERE ${plain('error')}`);
    expect(Number(again.n)).toBe(Number(scan.n));
  });
});
