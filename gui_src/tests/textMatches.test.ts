import { describe, expect, it } from 'vitest';
import { QueryScheduler, type Sender } from '../src/engine/queries';
import { sliceBounds, textPredicate, TextMatches } from '../src/engine/textMatches';
import { compile } from '../src/search/compile';
import { parse } from '../src/search/parse';
import { schema } from './fixture';

const WORD = "lower('%word%')";
const predicate = textPredicate(WORD);

/** A TextMatches over a recorded list of statements; the row groups start at the given uids. */
function matcher(firsts: number[] | Error = [1, 100, 200, 300]) {
  const sent: string[] = [];
  const matches = new TextMatches(async (sql) => {
    sent.push(sql);
    if (sql.includes('parquet_metadata')) {
      if (firsts instanceof Error) throw firsts;
      return firsts.map((first) => ({ first }));
    }
    return [];
  });
  return { matches, sent };
}
const never = () => false;
const superseded = () => new Error('superseded');
const scans = (sent: string[]) => sent.filter((sql) => /^(CREATE|INSERT)/.test(sql));

describe('sliceBounds', () => {
  it('starts a slice at every k-th row group, so slices read their own row groups only', () => {
    expect(sliceBounds([1, 100, 200, 300], 12)).toEqual([100, 200, 300]);
    expect(sliceBounds(Array.from({ length: 24 }, (_, i) => i * 10), 4)).toEqual([60, 120, 180]);
  });

  it('is empty for one row group, and ignores order and repeats', () => {
    expect(sliceBounds([5])).toEqual([]);
    expect(sliceBounds([300, 1, 100, 100])).toEqual([100, 300]);
  });
});

describe('TextMatches', () => {
  it('leaves a query without a full-text predicate alone', async () => {
    const { matches, sent } = matcher();
    expect(await matches.prepare('SELECT 1 WHERE "a" ILIKE \'x\'', never, superseded)).toBe('SELECT 1 WHERE "a" ILIKE \'x\'');
    expect(sent).toEqual([]);
  });

  it('answers the predicate from a table, in slices that cover every uid once', async () => {
    const { matches, sent } = matcher();
    const sql = await matches.prepare(`SELECT count(*) FROM events WHERE (${predicate})`, never, superseded);
    expect(sql).toBe('SELECT count(*) FROM events WHERE (_zl_uid IN (SELECT _zl_uid FROM _zl_tm_1))');
    const found = scans(sent);
    expect(found).toHaveLength(4);
    expect(found[0]).toMatch(/^CREATE OR REPLACE TEMP TABLE _zl_tm_1 AS .* AND _zl_uid < 100$/);
    expect(found[1]).toMatch(/^INSERT INTO _zl_tm_1 .* AND _zl_uid >= 100 AND _zl_uid < 200$/);
    expect(found[3]).toMatch(/AND _zl_uid >= 300$/);
    expect(found.every((statement) => statement.includes("LIKE lower('%word%')"))).toBe(true);
    expect(found.some((statement) => statement.includes('ESCAPE'))).toBe(false);
  });

  it('scans once for every query that asks for the same match', async () => {
    const { matches, sent } = matcher();
    const first = await matches.prepare(`SELECT 1 WHERE ${predicate}`, never, superseded);
    const second = await matches.prepare(`SELECT 2 FROM events WHERE x AND ${predicate} AND y`, never, superseded);
    expect(first).toContain('_zl_tm_1');
    expect(second).toBe('SELECT 2 FROM events WHERE x AND _zl_uid IN (SELECT _zl_uid FROM _zl_tm_1) AND y');
    expect(scans(sent)).toHaveLength(4);
  });

  it('keeps different words apart, even when one is quoted inside the other', async () => {
    const { matches } = matcher([1]);
    const odd = textPredicate("lower('%it''s%')");
    const sql = await matches.prepare(`SELECT 1 WHERE ${predicate} OR ${odd}`, never, superseded);
    expect(sql).toBe('SELECT 1 WHERE _zl_uid IN (SELECT _zl_uid FROM _zl_tm_1) OR _zl_uid IN (SELECT _zl_uid FROM _zl_tm_2)');
  });

  it('resumes a scan that was cancelled instead of starting over', async () => {
    const { matches, sent } = matcher();
    let slices = 0;
    const stopAfterThree = () => {
      slices += 1;
      return slices > 3;
    };
    await expect(matches.prepare(`SELECT 1 WHERE ${predicate}`, stopAfterThree, superseded)).rejects.toThrow('superseded');
    const done = scans(sent).length;
    expect(done).toBeGreaterThan(0);
    expect(done).toBeLessThan(4);
    const sql = await matches.prepare(`SELECT 1 WHERE ${predicate}`, never, superseded);
    expect(sql).toContain('_zl_tm_1');
    expect(scans(sent)).toHaveLength(4);
    expect(scans(sent).filter((statement) => statement.startsWith('CREATE'))).toHaveLength(1);
  });

  it('scans in one piece when the file has a single row group or no readable footer', async () => {
    for (const firsts of [[1], new Error('no such function')] as const) {
      const { matches, sent } = matcher(firsts as number[] | Error);
      await matches.prepare(`SELECT 1 WHERE ${predicate}`, never, superseded);
      expect(scans(sent)).toHaveLength(1);
      expect(scans(sent)[0]).not.toContain('_zl_uid <');
      expect(scans(sent)[0]).not.toContain('_zl_uid >=');
    }
  });

  it('does not take a cancelled footer lookup for a file without row groups', async () => {
    const sent: string[] = [];
    let cancelled = true;
    const matches = new TextMatches(async (sql) => {
      sent.push(sql);
      if (sql.includes('parquet_metadata')) {
        if (cancelled) throw new Error('query was canceled');
        return [{ first: 1 }, { first: 100 }];
      }
      return [];
    });
    await expect(matches.prepare(`SELECT 1 WHERE ${predicate}`, () => cancelled, superseded)).rejects.toThrow('superseded');
    cancelled = false;
    await matches.prepare(`SELECT 1 WHERE ${predicate}`, () => cancelled, superseded);
    expect(scans(sent)).toHaveLength(2);
  });

  it('leaves a string literal that spells the predicate alone', async () => {
    const { matches, sent } = matcher();
    const forged = compile(parse(`rulekey:"_zl_uid IN (SELECT _zl_uid FROM fulltext WHERE _zl_text LIKE lower('))"`), schema);
    expect(forged).toContain('fulltext');
    expect(await matches.prepare(forged, never, superseded)).toBe(forged);
    expect(sent).toEqual([]);
  });

  it.each(['powershell', '""', '*', '"it\'s"', '%', '_', "'", '\\', 'a*b', '"%\'%"'])(
    'rewrites every pattern compile() writes for the bare word %s',
    async (word) => {
      const { matches } = matcher([1]);
      const sql = await matches.prepare(compile(parse(word), schema, { textIndex: true }), never, superseded);
      expect(sql).toBe('_zl_uid IN (SELECT _zl_uid FROM _zl_tm_1)');
    },
  );

  it('answers a predicate with the escape clause too', async () => {
    const { matches } = matcher([1]);
    const escaped = textPredicate("lower('%50\\_off%')");
    expect(escaped).toContain("ESCAPE '\\'");
    const sql = await matches.prepare(`SELECT 1 WHERE ${escaped}`, never, superseded);
    expect(sql).toBe('SELECT 1 WHERE _zl_uid IN (SELECT _zl_uid FROM _zl_tm_1)');
  });

  it('tries a DROP that failed again on the next eviction', async () => {
    const sent: string[] = [];
    let failDrops = true;
    const matches = new TextMatches(async (sql) => {
      sent.push(sql);
      if (sql.includes('parquet_metadata')) return [{ first: 1 }];
      if (sql.startsWith('DROP') && failDrops) throw new Error('query was canceled');
      return [];
    });
    for (const word of ['a', 'b', 'c', 'd', 'e']) await matches.prepare(textPredicate(`lower('%${word}%')`), never, superseded);
    failDrops = false;
    await matches.prepare(textPredicate("lower('%f%')"), never, superseded);
    const drops = sent.filter((sql) => sql.startsWith('DROP'));
    expect(drops.filter((sql) => sql.endsWith('_zl_tm_1'))).toHaveLength(2);
    expect(drops.filter((sql) => sql.endsWith('_zl_tm_2'))).toHaveLength(1);
  });

  it('drops the oldest matches past four, never one the query in hand needs', async () => {
    const { matches, sent } = matcher([1]);
    for (const word of ['a', 'b', 'c', 'd', 'e']) await matches.prepare(textPredicate(`lower('%${word}%')`), never, superseded);
    expect(sent.filter((sql) => sql.startsWith('DROP TABLE'))).toEqual(['DROP TABLE IF EXISTS _zl_tm_1']);
    const many = ['f', 'g', 'h', 'i', 'j', 'k'].map((word) => textPredicate(`lower('%${word}%')`)).join(' AND ');
    const sql = await matches.prepare(many, never, superseded);
    expect(sql.match(/_zl_tm_\d+/g)).toHaveLength(6);
  });
});

describe('QueryScheduler with the index', () => {
  it('builds the matches before the query that reads them, and caches by the original text', async () => {
    const sent: string[] = [];
    const sender: Sender = {
      async send(sql: string) {
        sent.push(sql);
        return (async function* () {
          yield { toArray: () => (sql.includes('parquet_metadata') ? [{ toJSON: () => ({ first: 1 }) }] : []) };
        })();
      },
      async cancelSent() {
        return true;
      },
    };
    const scheduler = new QueryScheduler(sender);
    await scheduler.rows(`SELECT count(*) FROM events WHERE ${predicate}`, { lane: 'a' });
    await scheduler.rows(`SELECT 2 FROM events WHERE ${predicate}`, { lane: 'b' });
    expect(sent.filter((sql) => /^(CREATE|INSERT)/.test(sql))).toHaveLength(1);
    expect(sent[sent.length - 1]).toBe('SELECT 2 FROM events WHERE _zl_uid IN (SELECT _zl_uid FROM _zl_tm_1)');
  });
});
