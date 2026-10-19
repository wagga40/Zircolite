import { describe, expect, it } from 'vitest';
import { isSuperseded, QueryScheduler, type Sender, Superseded } from '../src/engine/queries';
import { FieldMatches, sliceBounds, type Stop, TEXT_VIEW_SQL, textPredicate, TextMatches } from '../src/engine/textMatches';
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
/** A Stop that gives the query up once `cancelled` says so. */
function stopWhen(cancelled: () => boolean): Stop {
  return { cancelled, superseded: () => new Error('superseded'), until: (promise) => promise };
}
const never = stopWhen(() => false);
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
    expect(await matches.prepare('SELECT 1 WHERE "a" ILIKE \'x\'', never)).toBe('SELECT 1 WHERE "a" ILIKE \'x\'');
    expect(sent).toEqual([]);
  });

  it('answers the predicate from a table, in slices that cover every uid once', async () => {
    const { matches, sent } = matcher();
    const sql = await matches.prepare(`SELECT count(*) FROM events WHERE (${predicate})`, never);
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
    const first = await matches.prepare(`SELECT 1 WHERE ${predicate}`, never);
    const second = await matches.prepare(`SELECT 2 FROM events WHERE x AND ${predicate} AND y`, never);
    expect(first).toContain('_zl_tm_1');
    expect(second).toBe('SELECT 2 FROM events WHERE x AND _zl_uid IN (SELECT _zl_uid FROM _zl_tm_1) AND y');
    expect(scans(sent)).toHaveLength(4);
  });

  it('keeps different words apart, even when one is quoted inside the other', async () => {
    const { matches } = matcher([1]);
    const odd = textPredicate("lower('%it''s%')");
    const sql = await matches.prepare(`SELECT 1 WHERE ${predicate} OR ${odd}`, never);
    expect(sql).toBe('SELECT 1 WHERE _zl_uid IN (SELECT _zl_uid FROM _zl_tm_1) OR _zl_uid IN (SELECT _zl_uid FROM _zl_tm_2)');
  });

  it('resumes a scan that was cancelled instead of starting over', async () => {
    const { matches, sent } = matcher();
    let slices = 0;
    const stopAfterThree = () => {
      slices += 1;
      return slices > 3;
    };
    await expect(matches.prepare(`SELECT 1 WHERE ${predicate}`, stopWhen(stopAfterThree))).rejects.toThrow('superseded');
    const done = scans(sent).length;
    expect(done).toBeGreaterThan(0);
    expect(done).toBeLessThan(4);
    const sql = await matches.prepare(`SELECT 1 WHERE ${predicate}`, never);
    expect(sql).toContain('_zl_tm_1');
    expect(scans(sent)).toHaveLength(4);
    expect(scans(sent).filter((statement) => statement.startsWith('CREATE'))).toHaveLength(1);
  });

  it('scans in one piece when the file has a single row group or no readable footer', async () => {
    for (const firsts of [[1], new Error('no such function')] as const) {
      const { matches, sent } = matcher(firsts as number[] | Error);
      await matches.prepare(`SELECT 1 WHERE ${predicate}`, never);
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
    await expect(matches.prepare(`SELECT 1 WHERE ${predicate}`, stopWhen(() => cancelled))).rejects.toThrow('superseded');
    cancelled = false;
    await matches.prepare(`SELECT 1 WHERE ${predicate}`, stopWhen(() => cancelled));
    expect(scans(sent)).toHaveLength(2);
  });

  it('leaves a string literal that spells the predicate alone', async () => {
    const { matches, sent } = matcher();
    const forged = compile(parse(`rulekey:"_zl_uid IN (SELECT _zl_uid FROM fulltext WHERE _zl_text LIKE lower('))"`), schema);
    expect(forged).toContain('fulltext');
    expect(await matches.prepare(forged, never)).toBe(forged);
    expect(sent).toEqual([]);
  });

  it.each(['powershell', '""', '*', '"it\'s"', '%', '_', "'", '\\', 'a*b', '"%\'%"'])(
    'rewrites every pattern compile() writes for the bare word %s',
    async (word) => {
      const { matches } = matcher([1]);
      const sql = await matches.prepare(compile(parse(word), schema, { textIndex: true }), never);
      expect(sql).toBe('_zl_uid IN (SELECT _zl_uid FROM _zl_tm_1)');
    },
  );

  it('answers a predicate with the escape clause too', async () => {
    const { matches } = matcher([1]);
    const escaped = textPredicate("lower('%50\\_off%')");
    expect(escaped).toContain("ESCAPE '\\'");
    const sql = await matches.prepare(`SELECT 1 WHERE ${escaped}`, never);
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
    for (const word of ['a', 'b', 'c', 'd', 'e']) await matches.prepare(textPredicate(`lower('%${word}%')`), never);
    failDrops = false;
    await matches.prepare(textPredicate("lower('%f%')"), never);
    const drops = sent.filter((sql) => sql.startsWith('DROP'));
    expect(drops.filter((sql) => sql.endsWith('_zl_tm_1'))).toHaveLength(2);
    expect(drops.filter((sql) => sql.endsWith('_zl_tm_2'))).toHaveLength(1);
  });

  it('drops the oldest matches past four, never one the query in hand needs', async () => {
    const { matches, sent } = matcher([1]);
    for (const word of ['a', 'b', 'c', 'd', 'e']) await matches.prepare(textPredicate(`lower('%${word}%')`), never);
    expect(sent.filter((sql) => sql.startsWith('DROP TABLE'))).toEqual(['DROP TABLE IF EXISTS _zl_tm_1']);
    const many = ['f', 'g', 'h', 'i', 'j', 'k'].map((word) => textPredicate(`lower('%${word}%')`)).join(' AND ');
    const sql = await matches.prepare(many, never);
    expect(sql.match(/_zl_tm_\d+/g)).toHaveLength(6);
  });
});

describe('TextMatches while the index loads', () => {
  function deferred() {
    let resolve: () => void = () => {};
    let reject: (error: unknown) => void = () => {};
    const promise = new Promise<void>((yes, no) => {
      resolve = yes;
      reject = no;
    });
    return { promise, resolve, reject };
  }

  it('waits for the file, then opens the view once, before its first slice', async () => {
    const { matches, sent } = matcher([1]);
    const file = deferred();
    matches.use({ registered: file.promise, failed: () => {} });
    const first = matches.prepare(`SELECT 1 WHERE ${predicate}`, never);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(sent).toEqual([]);
    file.resolve();
    await first;
    expect(sent[0]).toBe(TEXT_VIEW_SQL);
    await matches.prepare(textPredicate("lower('%other%')"), never);
    expect(sent.filter((sql) => sql === TEXT_VIEW_SQL)).toHaveLength(1);
  });

  it('rejects with the reason the file never came', async () => {
    const { matches, sent } = matcher([1]);
    matches.use({ registered: Promise.reject(new Error('data/text.parquet.0000.js could not be loaded')), failed: () => {} });
    await expect(matches.prepare(`SELECT 1 WHERE ${predicate}`, never)).rejects.toThrow('could not be loaded');
    expect(sent).toEqual([]);
  });

  it('reports a file the engine cannot open, and rejects with the engine error', async () => {
    const reported: unknown[] = [];
    const matches = new TextMatches(async (sql) => {
      if (sql === TEXT_VIEW_SQL) throw new Error('Invalid Input Error: No magic bytes found at end of file');
      return [];
    });
    matches.use({ registered: Promise.resolve(), failed: (error) => reported.push(error) });
    await expect(matches.prepare(`SELECT 1 WHERE ${predicate}`, never)).rejects.toThrow('No magic bytes');
    expect(reported).toHaveLength(1);
  });

  it('does not report a view a Stop interrupted, and opens it on the next query', async () => {
    const reported: unknown[] = [];
    let cancelled = false;
    let opens = 0;
    const matches = new TextMatches(async (sql) => {
      if (sql === TEXT_VIEW_SQL && ++opens === 1) {
        cancelled = true;
        throw new Error('INTERRUPT Error: Interrupted!');
      }
      return sql.includes('parquet_metadata') ? [{ first: 1 }] : [];
    });
    matches.use({ registered: Promise.resolve(), failed: (error) => reported.push(error) });
    await expect(matches.prepare(`SELECT 1 WHERE ${predicate}`, stopWhen(() => cancelled))).rejects.toThrow('superseded');
    cancelled = false;
    expect(await matches.prepare(`SELECT 1 WHERE ${predicate}`, never)).toContain('_zl_tm_1');
    expect([opens, reported.length]).toEqual([2, 0]);
  });
});

describe('QueryScheduler with the index', () => {
  it('gives up a query that waits for the index when it is stopped, and runs the next one', async () => {
    const sent: string[] = [];
    const sender: Sender = {
      async send(sql: string) {
        sent.push(sql);
        return (async function* () {
          yield { toArray: () => [{ toJSON: () => ({ n: 1 }) }] };
        })();
      },
      async cancelSent() {
        return false;
      },
    };
    const scheduler = new QueryScheduler(sender);
    scheduler.useTextIndex({ registered: new Promise(() => {}), failed: () => {} });
    const waiting = scheduler.rows(`SELECT count(*) FROM events WHERE ${predicate}`, { lane: 'table' });
    const watched = expect(waiting).rejects.toSatisfy(isSuperseded);
    await new Promise((resolve) => setTimeout(resolve, 0));
    scheduler.cancel();
    await watched;
    expect(await scheduler.rows('SELECT 1 AS n', { lane: 'other' })).toEqual([{ n: 1 }]);
    expect(sent).toEqual(['SELECT 1 AS n']);
  });

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

/** A Stop whose supersede is the real one, so isSuperseded recognises it. */
function fakeStop(cancelled: () => boolean): Stop {
  return {
    cancelled,
    superseded: () => new Superseded(),
    // Like the scheduler's: a cancel before the call rejects, one while it waits does not.
    until: (p) => (cancelled() ? Promise.reject(new Superseded()) : p),
  };
}

describe('after a cancel', () => {
  it('sends no statement once the query is given up', async () => {
    const sent: string[] = [];
    let cancelled = false;
    const matches = new TextMatches(async (sql) => {
      sent.push(sql);
      return sql.startsWith('SELECT min(') ? [{ first: 0 }, { first: 100 }] : [];
    });
    let release = () => {};
    const registered = new Promise<void>((resolve) => (release = resolve));
    matches.use({ registered, failed() {} });
    const prepared = matches.prepare(textPredicate("lower('%a%')"), fakeStop(() => cancelled));
    cancelled = true;
    release();
    await expect(prepared).rejects.toSatisfy(isSuperseded);
    expect(sent).toEqual([]);
  });
});

describe('an index that cannot be read', () => {
  it('reports the failure, so the search falls back to the scan', async () => {
    const failures: unknown[] = [];
    const matches = new TextMatches(async (sql) => {
      if (sql.startsWith('SELECT min(')) return [{ first: 0 }, { first: 100 }, { first: 200 }];
      if (sql.includes('_zl_uid >= ')) throw new Error('IO Error: corrupt page');
      return [];
    });
    matches.use({ registered: Promise.resolve(), failed: (error) => failures.push(error) });
    await expect(matches.prepare(textPredicate("lower('%a%')"), fakeStop(() => false))).rejects.toThrow('corrupt page');
    expect(failures).toHaveLength(1);
  });

  it('does not blame the file for a Stop', async () => {
    const failures: unknown[] = [];
    let cancelled = false;
    const matches = new TextMatches(async (sql) => {
      if (sql.includes('_zl_uid >= ')) {
        cancelled = true;
        throw new Error('INTERRUPT');
      }
      return sql.startsWith('SELECT min(') ? [{ first: 0 }, { first: 100 }, { first: 200 }] : [];
    });
    matches.use({ registered: Promise.resolve(), failed: (error) => failures.push(error) });
    await expect(matches.prepare(textPredicate("lower('%a%')"), fakeStop(() => cancelled))).rejects.toSatisfy(isSuperseded);
    expect(failures).toEqual([]);
  });
});

describe('guards after a cancel', () => {
  it('looks up no slice bounds once the query is given up', async () => {
    const { matches, sent } = matcher();
    await expect(matches.prepare(`SELECT 1 WHERE ${predicate}`, stopWhen(() => true))).rejects.toThrow('superseded');
    expect(sent).toEqual([]);
  });

  it('drops no table once the query is given up, and the next eviction drops them', async () => {
    const { matches, sent } = matcher();
    const like = (word: string) => textPredicate(`lower('%${word}%')`);
    await matches.prepare(['a', 'b', 'c', 'd'].map(like).join(' AND '), never);
    let cancelled = true;
    await expect(matches.prepare(like('e'), stopWhen(() => cancelled))).rejects.toThrow('superseded');
    expect(sent.some((sql) => sql.startsWith('DROP TABLE'))).toBe(false);
    cancelled = false;
    await matches.prepare(like('f'), never);
    expect(sent.filter((sql) => sql.startsWith('DROP TABLE'))).toEqual(['DROP TABLE IF EXISTS _zl_tm_1', 'DROP TABLE IF EXISTS _zl_tm_2']);
  });
});

describe('FieldMatches', () => {
  /** Every column is as large as given; the matches built are the large ones. */
  function fieldMatcher(bytes = 1e9, large?: number) {
    const sent: string[] = [];
    const matches = new FieldMatches(async (sql) => {
      sent.push(sql);
      if (sql.includes('total_uncompressed_size')) return schema.fields.map((field) => ({ c: field.name, b: bytes }));
      return sql.includes('parquet_metadata') ? [{ first: 1 }] : [];
    }, large);
    return { matches, sent };
  }

  it.each([
    'CommandLine:*whoami*', 'Image:*\\cmd.exe', 'Image:*50_off*', 'CommandLine:*"it\'s"*', 'CommandLine:*100%*',
    '"it\'s \\"odd\\"":*x*', 'EventID:*62*', 'Image:*a*b*', 'CommandLine:*"\\"q\\""*',
  ])('rewrites the match compile() writes for %s', async (query) => {
    const { matches, sent } = fieldMatcher();
    expect(await matches.prepare(compile(parse(query), schema, { matches: true }), never)).toBe('_zl_uid IN (SELECT _zl_uid FROM _zl_fm_1)');
    expect(sent.some((sql) => sql.includes("parquet_metadata('events.parquet')"))).toBe(true);
    expect(scans(sent)[0]).toMatch(/^CREATE OR REPLACE TEMP TABLE _zl_fm_1 AS SELECT _zl_uid FROM events WHERE \(/);
  });

  it('scans a large column for a plain contains through lower() LIKE, the engine\'s fast contains', async () => {
    for (const [query, scan] of [
      ['CommandLine:*whoami*', `(lower("CommandLine") LIKE lower('%whoami%'))`],
      ['EventID:*62*', `(lower(CAST("EventID" AS VARCHAR)) LIKE lower('%62%'))`],
      ['CommandLine:*"it\'s"*', `(lower("CommandLine") LIKE lower('%it''s%'))`],
      ['Image:*a*b*', `("Image" ILIKE '%a%b%')`],
      ['Image:*50_off*', String.raw`("Image" ILIKE '%50\_off%' ESCAPE '\')`],
    ]) {
      const { matches, sent } = fieldMatcher();
      await matches.prepare(compile(parse(query), schema, { matches: true }), never);
      expect(scans(sent)[0], query).toBe(`CREATE OR REPLACE TEMP TABLE _zl_fm_1 AS SELECT _zl_uid FROM events WHERE ${scan}`);
    }
  });

  it('answers a match on a small column in place, where a table would cost more than the scans it saves', async () => {
    const { matches, sent } = fieldMatcher(1024);
    const sql = compile(parse('CommandLine:*whoami* OR Image:*\\cmd.exe'), schema, { matches: true });
    expect(await matches.prepare(sql, never)).toBe(String.raw`(("CommandLine" ILIKE '%whoami%') OR ("Image" ILIKE '%\\cmd.exe' ESCAPE '\'))`);
    expect(scans(sent)).toEqual([]);
    expect(sent.filter((q) => q.includes('total_uncompressed_size'))).toHaveLength(1);
    await matches.prepare(sql, never);
    expect(sent.filter((q) => q.includes('total_uncompressed_size'))).toHaveLength(1);
  });

  it('slices a scan by the size of its column, about a second of reading each', async () => {
    for (const [mib, slices] of [[120, 1], [600, 2], [3125, 12]] as const) {
      const sent: string[] = [];
      const matches = new FieldMatches(async (sql) => {
        sent.push(sql);
        if (sql.includes('total_uncompressed_size')) return [{ c: 'CommandLine', b: mib * 1024 * 1024 }];
        return sql.includes('parquet_metadata') ? Array.from({ length: 24 }, (_, i) => ({ first: 1 + i * 1000 })) : [];
      });
      await matches.prepare(compile(parse('CommandLine:*whoami*'), schema, { matches: true }), never);
      expect(scans(sent), `${mib} MiB`).toHaveLength(slices);
    }
  });

  it('answers in place when the file cannot say how large its columns are', async () => {
    const sent: string[] = [];
    const matches = new FieldMatches(async (sql) => {
      sent.push(sql);
      if (sql.includes('parquet_metadata')) throw new Error('no such file');
      return [];
    });
    const sql = compile(parse('CommandLine:*whoami*'), schema, { matches: true });
    expect(await matches.prepare(sql, never)).toBe(`("CommandLine" ILIKE '%whoami%')`);
    expect(scans(sent)).toEqual([]);
  });

  it('leaves a match that does not start with a wildcard, and a literal that spells one, alone', async () => {
    const { matches, sent } = fieldMatcher();
    for (const query of ['Image:C:*', 'EventID:4624', 'rulekey:"_zl_uid IN (SELECT _zl_uid FROM events WHERE lower(\\"x\\") LIKE lower(\'%a%\'))"']) {
      const sql = compile(parse(query), schema, { matches: true });
      expect(await matches.prepare(sql, never)).toBe(sql);
    }
    expect(sent).toEqual([]);
  });
});
