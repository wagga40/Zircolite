import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Superseded } from '../src/engine/queries';
import { csvLine } from '../src/explore/export';
import { columnWidths, LOGGING_SQL, numericType, resultSql, runQuery, SqlRefused, TABLES_SQL, trimStatement } from '../src/sql/console';
import { type Fixture, openFixture } from './fixture';

let db: Fixture;
beforeAll(async () => { db = await openFixture(); });
afterAll(() => db.close());

const send = (sql: string) => db.rows(sql);
const events = async () => Number((await db.rows('SELECT count(*) AS n FROM events'))[0].n);

describe('what the console runs', () => {
  it('runs one SELECT, in any of its forms', async () => {
    for (const text of ['SELECT 1', 'WITH a AS (SELECT 1 AS x) SELECT * FROM a', 'VALUES (1)', 'FROM events', 'SELECT 1 -- note', 'DESCRIBE events']) {
      await expect(runQuery(send, text), text).resolves.toHaveProperty('columns');
    }
  });

  it('never changes the package, whatever it is given', async () => {
    const before = await events();
    const texts = [
      'DROP TABLE events', "INSERT INTO hits VALUES (0, 1)", "ATTACH 'x.db'", "COPY events TO 'x.csv'", 'SET threads = 1', 'PRAGMA version',
      'DELETE FROM events', 'SELECT 1; DROP TABLE events', 'SELECT 1) ; DROP TABLE events; SELECT * FROM (SELECT 1',
      'SELECT 1) ; CREATE TABLE zl_probe AS SELECT 42 AS x; SELECT * FROM (SELECT 1', 'CREATE TABLE zl_probe AS SELECT 42 AS x',
    ];
    for (const text of texts) await expect(runQuery(send, text), text).rejects.toBeInstanceOf(Error);
    expect(await events()).toBe(before);
    await expect(db.rows('SELECT * FROM zl_probe')).rejects.toThrow();
  });

  it('keeps the answer, or the error, when switching logging off fails', async () => {
    const failing = (sql: string) => (sql === LOGGING_SQL ? Promise.reject(new Error('stopped')) : send(sql));
    await expect(runQuery(failing, 'SELECT 1 AS a')).resolves.toHaveProperty('rows', [['1']]);
    await expect(runQuery(failing, 'SELECT * FROM evnts')).rejects.toThrow(/^Catalog Error/);
  });

  it('calls only a real refusal a refusal', async () => {
    await expect(runQuery(send, 'DROP TABLE events')).rejects.toBeInstanceOf(SqlRefused);
    await expect(runQuery(send, 'DROP TABLE events')).rejects.toThrow(/^only one SELECT query runs here/);
    await expect(runQuery(send, ' ; ')).rejects.toThrow('the query is empty');
    const typo = await runQuery(send, 'SELECT * FROM evnts').catch((e: unknown) => e as Error);
    expect(typo).toBeInstanceOf(Error);
    expect(typo).not.toBeInstanceOf(SqlRefused);
    expect((typo as Error).message).toMatch(/^Catalog Error/);
    expect((typo as Error).message).not.toMatch(/LINE \d/);
  });

  it('switches logging off through the page even when the run was superseded or its view is gone', async () => {
    const logging = async () => String((await db.rows(LOGGING_SQL))[0].on);
    // The console's scope: it answers until the result arrives, then the view goes and every call is refused.
    let gone = false;
    const scoped = async (sql: string) => {
      if (gone) throw new Superseded();
      const out = await send(sql);
      if (sql.startsWith('SELECT CAST(c0')) {
        gone = true;
        throw new Superseded();
      }
      return out;
    };
    const reset: string[] = [];
    const page = (sql: string) => {
      reset.push(sql);
      return send(sql);
    };
    await expect(runQuery(scoped, "SELECT * FROM enable_logging(storage := 'memory')", page)).rejects.toBeInstanceOf(Superseded);
    expect(reset[0]).toBe(LOGGING_SQL);
    expect(await logging()).toBe('false');
  });

  it('keeps the answer, or the error, when the page refuses the reset', async () => {
    const refusing = () => Promise.reject(new Superseded());
    await expect(runQuery(send, 'SELECT 1 AS a', refusing)).resolves.toHaveProperty('rows', [['1']]);
    await expect(runQuery(send, 'SELECT * FROM evnts', refusing)).rejects.toThrow(/^Catalog Error/);
  });

  it('switches off the logging a query turned on', async () => {
    const logging = async () => String((await db.rows(LOGGING_SQL))[0].on);
    await runQuery(send, "SELECT * FROM enable_logging(storage := 'memory')");
    expect(await logging()).toBe('false');
    await db.rows("SELECT * FROM enable_logging(storage := 'memory')");
    expect(await logging()).toBe('true');
    await runQuery(send, 'SELECT * FROM nothing_here').catch(() => {});
    expect(await logging()).toBe('false');
  });
});

describe('what the console shows', () => {
  it('keeps 64-bit values exact and NULL apart from text', async () => {
    const result = await runQuery(send, 'SELECT 9007199254740993::BIGINT AS big, NULL AS nothing, \'\' AS empty');
    expect(result.columns.map((c) => c.name)).toEqual(['big', 'nothing', 'empty']);
    expect(result.rows).toEqual([['9007199254740993', null, '']]);
    expect(result.more).toBe(false);
  });

  it('keeps two columns of one name, and a trailing comment', async () => {
    const result = await runQuery(send, 'SELECT 1 AS a, 2 AS a -- the same name twice');
    expect(result.rows).toEqual([['1', '2']]);
    expect(result.columns).toHaveLength(2);
  });

  it('says when there are more rows than it shows', async () => {
    const result = await runQuery(send, 'SELECT * FROM range(10001)');
    expect(result.rows).toHaveLength(10_000);
    expect(result.more).toBe(true);
  });

  it('doubles quotes so the text stays one literal', () => {
    expect(resultSql("SELECT 'a' -- x", 1, 5)).toBe("SELECT CAST(c0 AS VARCHAR) AS c0 FROM query('SELECT ''a'' -- x') AS _zl_q(c0) LIMIT 5");
  });

  it('drops the semicolons a console habitually gets', () => {
    expect(trimStatement('  SELECT 1;  ;\n')).toBe('SELECT 1');
  });

  it('lists the package tables and their columns', async () => {
    const tables = new Set((await db.rows(TABLES_SQL)).map((r) => r.t));
    for (const name of ['events', 'rules', 'hits', 'alerts', 'alert_events']) expect(tables.has(name), name).toBe(true);
  });

  it('counts only plain numbers as numeric, and sizes columns to their content', () => {
    for (const type of ['BIGINT', 'DOUBLE', 'DECIMAL(18,3)', 'UHUGEINT']) expect(numericType(type), type).toBe(true);
    for (const type of ['INTEGER[]', 'DOUBLE[]', 'VARCHAR', 'STRUCT(a INTEGER)']) expect(numericType(type), type).toBe(false);
    const columns = [{ name: 'title', type: 'VARCHAR' }, { name: 'n', type: 'BIGINT' }, { name: 'x', type: 'VARCHAR' }];
    expect(columnWidths(columns, [['Remote Thread Creation', '1', 'y'.repeat(200)], [null, '22', 'z']])).toEqual([24, 8, 60]);
  });

  it('keeps a negative number a number in the CSV, and guards a negative string', async () => {
    const result = await runQuery(send, "SELECT -5 AS n, '-5' AS s");
    const mask = result.columns.map((c) => numericType(c.type));
    expect(mask).toEqual([true, false]);
    expect(csvLine(result.rows[0], mask)).toBe("-5,'-5\r\n");
  });
});
