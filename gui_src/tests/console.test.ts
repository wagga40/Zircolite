import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { resultSql, runQuery, SqlRefused, TABLES_SQL, trimStatement } from '../src/sql/console';
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
    for (const text of texts) await expect(runQuery(send, text), text).rejects.toBeInstanceOf(SqlRefused);
    expect(await events()).toBe(before);
    await expect(db.rows('SELECT * FROM zl_probe')).rejects.toThrow();
  });

  it('says why a query did not run', async () => {
    await expect(runQuery(send, 'DROP TABLE events')).rejects.toThrow(/^only one SELECT query runs here .*DuckDB says: /);
    await expect(runQuery(send, ' ; ')).rejects.toThrow('the query is empty');
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
});
