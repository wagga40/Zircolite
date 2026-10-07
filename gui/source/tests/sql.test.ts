import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { asciiLower, ident, likeEscape, str } from '../src/engine/sql';
import { Schema } from '../src/engine/schema';
import { type Fixture, FIELDS, openFixture } from './fixture';

let db: Fixture;
beforeAll(async () => { db = await openFixture(); });
afterAll(() => db.close());

describe('sql helpers', () => {
  it.each(['plain', "it's", 'back\\slash', 'dou"ble', "x' OR 1=1 --", 'Ä ä 😀'])('round-trips %s', async (text) => {
    const [row] = await db.rows(`SELECT ${str(text)} AS ${ident(text)}`);
    expect(row[text]).toBe(text);
  });

  it('escapes LIKE metacharacters so a value matches only itself', async () => {
    const pattern = str(likeEscape('50_off'));
    expect(await db.rows(`SELECT '50x0off' LIKE ${pattern} ESCAPE '\\' AS a, '50_off' LIKE ${pattern} ESCAPE '\\' AS b`))
      .toEqual([{ a: false, b: true }]);
  });

  it('folds ASCII letters only, as SQLite and DuckDB do', () => {
    expect(asciiLower('ProcessID')).toBe('processid');
    expect(asciiLower('Ä')).toBe('Ä');
  });

  it('builds the event levels from the highest hit', async () => {
    expect(await db.rows('SELECT _zl_uid, _zl_lvl FROM event_levels ORDER BY _zl_uid')).toEqual([
      { _zl_uid: 1, _zl_lvl: 0 }, { _zl_uid: 3, _zl_lvl: 2 }, { _zl_uid: 4294967297, _zl_lvl: 4 },
    ]);
  });
});

describe('Schema', () => {
  const schema = new Schema(FIELDS);

  it('finds fields ignoring ASCII case', () => {
    expect(schema.find('commandline')?.name).toBe('CommandLine');
    expect(schema.find('nope')).toBeUndefined();
  });

  it('suggests the closest field names', () => {
    expect(schema.suggest('Compter')).toContain('Computer');
    expect(schema.suggest('CommandLin')[0]).toBe('CommandLine');
    expect(schema.suggest('zzzzzzzz')).toEqual([]);
  });

  it('carries the manifest\'s tactic list', () => {
    const manifest = { columns: [{ name: 'A', key: 'a', type: 'VARCHAR', count: 1 }], tactics: ['execution', 'impact'] };
    expect(Schema.fromManifest(manifest as never).tactics).toEqual(['execution', 'impact']);
  });
});
