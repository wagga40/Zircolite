import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Schema } from '../src/engine/schema';
import { defaultColumns, familyColumns, familyLabel, familyOf, familyProbeSql, moveColumn, placeColumn, shownColumns, toggleColumn } from '../src/explore/columns';
import { columnValuesSql, filterFields, percent, topValuesSql, valueLabel } from '../src/explore/sidebar';
import { compile } from '../src/search/compile';
import { appendTerm } from '../src/search/edit';
import { parse } from '../src/search/parse';
import { type Fixture, openFixture, schema } from './fixture';

let db: Fixture;
beforeAll(async () => { db = await openFixture(); });
afterAll(() => db.close());

const field = (name: string) => {
  const found = schema.find(name);
  if (!found) throw new Error(`fixture has no ${name}`);
  return found;
};

describe('top values', () => {
  it('counts values under the filter ignoring case, as filtering by them does', async () => {
    expect(await db.rows(topValuesSql(field('Computer'), 'TRUE'))).toEqual([
      { v: 'DC01', n: 3, spellings: 1, total: 6 }, { v: 'WS02', n: 3, spellings: 2, total: 6 },
    ]);
    expect(await db.uids(compile(parse(appendTerm('', 'Computer', 'WS02', false)), schema))).toHaveLength(3);
  });

  it('reads numeric fields as text and applies the filter', async () => {
    expect(await db.rows(topValuesSql(field('EventID'), `"Channel" = 'Security'`))).toEqual([
      { v: '4624', n: 1, spellings: 1, total: 3 }, { v: '4634', n: 1, spellings: 1, total: 3 }, { v: '4688', n: 1, spellings: 1, total: 3 },
    ]);
  });

  it('handles awkward field names', async () => {
    expect(await db.rows(topValuesSql(field(`it's "odd"`), 'TRUE'))).toEqual([{ v: 'x', n: 1, spellings: 1, total: 1 }]);
  });

  it('composes with a compiled search', async () => {
    const where = compile(parse('-EventID:4688'), schema);
    expect(await db.rows(topValuesSql(field('Computer'), where))).toEqual([
      { v: 'WS02', n: 3, spellings: 2, total: 5 }, { v: 'DC01', n: 2, spellings: 1, total: 5 },
    ]);
    expect(await db.rows(topValuesSql(field('Computer'), 'FALSE'))).toEqual([]);
  });

  it('keeps empty text as a value of its own', async () => {
    const own = await openFixture();
    try {
      await own.rows(`INSERT INTO events (_zl_uid, _zl_part, "Image") VALUES (99, 0, '')`);
      const rows = await own.rows(topValuesSql(field('Image'), 'TRUE'));
      expect(rows).toContainEqual({ v: '', n: 1, spellings: 1, total: 4 });
    } finally {
      own.close();
    }
  });

  it('names empty text the way the list shows it', () => {
    expect([valueLabel(''), valueLabel('DC01')]).toEqual(['empty text', 'DC01']);
  });

  it('returns nothing when no event has the field', async () => {
    expect(await db.rows(topValuesSql(field('TargetUserName'), `"Channel" = 'Windows PowerShell'`))).toEqual([]);
  });
});

describe('column values', () => {
  it('lists every value ignoring case, with the count of distinct values and of results', async () => {
    expect(await db.rows(columnValuesSql(field('Computer'), 'TRUE'))).toEqual([
      { v: 'DC01', n: 3, spellings: 1, distinct: 2, total: 6 }, { v: 'WS02', n: 3, spellings: 2, distinct: 2, total: 6 },
    ]);
  });

  it('puts the rarest first on request', async () => {
    expect((await db.rows(columnValuesSql(field('EventID'), 'TRUE', { order: 'rare' }))).map((r) => [r.v, r.n])).toEqual([
      ['400', 1], ['4624', 1], ['4634', 1], ['4688', 1], ['1', 2],
    ]);
  });

  it('finds values containing a text, in any case, and counts only those', async () => {
    expect(await db.rows(columnValuesSql(field('Image'), 'TRUE', { search: 'SYSTEM32' }))).toEqual([
      { v: 'C:\\Windows\\System32\\cmd.exe', n: 1, spellings: 1, distinct: 2, total: 2 },
      { v: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', n: 1, spellings: 1, distinct: 2, total: 2 },
    ]);
    expect(await db.rows(columnValuesSql(field('Image'), 'TRUE', { search: "50_o" }))).toHaveLength(1);
    expect(await db.rows(columnValuesSql(field('Image'), 'TRUE', { search: "5%o" }))).toEqual([]);
  });

  it('applies the filter and the limit', async () => {
    expect(await db.rows(columnValuesSql(field('Computer'), `"Channel" = 'Security'`, { limit: 1 }))).toEqual([
      { v: 'DC01', n: 3, spellings: 1, distinct: 1, total: 3 },
    ]);
  });
});

describe('field list', () => {
  it('formats coverage without overstating it', () => {
    expect([percent(0, 10), percent(1, 1000), percent(370, 1000), percent(999, 1000), percent(1000, 1000), percent(5, 0)])
      .toEqual(['0%', '<1%', '37%', '>99%', '100%', '0%']);
  });

  it('puts shown columns first, then the most common fields', () => {
    expect(filterFields(schema.fields, '', ['Image', 'Channel']).map((f) => f.name)).toEqual([
      'Image', 'Channel', 'Computer', 'EventID', 'CommandLine', 'TargetUserName', `it's "odd"`, 'level',
    ]);
  });

  it('filters names ignoring case', () => {
    expect(filterFields(schema.fields, 'COMM', []).map((f) => f.name)).toEqual(['CommandLine']);
  });
});

describe('columns', () => {
  it('prefers the fields that identify an event', () => {
    expect(defaultColumns(schema)).toEqual(['Channel', 'EventID', 'Computer', 'TargetUserName', 'Image', 'CommandLine']);
  });

  it('falls back to the most common fields', () => {
    const other = new Schema([
      { name: 'a', key: 'a', type: 'VARCHAR', count: 1 },
      { name: 'b', key: 'b', type: 'VARCHAR', count: 9 },
      { name: 'Computer', key: 'computer', type: 'VARCHAR', count: 2 },
    ]);
    expect(defaultColumns(other)).toEqual(['Computer', 'b', 'a']);
  });

  it('keeps the user’s choice, drops unknown names, and allows none', () => {
    expect(shownColumns(['computer', 'gone', 'Computer'], schema).map((f) => f.name)).toEqual(['Computer']);
    expect(shownColumns(null, schema).map((f) => f.name)).toEqual(defaultColumns(schema));
    expect(shownColumns([], schema)).toEqual([]);
  });

  it('toggles a column by name, ignoring case', () => {
    expect(toggleColumn(['Channel', 'Computer'], 'computer')).toEqual(['Channel']);
    expect(toggleColumn(['Channel'], 'Image')).toEqual(['Channel', 'Image']);
  });

  it('moves a column one place, ignoring case and staying inside the list', () => {
    expect(moveColumn(['A', 'B', 'C'], 'b', -1)).toEqual(['B', 'A', 'C']);
    expect(moveColumn(['A', 'B', 'C'], 'B', 1)).toEqual(['A', 'C', 'B']);
    expect(moveColumn(['A', 'B', 'C'], 'A', -1)).toEqual(['A', 'B', 'C']);
    expect(moveColumn(['A', 'B', 'C'], 'C', 1)).toEqual(['A', 'B', 'C']);
    expect(moveColumn(['A', 'B'], 'Z', 1)).toEqual(['A', 'B']);
  });

  it('places a column at an index, as a drag drops it', () => {
    expect(placeColumn(['A', 'B', 'C', 'D'], 'A', 2)).toEqual(['B', 'A', 'C', 'D']);
    expect(placeColumn(['A', 'B', 'C', 'D'], 'D', 0)).toEqual(['D', 'A', 'B', 'C']);
    expect(placeColumn(['A', 'B', 'C', 'D'], 'B', 4)).toEqual(['A', 'C', 'D', 'B']);
    expect(placeColumn(['A', 'B', 'C', 'D'], 'B', 1)).toEqual(['A', 'B', 'C', 'D']);
    expect(placeColumn(['A', 'B', 'C', 'D'], 'B', 2)).toEqual(['A', 'B', 'C', 'D']);
  });
});

describe('event family columns', () => {
  const SYSMON = 'Microsoft-Windows-Sysmon/Operational';
  const families = [
    { channel: 'Security', eventid: '4624', columns: ['Channel', 'EventID', 'Computer', 'TargetUserName'] },
    { channel: 'Security', eventid: '4688', columns: ['Channel', 'EventID', 'Computer', 'TargetUserName'] },
    { channel: SYSMON, eventid: '1', columns: ['Channel', 'EventID', 'Computer', 'level', 'CommandLine', 'Image', `it's "odd"`] },
    { channel: 'Windows PowerShell', eventid: '1', columns: ['Channel', 'EventID', 'Computer', 'Image'] },
  ];

  it.each<[string, string | null]>([
    ['EventID:4624', 'Security 4624'],
    ['x eventid:"4688" y', 'Security 4688'],
    ['EventID:1', null],
    [`EventID:1 Channel:"${SYSMON}"`, `${SYSMON} 1`],
    ['EventID:1 channel:"windows powershell"', 'Windows PowerShell 1'],
    ['-EventID:4624', null],
    ['EventID:46*', null],
    ['EventID:4624 OR x', null],
    ['EventID:4624 EventID:4688', null],
    ['EventID:9999', null],
    ['Image:"open', null],
  ])('reads %j as %j', (query, expected) => {
    const family = familyOf(query, families);
    expect(family ? `${family.channel} ${family.eventid}` : null).toBe(expected);
  });

  it('offers the family\'s telling columns, host first, without the columns every event has', () => {
    expect(familyColumns(families[2], schema).map((f) => f.name)).toEqual(['Computer', 'Image', 'CommandLine', `it's "odd"`]);
    expect(familyColumns(families[0], schema).map((f) => f.name)).toEqual(['Computer', 'TargetUserName']);
  });

  it('names a family briefly', () => {
    expect(familyLabel({ channel: SYSMON, eventid: '1' })).toBe('Sysmon/Operational 1');
    expect(familyLabel({ channel: null, eventid: '7' })).toBe('event 7');
  });

  it('asks the result list which families it holds', async () => {
    await db.rows(`CREATE OR REPLACE TEMP TABLE view_ids AS SELECT row_number() OVER () AS _zl_pos, _zl_uid FROM events WHERE "Computer" = 'DC01'`);
    expect(await db.rows(familyProbeSql(schema) as string)).toHaveLength(2);
    await db.rows(`CREATE OR REPLACE TEMP TABLE view_ids AS SELECT row_number() OVER () AS _zl_pos, _zl_uid FROM events WHERE "EventID" = 4624`);
    expect(await db.rows(familyProbeSql(schema) as string)).toEqual([{ c: 'Security', i: '4624' }]);
    expect(familyProbeSql(new Schema([], []))).toBeNull();
  });
});
