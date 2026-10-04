import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Schema } from '../src/engine/schema';
import { defaultColumns, shownColumns, toggleColumn } from '../src/explore/columns';
import { filterFields, percent, topValuesSql } from '../src/explore/sidebar';
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

  it('returns nothing when no event has the field', async () => {
    expect(await db.rows(topValuesSql(field('TargetUserName'), `"Channel" = 'Windows PowerShell'`))).toEqual([]);
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

});
