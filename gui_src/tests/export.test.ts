import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Db } from '../src/engine/db';
import { nameResolver } from '../src/engine/names';
import type { Field } from '../src/engine/schema';
import { csvCell, csvExport, csvLine, eventJson, jsonExport, prepareExport } from '../src/explore/export';
import { idsSql } from '../src/explore/table';
import { type Fixture, openFixture, schema } from './fixture';

let fx: Fixture;
let db: Db;
beforeAll(async () => {
  fx = await openFixture();
  db = { rows: (sql: string) => fx.rows(sql), exec: async (sql: string) => { await fx.rows(sql); } } as unknown as Db;
});
afterAll(() => fx.close());

const manifest = { parts: [{ part: 0, spellings: {} }, { part: 1, spellings: { image: 'image' } }] } as never;
// Blob.text() drops a leading byte order mark, which the export test needs to see.
const text = async (parts: BlobPart[] | null) => new TextDecoder('utf-8', { ignoreBOM: true }).decode(await new Blob(parts ?? []).arrayBuffer());
const field = (name: string): Field => {
  const found = schema.find(name);
  if (!found) throw new Error(`fixture has no ${name}`);
  return found;
};

describe('csv', () => {
  it.each<[string | null, string]>([
    [null, ''], ['a', 'a'], ['a,b', '"a,b"'], ['say "hi"', '"say ""hi"""'], ['two\nlines', '"two\nlines"'],
    ['=1+1', "'=1+1"], ['-enc x', "'-enc x"], ['@x', "'@x"], ['+1', "'+1"],
  ])('writes %j as %j', (value, expected) => {
    expect(csvCell(value)).toBe(expected);
  });

  it('ends lines with CRLF', () => {
    expect(csvLine(['a', null, 'b,c'])).toBe('a,,"b,c"\r\n');
  });

  it('exports the results in order, in batches', async () => {
    await db.exec(idsSql('TRUE', false));
    const count = await prepareExport(db);
    expect(count).toBe(6);
    const seen: number[] = [];
    const out = await text(await csvExport(db, [field('Computer'), field('EventID')], count, (done) => seen.push(done), () => false, 4));
    expect(out).toBe(
      '\uFEFFTime (UTC),Level,Computer,EventID\r\n' +
        '2021-06-03 06:00:00.000,informational,DC01,4624\r\n' +
        '2021-06-03 06:00:30.000,,DC01,4634\r\n' +
        '2021-06-03 06:05:00.000,medium,WS02,1\r\n' +
        '2021-06-03 07:00:00.000,critical,WS02,1\r\n' +
        '2021-06-03 08:00:00.000,,DC01,4688\r\n' +
        ',,ws02,400\r\n',
    );
    expect(seen).toEqual([4, 6]);
  });

  it('keeps exporting its snapshot when the results change', async () => {
    await db.exec(idsSql('TRUE', false));
    const count = await prepareExport(db);
    await db.exec(idsSql('FALSE', false));
    const out = await text(await csvExport(db, [field('EventID')], count, () => {}, () => false));
    expect(out.trim().split('\r\n')).toHaveLength(7);
  });

  it('stops when cancelled', async () => {
    await db.exec(idsSql('TRUE', false));
    expect(await csvExport(db, [], await prepareExport(db), () => {}, () => true)).toBeNull();
  });
});

describe('json', () => {
  it('writes numbers exactly and anything else as a string', () => {
    expect(eventJson([
      { name: 'EventID', type: 'BIGINT', text: '400' },
      { name: 'Big', type: 'BIGINT', text: '9007199254740993' },
      { name: 'Ratio', type: 'DOUBLE', text: 'inf' },
      { name: 'computer', type: 'VARCHAR', text: 'ws02' },
    ])).toBe('{"EventID":400,"Big":9007199254740993,"Ratio":"inf","computer":"ws02"}');
    expect(eventJson([], true)).toBe('{}');
    expect(eventJson([{ name: 'a', type: 'VARCHAR', text: 'b' }], true)).toBe('{\n  "a": "b"\n}');
  });

  it('exports every field under the event’s own spelling, leaving nulls out', async () => {
    await db.exec(idsSql('TRUE', false));
    const count = await prepareExport(db);
    const lines = (await text(await jsonExport(db, schema.fields, manifest, count, () => {}, () => false))).trim().split('\n');
    expect(lines).toHaveLength(6);
    const timeless = JSON.parse(lines[5]);
    expect(Object.keys(timeless)).toEqual(['Channel', 'EventID', 'computer', 'image', 'level']);
    expect(timeless).toEqual({ Channel: 'Windows PowerShell', EventID: 400, computer: 'ws02', image: 'C:\\Tools\\50_off.exe', level: 'error' });
    expect(JSON.parse(lines[0])).toEqual({ Channel: 'Security', EventID: 4624, Computer: 'DC01', TargetUserName: 'bob' });
  });
});

describe('names', () => {
  it('prefers the event’s spelling, then its part’s, then the package’s', () => {
    expect(nameResolver(manifest, 1, '["computer"]')(field('Computer'))).toBe('computer');
    expect(nameResolver(manifest, 1, null)(field('Image'))).toBe('image');
    expect(nameResolver(manifest, 0, null)(field('Image'))).toBe('Image');
  });

  it('refuses a spelling record it cannot read', () => {
    expect(() => nameResolver(manifest, 0, '{oops')).toThrow();
  });
});
