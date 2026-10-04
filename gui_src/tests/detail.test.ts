import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { compile } from '../src/search/compile';
import { appendRaw, quoteValue } from '../src/search/edit';
import { parse } from '../src/search/parse';
import type { Field } from '../src/engine/schema';
import {
  type Entry, familyFields, groupEntries, headSql, hostEntry, nearbyRange, rulesSql, valuesSql,
} from '../src/explore/detail';
import { type Fixture, openFixture, schema } from './fixture';

let db: Fixture;
beforeAll(async () => { db = await openFixture(); });
afterAll(() => db.close());

const manifest = {
  families: [{ channel: 'Windows PowerShell', eventid: '400', columns: ['Channel', 'Computer', 'EventID', 'Image', 'level'] }],
  parts: [{ part: 0, spellings: {} }, { part: 1, spellings: { image: 'image' } }],
} as never;

const field = (name: string): Field => ({ name, key: name.toLowerCase(), type: 'VARCHAR', count: 1 });
const entry = (name: string, value = 'v'): Entry => ({ field: field(name), name, value });

describe('reading one event', () => {
  it('reads its head', async () => {
    expect(await db.rows(headSql(schema, 4294967298))).toEqual([
      { _zl_part: 1, _zl_spelling: '["computer"]', _zl_t: null, _zl_channel: 'Windows PowerShell', _zl_eventid: '400' },
    ]);
  });

  it('projects onto its family’s columns, or every column when the family is unknown', () => {
    expect(familyFields(manifest, schema, 'Windows PowerShell', '400').map((f) => f.name)).toEqual(['Channel', 'Computer', 'EventID', 'Image', 'level']);
    expect(familyFields(manifest, schema, 'Security', '9999')).toEqual(schema.fields);
  });

  it('reads the values as text', async () => {
    const fields = familyFields(manifest, schema, 'Windows PowerShell', '400');
    expect(await db.rows(valuesSql(fields, 4294967298))).toEqual([
      { _zl_v0: 'Windows PowerShell', _zl_v1: 'ws02', _zl_v2: '400', _zl_v3: 'C:\\Tools\\50_off.exe', _zl_v4: 'error' },
    ]);
  });

  it('lists the rules that matched it, most severe first', async () => {
    expect((await db.rows(rulesSql(4294967297))).map((r) => [r.title, r.level, r.techniques])).toEqual([
      ['Critical thing', 'critical', ['T1053']],
      ['Encoded PowerShell - Sysmon', 'high', ['T1059.001']],
    ]);
    expect(await db.rows(rulesSql(2))).toEqual([]);
  });

  it('refuses anything but an event id', () => {
    expect(() => headSql(schema, -1)).toThrow();
    expect(() => rulesSql(1.5)).toThrow();
    expect(() => valuesSql([], Number.NaN)).toThrow();
  });
});

describe('presenting it', () => {
  it('groups fields the way analysts scan them', () => {
    const names = ['Channel', 'Computer', 'EventID', 'Image', 'CommandLine', 'TargetUserName', 'level', `it's "odd"`,
      'DestinationIp', 'TargetFilename', 'TargetObject', 'ParentUser', 'SourceImage', 'ParentProcessGuid', 'ProcessId', 'TargetSid'];
    expect(groupEntries(names.map((name) => entry(name))).map((g) => [g.name, g.entries.map((e) => e.name)])).toEqual([
      ['System', ['Channel', 'Computer', 'EventID', 'level']],
      ['User', ['ParentUser', 'TargetSid', 'TargetUserName']],
      ['Process', ['CommandLine', 'Image', 'ParentProcessGuid', 'ProcessId', 'SourceImage']],
      ['Network', ['DestinationIp']],
      ['File and registry', ['TargetFilename', 'TargetObject']],
      ['Other', [`it's "odd"`]],
    ]);
  });

  it('finds the host to pivot on, and the minutes around the event', () => {
    expect(hostEntry([entry('Image'), entry('Computer', 'DC01')])?.value).toBe('DC01');
    expect(hostEntry([entry('Image')])).toBeNull();
    expect(hostEntry([entry('Computer', '')])).toBeNull();
    expect(nearbyRange(1_000_000)).toEqual([700_000, 1_300_000]);
  });
});

describe('filtering by a rule', () => {
  it('keeps quotes and backslashes in a title literal', () => {
    const title = 'Odd "quoted" \\ rule';
    const sql = compile(parse(appendRaw('', `rule:${quoteValue(title)}`)), schema);
    // The backslash is doubled for LIKE's ESCAPE '\\', so the title still matches itself literally.
    expect(sql).toContain(`ILIKE 'Odd "quoted" \\\\ rule' ESCAPE`);
    expect(sql).toMatch(/ILIKE/);
  });
});
