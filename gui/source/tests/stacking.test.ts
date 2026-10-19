import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type Field, Schema } from '../src/engine/schema';
import { compile } from '../src/search/compile';
import { parse } from '../src/search/parse';
import { decode, encode, EMPTY } from '../src/state/hash';
import { STACK_COLUMNS, STACK_ORDER, stackPresets, type StackRow, stackSql, stackTerms } from '../src/stacking/stack';
import { applyLocalCell, localSchema, localWhere, sortClause } from '../src/ui/localFilters';
import { type Fixture, openFixture, schema } from './fixture';

let db: Fixture;
beforeAll(async () => { db = await openFixture(); });
afterAll(() => db.close());

const field = (name: string): Field => {
  const found = schema.find(name);
  if (!found) throw new Error(name);
  return found;
};
const HOST = field('Computer');
const stack = async (fields: Field[], options: { missing?: boolean; filter?: string; order?: string } = {}) =>
  (await db.rows(stackSql(fields, 'TRUE', HOST, options))) as unknown as StackRow[];

describe('the stacking route', () => {
  it('round-trips', () => {
    for (const route of ['stacking', 'logons'] as const) expect(decode(encode({ ...EMPTY, route, q: 'x' }))).toEqual({ ...EMPTY, route, q: 'x' });
  });
});

describe('stacking', () => {
  it('lists each value with its events, hosts, detections and times, rarest first', async () => {
    expect(await stack([field('Image')])).toEqual([
      { v0: 'C:\\Tools\\50_off.exe', events: 1, hosts: 1, detections: 0, first: null, last: null, total: 3 },
      { v0: 'C:\\Windows\\System32\\cmd.exe', events: 1, hosts: 1, detections: 1, first: Date.UTC(2021, 5, 3, 6, 5), last: Date.UTC(2021, 5, 3, 6, 5), total: 3 },
      {
        v0: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', events: 1, hosts: 1, detections: 1,
        first: Date.UTC(2021, 5, 3, 7), last: Date.UTC(2021, 5, 3, 7), total: 3,
      },
    ]);
  });

  it('stacks field pairs, grouping each ignoring case', async () => {
    const rows = await stack([field('Computer'), field('Channel')]);
    expect(rows.map((r) => [r.v0, r.v1, r.events])).toEqual([
      ['ws02', 'Windows PowerShell', 1],
      ['WS02', 'Microsoft-Windows-Sysmon/Operational', 2],
      ['DC01', 'Security', 3],
    ]);
  });

  it('leaves events without a stacked field out, unless asked', async () => {
    expect((await stack([field('Image')])).some((r) => r.v0 === null)).toBe(false);
    const all = await stack([field('Image')], { missing: true });
    expect(all.find((r) => r.v0 === null)?.events).toBe(3);
    expect(all.reduce((sum, r) => sum + r.events, 0)).toBe(6);
  });

  it('pivots each row to exactly its events', async () => {
    for (const fields of [[field('Image')], [field('Computer'), field('Channel')], [field('TargetUserName'), field('EventID')]]) {
      for (const row of await stack(fields, { missing: true })) {
        const listed = await db.uids(compile(parse(stackTerms(fields, row)), schema));
        expect(listed.length, `${fields.map((f) => f.name)} ${JSON.stringify(row)}`).toBe(row.events);
      }
    }
  });

  it('filters and sorts by its own columns', async () => {
    const columns = localSchema(STACK_COLUMNS(2));
    const result = applyLocalCell('', STACK_COLUMNS(2).find((c) => c.name === 'events')!, '>=2', columns);
    if ('problem' in result) throw new Error(result.problem);
    const rows = await stack([field('Computer'), field('Channel')], {
      filter: localWhere(result.query, columns), order: sortClause({ column: 'events', desc: true }, STACK_ORDER),
    });
    expect(rows.map((r) => [r.v0, r.events, r.total])).toEqual([['DC01', 3, 2], ['WS02', 2, 2]]);
  });

  it('counts no hosts without a host field', async () => {
    const rows = (await db.rows(stackSql([field('Image')], 'TRUE', null))) as unknown as StackRow[];
    expect(rows.every((r) => r.hosts === null)).toBe(true);
  });

  it('offers only the presets whose fields the package has', () => {
    const names = (s: Schema) => stackPresets(s).map((preset) => preset.map((f) => f.name).join(' + '));
    expect(names(schema)).toEqual(['Image', 'CommandLine', 'Image + TargetUserName']);
    expect(names(new Schema([], []))).toEqual([]);
  });
});
