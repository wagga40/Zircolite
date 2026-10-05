import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type Field, Schema } from '../src/engine/schema';
import { ENTITY_KINDS, entitiesSql, entityFields, entityTerm, type EntityRow } from '../src/entities/entities';
import { compile } from '../src/search/compile';
import { parse } from '../src/search/parse';
import { FIELDS, type Fixture, openFixture, schema, TACTICS } from './fixture';

const kind = (name: string) => ENTITY_KINDS.find((k) => k.kind === name)!;
// Event 4294967297 names cmd.exe as its parent, in lower case; event 3 runs it.
const PARENT: Field = { name: 'ParentImage', key: 'parentimage', type: 'VARCHAR', count: 1 };
const wide = new Schema([...FIELDS, PARENT], TACTICS);
const EXTRA = [
  'ALTER TABLE events ADD COLUMN "ParentImage" VARCHAR',
  "UPDATE events SET \"ParentImage\" = 'c:\\windows\\system32\\cmd.exe' WHERE _zl_uid = 4294967297",
];

let db: Fixture;
beforeAll(async () => { db = await openFixture(EXTRA); });
afterAll(() => db.close());

const rows = async (fields: Field[], filter = '', order: 'events' | 'first' = 'events') =>
  (await db.rows(entitiesSql(fields, 'TRUE', filter, order))) as unknown as EntityRow[];

describe('entity fields', () => {
  it('uses the text fields of a kind that the package has', () => {
    expect(entityFields(kind('hosts'), schema).map((f) => f.name)).toEqual(['Computer']);
    expect(entityFields(kind('processes'), wide).map((f) => f.name)).toEqual(['Image', 'ParentImage']);
    expect(entityFields(kind('ips'), schema)).toEqual([]);
  });
});

describe('entities', () => {
  it('group spellings of a value, count events once, and date them', async () => {
    expect(await rows(entityFields(kind('hosts'), schema))).toEqual([
      { v: 'DC01', events: 3, detections: 1, first: Date.UTC(2021, 5, 3, 6, 0, 0), last: Date.UTC(2021, 5, 3, 8, 0, 0), total: 2 },
      { v: 'WS02', events: 3, detections: 2, first: Date.UTC(2021, 5, 3, 6, 5, 0), last: Date.UTC(2021, 5, 3, 7, 0, 0), total: 2 },
    ]);
  });

  it('an entity\'s count is exactly what its term lists', async () => {
    for (const fields of [entityFields(kind('hosts'), schema), entityFields(kind('users'), schema), entityFields(kind('processes'), wide)]) {
      for (const row of await rows(fields)) {
        const listed = await db.uids(compile(parse(entityTerm(fields, row.v)), wide));
        expect(listed.length, `${fields.map((f) => f.name)} ${row.v}`).toBe(row.events);
      }
    }
  });

  it('counts an event once when two of its fields hold the value', async () => {
    const cmd = (await rows(entityFields(kind('processes'), wide))).find((r) => r.v.toLowerCase().endsWith('cmd.exe'));
    expect(cmd?.events).toBe(2);
    expect(entityTerm(entityFields(kind('processes'), wide), cmd!.v)).toMatch(/^\(Image:".*" OR ParentImage:".*"\)$/);
  });

  it('filters by a part of the value, LIKE characters included literally', async () => {
    expect((await rows(entityFields(kind('hosts'), schema), 'ws')).map((r) => r.v)).toEqual(['WS02']);
    expect(await rows(entityFields(kind('hosts'), schema), '%')).toEqual([]);
  });

  it('sorts by first seen', async () => {
    expect((await rows(entityFields(kind('hosts'), schema), '', 'first')).map((r) => r.v)).toEqual(['DC01', 'WS02']);
  });
});
