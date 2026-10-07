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

describe('awkward values', () => {
  const HOSTS = ['a*b', 'q\\x"y', '50%_off', '', 'ÉCOLE', 'école'];
  let awkward: Fixture;
  beforeAll(async () => {
    const values = HOSTS.map((h, i) => `(${100 + i}, 0, TIMESTAMP '2021-07-01 00:00:0${i}', '${h.replaceAll("'", "''")}')`).join(', ');
    awkward = await openFixture([`INSERT INTO events (_zl_uid, _zl_part, _zl_time, "Computer") VALUES ${values}, (200, 0, NULL, 'ÉCOLE')`]);
  });
  afterAll(() => awkward.close());

  const hostRows = async (filter = '') =>
    (await awkward.rows(entitiesSql(entityFields(kind('hosts'), schema), 'TRUE', filter, 'events'))) as unknown as EntityRow[];

  it('each count is exactly what its term lists', async () => {
    const fields = entityFields(kind('hosts'), schema);
    const found = await hostRows();
    for (const row of found) {
      const listed = await awkward.uids(compile(parse(entityTerm(fields, row.v)), schema));
      expect(listed.length, JSON.stringify(row.v)).toBe(row.events);
    }
    // ÉCOLE and école are one value with two events beside the spelling-only ones.
    expect(found.filter((r) => r.v.toLowerCase() === 'école')).toHaveLength(1);
  });

  it('a percent filter matches only values holding a percent sign', async () => {
    expect((await hostRows('%')).map((r) => r.v)).toEqual(['50%_off']);
  });
});
