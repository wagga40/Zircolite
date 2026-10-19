import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type Field, Schema } from '../src/engine/schema';
import { ACTIVITY, type Activity, activitySql, activitySummary, activityTerms } from '../src/processes/activity';
import { processRowsSql } from '../src/processes/processes';
import { type RawProcess, toProcess } from '../src/processes/tree';
import { compile } from '../src/search/compile';
import { parse } from '../src/search/parse';
import { FIELDS, type Fixture, openFixture, TACTICS } from './fixture';

const GUID: Field = { name: 'ProcessGuid', key: 'processguid', type: 'VARCHAR', count: 8 };
const schema = new Schema([...FIELDS, GUID], TACTICS);
const SYSMON = 'Microsoft-Windows-Sysmon/Operational';

let db: Fixture;
beforeAll(async () => {
  const event = (uid: number, channel: string, id: number, guid: string) =>
    `(${uid}, 0, TIMESTAMP '2021-06-03 06:10:00', NULL, '${channel}', ${id}, 'WS02', NULL, NULL, NULL, NULL, NULL, '${guid}')`;
  db = await openFixture([
    'ALTER TABLE events ADD COLUMN "ProcessGuid" VARCHAR',
    "UPDATE events SET \"ProcessGuid\" = '{AAAA-1}' WHERE _zl_uid = 3",
    `INSERT INTO events VALUES ${[
      event(10, SYSMON, 3, '{aaaa-1}'), event(11, SYSMON, 3, '{AAAA-1}'), event(12, SYSMON, 22, '{AAAA-1}'), event(13, SYSMON, 11, '{AAAA-1}'),
      event(14, SYSMON, 13, '{AAAA-1}'), event(15, SYSMON, 12, '{AAAA-1}'), event(16, SYSMON, 3, '{BBBB-2}'), event(17, 'Security', 3, '{AAAA-1}'),
      event(18, 'Linux-Sysmon/Operational', 11, '{AAAA-1}'),
      // A start whose guid carries a trailing space, as do the events it made.
      event(20, SYSMON, 1, '{CCCC-3} '), event(21, SYSMON, 3, '{CCCC-3} '), event(22, SYSMON, 3, '{cccc-3} '),
    ].join(', ')}`,
  ]);
});
afterAll(() => db.close());

describe('a process\'s activity', () => {
  it('counts its network, DNS, file and registry events by its ProcessGuid, in any letter case', async () => {
    expect(await db.rows(activitySql(schema, '{AAAA-1}') as string)).toEqual([{ network: 2, dns: 1, files: 2, registry: 2 }]);
  });

  it('opens exactly the events each count counts', async () => {
    const [counts] = (await db.rows(activitySql(schema, '{aaaa-1}') as string)) as unknown as Activity[];
    for (const { key } of ACTIVITY) {
      const listed = await db.uids(compile(parse(activityTerms(schema, '{aaaa-1}', key) as string), schema));
      expect(listed.length, key).toBe(counts[key]);
    }
  });

  it('comes with each process start of the tree', async () => {
    const rows = await db.rows(processRowsSql(schema, 'TRUE') as string);
    const cmd = rows.find((row) => row._zl_uid === 3);
    expect(cmd).toMatchObject({ network: 2, dns: 1, files: 2, registry: 2 });
  });

  it('opens from the tree exactly the events the tree counts, whatever spaces the guid carries', async () => {
    const rows = (await db.rows(processRowsSql(schema, 'TRUE') as string)) as unknown as RawProcess[];
    const padded = toProcess(rows.find((row) => row._zl_uid === 20) as RawProcess);
    expect(padded.activity).toMatchObject({ network: 2 });
    for (const { key } of ACTIVITY) {
      const listed = await db.uids(compile(parse(activityTerms(schema, padded.rawGuid as string, key) as string), schema));
      expect(listed.length, key).toBe(padded.activity?.[key]);
    }
  });

  it('is not asked of a package without ProcessGuid', () => {
    const plain = new Schema(FIELDS, TACTICS);
    expect(activitySql(plain, '{x}')).toBeNull();
    expect(activityTerms(plain, '{x}', 'network')).toBeNull();
  });
});

describe('the activity column', () => {
  it('names the kinds a process has, briefly', () => {
    expect(activitySummary({ network: 3, dns: 0, files: 12, registry: 1 })).toBe('3 net · 12 file · 1 reg');
    expect(activitySummary({ network: 0, dns: 0, files: 0, registry: 0 })).toBe('');
    expect(activitySummary(null)).toBe('');
  });
});
