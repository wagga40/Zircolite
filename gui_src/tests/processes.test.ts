import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type Field, Schema } from '../src/engine/schema';
import { ancestorsSql, creationPredicate, processCountSql, processRowsSql } from '../src/processes/processes';
import {
  basename, buildForest, pidText, type Process, type RawProcess, toProcess, visibleRows,
} from '../src/processes/tree';
import { FIELDS, type Fixture, openFixture, TACTICS } from './fixture';

let next = 0;
function proc(fields: Partial<Process>): Process {
  return {
    uid: ++next, t: 0, host: 'H', guid: null, parentGuid: null, pid: null, ppid: null, image: null, parentImage: null,
    commandLine: null, user: null, lvl: null, hits: 0, context: false, parent: null, children: [], ...fields,
  };
}

describe('PIDs', () => {
  it('reads Security 4688 hexadecimal and Sysmon decimal the same way', () => {
    expect(pidText('0x1f4')).toBe('500');
    expect(pidText('500')).toBe('500');
    expect(pidText('0500')).toBe('500');
    expect(pidText(' ')).toBeNull();
    expect(pidText(null)).toBeNull();
  });
});

describe('the forest', () => {
  it('links by guid, then by host, PID and time', () => {
    const root = proc({ guid: '{r}', pid: '4', t: 0 });
    const child = proc({ guid: '{c}', parentGuid: '{r}', pid: '10', t: 5 });
    const byPid = proc({ ppid: '10', pid: '11', t: 6 });
    // Processes point at each other both ways, so compare identities, not structures.
    expect(buildForest([byPid, child, root]).map((p) => p.uid)).toEqual([root.uid]);
    expect(root.children.map((p) => p.uid)).toEqual([child.uid]);
    expect(child.children.map((p) => p.uid)).toEqual([byPid.uid]);
  });

  it('a reused PID links to the latest earlier start', () => {
    const first = proc({ pid: '500', t: 100 });
    const second = proc({ pid: '500', t: 300 });
    const early = proc({ ppid: '500', t: 200 });
    const late = proc({ ppid: '500', t: 400 });
    buildForest([first, second, early, late]);
    expect(early.parent).toBe(first);
    expect(late.parent).toBe(second);
  });

  it('does not link across hosts, or without times', () => {
    const parent = proc({ host: 'A', pid: '7', t: 1 });
    const elsewhere = proc({ host: 'B', ppid: '7', t: 2 });
    const timeless = proc({ host: 'A', ppid: '7', t: null });
    expect(buildForest([parent, elsewhere, timeless])).toHaveLength(3);
  });

  it('trusts a parent guid it cannot find over a PID that happens to match', () => {
    const lookalike = proc({ pid: '9', t: 1 });
    const orphan = proc({ parentGuid: '{gone}', ppid: '9', t: 2 });
    buildForest([lookalike, orphan]);
    expect(orphan.parent).toBeNull();
  });

  it('a guid cycle does not loop', () => {
    const a = proc({ guid: '{a}', parentGuid: '{b}', t: 1 });
    const b = proc({ guid: '{b}', parentGuid: '{a}', t: 2 });
    const roots = buildForest([a, b]);
    expect(roots).toHaveLength(1);
    expect(visibleRows(roots, new Set([a.uid, b.uid]))).toHaveLength(2);
  });

  it('shows children only under an expanded parent, with their place in the set', () => {
    const root = proc({ guid: '{r}', t: 0 });
    const one = proc({ parentGuid: '{r}', t: 1 });
    const two = proc({ parentGuid: '{r}', t: 2 });
    const roots = buildForest([root, one, two]);
    expect(visibleRows(roots, new Set()).map((r) => r.process.uid)).toEqual([root.uid]);
    const rows = visibleRows(roots, new Set([root.uid]));
    expect(rows.map((r) => [r.depth, r.posinset, r.setsize])).toEqual([[0, 1, 1], [1, 1, 2], [1, 2, 2]]);
    expect(rows[0]).toMatchObject({ expandable: true, expanded: true });
  });

  it('names an executable by its last path part, either slash', () => {
    expect(basename('C:\\Windows\\System32\\cmd.exe')).toBe('cmd.exe');
    expect(basename('/usr/bin/bash')).toBe('bash');
    expect(basename(null)).toBe('');
  });
});

const PROCESS_FIELDS: Field[] = ['ProcessGuid', 'ParentProcessGuid', 'ProcessId', 'ParentProcessId', 'NewProcessId',
  'NewProcessName', 'ParentImage', 'ParentProcessName', 'User', 'SubjectUserName']
  .map((name) => ({ name, key: name.toLowerCase(), type: 'VARCHAR', count: 1 }));
const wide = new Schema([...FIELDS, ...PROCESS_FIELDS], TACTICS);
const EXTRA = [
  ...PROCESS_FIELDS.map((f) => `ALTER TABLE events ADD COLUMN "${f.name}" VARCHAR`),
  `UPDATE events SET "ProcessGuid" = '{AAAA}', "ParentProcessGuid" = '{PPPP}', "ProcessId" = '100', "ParentProcessId" = '50' WHERE _zl_uid = 3`,
  `UPDATE events SET "ProcessGuid" = '{BBBB}', "ParentProcessGuid" = '{AAAA}', "ProcessId" = '200', "ParentProcessId" = '100' WHERE _zl_uid = 4294967297`,
  `INSERT INTO events (_zl_uid, _zl_part, _zl_time, "Channel", "EventID", "Computer", "Image", "ProcessGuid", "ParentProcessGuid", "ProcessId", "ParentProcessId")
     VALUES (4294967300, 1, TIMESTAMP '2021-06-03 05:00:00', 'Microsoft-Windows-Sysmon/Operational', 1, 'WS02', 'C:\\Windows\\explorer.exe', '{PPPP}', '{ROOT}', '50', '4')`,
  `UPDATE events SET "NewProcessId" = '0x1f4', "ProcessId" = '0x64', "NewProcessName" = 'C:\\Windows\\System32\\net.exe', "SubjectUserName" = 'àéî' WHERE _zl_uid = 4294967299`,
];

describe('process starts in the package', () => {
  let db: Fixture;
  beforeAll(async () => { db = await openFixture(EXTRA); });
  afterAll(() => db.close());

  it('finds Sysmon 1 and Security 4688, in start order', async () => {
    expect(await db.rows(processCountSql(wide, 'TRUE') as string)).toEqual([{ n: 4 }]);
    const rows = (await db.rows(processRowsSql(wide, 'TRUE') as string)) as unknown as RawProcess[];
    expect(rows.map((r) => r._zl_uid)).toEqual([4294967300, 3, 4294967297, 4294967299]);
    const net = toProcess(rows[3]);
    expect(net).toMatchObject({ pid: '500', ppid: '100', image: 'C:\\Windows\\System32\\net.exe', user: 'àéî', host: 'DC01' });
    const powershell = rows.find((r) => r._zl_uid === 4294967297)!;
    expect([powershell.lvl, powershell.hits]).toEqual([4, 2]);
  });

  it('adds the ancestors of what the filters keep, outside the filters', async () => {
    const where = `"Image" ILIKE '%powershell%'`;
    const kept = (await db.rows(processRowsSql(wide, where) as string)) as unknown as RawProcess[];
    const context = (await db.rows(ancestorsSql(wide, where) as string)) as unknown as RawProcess[];
    expect(kept.map((r) => r._zl_uid)).toEqual([4294967297]);
    expect(context.map((r) => r._zl_uid).sort()).toEqual([3, 4294967300]);
    expect(context.every((r) => r.context)).toBe(true);
    const roots = buildForest([...kept, ...context].map(toProcess));
    expect(roots.map((r) => r.uid)).toEqual([4294967300]);
    expect(roots[0].children[0].children[0].uid).toBe(4294967297);
  });

  it('caps the tree and says so through the count', async () => {
    const rows = await db.rows(processRowsSql(wide, 'TRUE', 2) as string);
    expect(rows).toHaveLength(2);
    expect(await db.rows(processCountSql(wide, 'TRUE') as string)).toEqual([{ n: 4 }]);
  });

  it('cannot find starts without Channel and EventID', () => {
    const bare = new Schema(FIELDS.filter((f) => f.name !== 'Channel'), TACTICS);
    expect(creationPredicate(bare)).toBeNull();
    expect(processRowsSql(bare, 'TRUE')).toBeNull();
  });
});
