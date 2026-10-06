import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type Field, Schema } from '../src/engine/schema';
import { ancestorsSql, creationPredicate, keepAncestors, PROCESS_LIMIT, processCountSql, processRowsSql } from '../src/processes/processes';
import {
  basename, buildForest, cutRoots, pidText, type Process, type RawProcess, toProcess, visibleAncestor, visibleRows,
} from '../src/processes/tree';
import { FIELDS, type Fixture, openFixture, TACTICS } from './fixture';

let next = 0;
function proc(fields: Partial<Process>): Process {
  return {
    uid: ++next, t: 0, host: 'H', guid: null, parentUid: null, pid: null, ppid: null, image: null, parentImage: null,
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

function raw(fields: Partial<RawProcess>): RawProcess {
  return {
    _zl_uid: 1, _zl_t: 0, sysmon: false, host: 'H', guid: null, pid: null, ppid: null, newpid: null, image: null, newimage: null,
    pimage: null, pname: null, cmd: null, user: null, subject: null, target: null, lvl: null, hits: 0, _zl_parent: null, context: false,
    ...fields,
  };
}

describe('users', () => {
  it('names the account a Security 4688 process runs as, not the one that started it', () => {
    expect(toProcess(raw({ subject: 'admin', target: 'bob' })).user).toBe('bob');
    // 4688 writes - when it names no account for the new process.
    expect(toProcess(raw({ subject: 'admin', target: ' - ' })).user).toBe('admin');
    expect(toProcess(raw({ subject: 'admin', target: null })).user).toBe('admin');
    expect(toProcess(raw({ sysmon: true, user: 'CORP\\eve', subject: 'x', target: 'y' })).user).toBe('CORP\\eve');
  });
});

describe('the forest', () => {
  it('counts the roots whose resolved parent the tree does not reach, not those cut from a cycle', () => {
    const shownParent = proc({ t: 0 });
    const child = proc({ parentUid: shownParent.uid, t: 1 });
    const stopped = proc({ parentUid: 424_242, t: 2 });
    const a = proc({ t: 3 });
    const b = proc({ parentUid: a.uid, t: 4 });
    a.parentUid = b.uid;
    const nothing = proc({ parentUid: null, t: 5 });
    const all = [shownParent, child, stopped, a, b, nothing];
    const roots = buildForest(all);
    expect(cutRoots(roots, new Set(all.map((p) => p.uid)))).toBe(1);
  });

  it('links each start under the parent SQL resolved for it, in start order', () => {
    const root = proc({ t: 0 });
    const late = proc({ parentUid: root.uid, t: 9 });
    const early = proc({ parentUid: root.uid, t: 5 });
    const grandchild = proc({ parentUid: early.uid, t: 6 });
    // Processes point at each other both ways, so compare identities, not structures.
    expect(buildForest([grandchild, late, early, root]).map((p) => p.uid)).toEqual([root.uid]);
    expect(root.children.map((p) => p.uid)).toEqual([early.uid, late.uid]);
    expect(early.children.map((p) => p.uid)).toEqual([grandchild.uid]);
  });

  it('makes a start whose parent is not among the rows a root', () => {
    const orphan = proc({ parentUid: 999_999, t: 1 });
    const unknown = proc({ parentUid: null, t: 2 });
    expect(buildForest([orphan, unknown]).map((p) => p.uid)).toEqual([orphan.uid, unknown.uid]);
  });

  it('a cycle in the links does not loop', () => {
    const a = proc({ t: 1 });
    const b = proc({ parentUid: a.uid, t: 2 });
    a.parentUid = b.uid;
    const roots = buildForest([a, b]);
    expect(roots).toHaveLength(1);
    expect(visibleRows(roots, new Set([a.uid, b.uid]))).toHaveLength(2);
  });

  it('shows children only under an expanded parent, with their place in the set', () => {
    const root = proc({ t: 0 });
    const one = proc({ parentUid: root.uid, t: 1 });
    const two = proc({ parentUid: root.uid, t: 2 });
    const roots = buildForest([root, one, two]);
    expect(visibleRows(roots, new Set()).map((r) => r.process.uid)).toEqual([root.uid]);
    const rows = visibleRows(roots, new Set([root.uid]));
    expect(rows.map((r) => [r.depth, r.posinset, r.setsize])).toEqual([[0, 1, 1], [1, 1, 2], [1, 2, 2]]);
    expect(rows[0]).toMatchObject({ expandable: true, expanded: true });
  });

  it('links a chain thousands of starts deep without a walk up it for each', () => {
    const chain: Process[] = [];
    for (let i = 0; i < 20_000; i++) chain.push(proc({ parentUid: i ? chain[i - 1].uid : null, t: i }));
    const began = performance.now();
    const roots = buildForest([...chain].reverse());
    expect(performance.now() - began).toBeLessThan(200);
    expect(roots).toEqual([chain[0]]);
    expect(chain[19_999].parent).toBe(chain[19_998]);
  });

  it('moves an active row hidden by a collapse to its highest closed ancestor', () => {
    const root = proc({ t: 0 });
    const mid = proc({ parentUid: root.uid, t: 1 });
    const leaf = proc({ parentUid: mid.uid, t: 2 });
    buildForest([root, mid, leaf]);
    expect(visibleAncestor(leaf, new Set([root.uid, mid.uid]))).toBe(leaf);
    expect(visibleAncestor(leaf, new Set([root.uid]))).toBe(mid);
    expect(visibleAncestor(leaf, new Set())).toBe(root);
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
  // The account that started net.exe is SYSTEM; TargetUserName, set by the base fixture, is the one it runs as.
  `UPDATE events SET "NewProcessId" = '0x1f4', "ProcessId" = '0x64', "NewProcessName" = 'C:\\Windows\\System32\\net.exe', "SubjectUserName" = 'SYSTEM' WHERE _zl_uid = 4294967299`,
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
    // Nearest first: the shell that started powershell, then the explorer that started the shell.
    expect(context.map((r) => r._zl_uid)).toEqual([3, 4294967300]);
    expect(context.every((r) => r.context)).toBe(true);
    expect([kept[0]._zl_parent, context[0]._zl_parent, context[1]._zl_parent]).toEqual([3, 4294967300, null]);
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

const SYSMON = "'Microsoft-Windows-Sysmon/Operational', 1";
const SECURITY = "'Security', 4688";

/** One process start, named the same way for both sources: pid is the new process, ppid its creator. */
interface Start { uid: number; at: string | null; security?: boolean; host: string; image?: string; guid?: string; pguid?: string; pid?: string; ppid?: string }

function insert(s: Start): string {
  const v = (x: string | null | undefined) => (x === null || x === undefined ? 'NULL' : `'${x.replaceAll("'", "''")}'`);
  const time = s.at === null ? 'NULL' : `TIMESTAMP '2021-06-04 ${s.at}'`;
  // Security 4688 writes the new process as NewProcessId and its creator as ProcessId.
  const [pid, ppid, newpid] = s.security ? [s.ppid, null, s.pid] : [s.pid, s.ppid, null];
  return 'INSERT INTO events (_zl_uid, _zl_part, _zl_time, "Channel", "EventID", "Computer", "Image", "NewProcessName", ' +
    '"ProcessGuid", "ParentProcessGuid", "ProcessId", "ParentProcessId", "NewProcessId") VALUES ' +
    `(${s.uid}, 2, ${time}, ${s.security ? SECURITY : SYSMON}, ${v(s.host)}, ${v(s.security ? null : s.image)}, ` +
    `${v(s.security ? s.image : null)}, ${v(s.guid)}, ${v(s.pguid)}, ${v(pid)}, ${v(ppid)}, ${v(newpid)})`;
}

const LINEAGE: Start[] = [
  // A PID reused: cmd.exe held 0x100 and ended; explorer.exe took 0x100 later and started powershell.
  { uid: 101, at: '00:00:01', security: true, host: 'LAB', image: 'C:\\Windows\\System32\\cmd.exe', pid: '0x100', ppid: '0x4' },
  { uid: 102, at: '00:00:03', security: true, host: 'LAB', image: 'C:\\Windows\\explorer.exe', pid: '0x100', ppid: '0x8' },
  { uid: 103, at: '00:00:04', security: true, host: 'LAB', image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', pid: '0x200', ppid: '0x100' },
  // A 4688 child of a Sysmon parent: hexadecimal 0x1f4 is decimal 500, and host names compare ignoring case.
  { uid: 201, at: '01:00:00', host: 'WS03', image: 'C:\\Tools\\parent.exe', guid: '{S1}', pid: '500', ppid: '4' },
  { uid: 202, at: '01:00:05', security: true, host: 'ws03', image: 'C:\\Tools\\child.exe', pid: '0x300', ppid: '0x1f4' },
  // The same PID on two hosts.
  { uid: 301, at: '02:00:00', host: 'HOSTA', image: 'C:\\a.exe', pid: '777' },
  { uid: 302, at: '02:00:01', security: true, host: 'HOSTB', image: 'C:\\b.exe', pid: '0x400', ppid: '0x309' },
  // Two starts naming each other as parent.
  { uid: 401, at: '03:00:00', host: 'CYC', image: 'C:\\c1.exe', guid: '{C1}', pguid: '{C2}' },
  { uid: 402, at: '03:00:01', host: 'CYC', image: 'C:\\c2.exe', guid: '{C2}', pguid: '{C1}' },
  // A reused PID: each child links to the latest start of 900 before it.
  { uid: 501, at: '04:00:00', host: 'R', image: 'C:\\first.exe', pid: '900' },
  { uid: 502, at: '04:00:20', host: 'R', image: 'C:\\second.exe', pid: '900' },
  { uid: 503, at: '04:00:10', host: 'R', image: 'C:\\early.exe', pid: '901', ppid: '900' },
  { uid: 504, at: '04:00:30', host: 'R', image: 'C:\\late.exe', pid: '902', ppid: '900' },
  // A parent guid nobody started, beside a PID that happens to match.
  { uid: 601, at: '05:00:00', host: 'T', image: 'C:\\lookalike.exe', pid: '9' },
  { uid: 602, at: '05:00:01', host: 'T', image: 'C:\\orphan.exe', pguid: '{GONE}', pid: '10', ppid: '9' },
  // Starts without a time link to nothing by PID, and nothing links to them.
  { uid: 701, at: null, host: 'W', image: 'C:\\timeless.exe', pid: '5' },
  { uid: 702, at: '06:00:00', host: 'W', image: 'C:\\w.exe', pid: '6', ppid: '5' },
  { uid: 703, at: null, host: 'W', image: 'C:\\w2.exe', pid: '7', ppid: '6' },
  // A PID cannot be its own parent's: the parent was alive when the child took its PID.
  { uid: 801, at: '07:00:00', host: 'P', image: 'C:\\old.exe', pid: '42' },
  { uid: 802, at: '07:00:05', host: 'P', image: 'C:\\self.exe', pid: '42', ppid: '42' },
  { uid: 901, at: '08:00:00', host: 'G', image: 'C:\\selfguid.exe', guid: '{SELF}', pguid: '{SELF}' },
  // A chain by guid: root, mid, leaf.
  { uid: 1001, at: '09:00:00', host: 'CH', image: 'C:\\root.exe', guid: '{R}' },
  { uid: 1002, at: '09:00:01', host: 'CH', image: 'C:\\mid.exe', guid: '{M}', pguid: '{R}' },
  { uid: 1003, at: '09:00:02', host: 'CH', image: 'C:\\leaf.exe', guid: '{L}', pguid: '{M}' },
];

describe('process lineage over every start', () => {
  let db: Fixture;
  beforeAll(async () => { db = await openFixture([...PROCESS_FIELDS.map((f) => `ALTER TABLE events ADD COLUMN "${f.name}" VARCHAR`), ...LINEAGE.map(insert)]); });
  afterAll(() => db.close());

  const uids = (list: number[]) => `_zl_uid IN (${list.join(', ')})`;
  async function tree(where: string, on = wide) {
    const kept = (await db.rows(processRowsSql(on, where) as string)) as unknown as RawProcess[];
    const context = (await db.rows(ancestorsSql(on, where) as string)) as unknown as RawProcess[];
    const all = [...kept, ...context];
    return { kept, context, roots: buildForest(all.map(toProcess)), parent: (uid: number) => all.find((r) => r._zl_uid === uid)?._zl_parent };
  }

  it('finds the true parent of a reused PID when a filter hides it, and shows it for context', async () => {
    const { kept, context, roots, parent } = await tree(`"NewProcessName" ILIKE '%cmd.exe' OR "NewProcessName" ILIKE '%powershell.exe'`);
    expect(kept.map((r) => r._zl_uid)).toEqual([101, 103]);
    expect(parent(103)).toBe(102);
    expect(context.map((r) => r._zl_uid)).toEqual([102]);
    expect(roots.map((r) => r.uid)).toEqual([101, 102]);
    expect(roots[1].children.map((r) => r.uid)).toEqual([103]);
    expect(roots[0].children).toEqual([]);
  });

  it('links a Security 4688 child to its Sysmon parent through hexadecimal and decimal PIDs', async () => {
    const { parent, roots } = await tree(uids([202]));
    expect(parent(202)).toBe(201);
    expect(roots.map((r) => r.uid)).toEqual([201]);
  });

  it('never links the same PID across two hosts', async () => {
    const { parent, context } = await tree(uids([302]));
    expect(parent(302)).toBeNull();
    expect(context).toEqual([]);
  });

  it('ends a guid cycle, and the tree holds each start once', async () => {
    const { kept, context, roots } = await tree(uids([401]));
    expect(kept.map((r) => r._zl_parent)).toEqual([402]);
    expect(context.map((r) => [r._zl_uid, r._zl_parent])).toEqual([[402, 401]]);
    expect(roots).toHaveLength(1);
    expect(visibleRows(roots, new Set([401, 402]))).toHaveLength(2);
  });

  it('links a reused PID to its latest earlier start', async () => {
    const { parent } = await tree(uids([503, 504]));
    expect([parent(503), parent(504)]).toEqual([501, 502]);
  });

  it('trusts a parent guid it cannot find over a PID that happens to match', async () => {
    expect((await tree(uids([602]))).parent(602)).toBeNull();
  });

  it('links nothing by PID without a time on either side', async () => {
    const { parent } = await tree(uids([702, 703]));
    expect([parent(702), parent(703)]).toEqual([null, null]);
  });

  it('never makes a start its own parent, or the parent of a start that holds its PID', async () => {
    const { parent } = await tree(uids([802, 901]));
    expect([parent(802), parent(901)]).toEqual([null, null]);
  });

  it('walks up a chain, nearest ancestor first', async () => {
    const { context, roots } = await tree(uids([1003]));
    expect(context.map((r) => r._zl_uid)).toEqual([1002, 1001]);
    expect(roots[0].children[0].children[0].uid).toBe(1003);
  });

  it('keeps the PID links in a package without guid fields, and the guid links without PID fields', async () => {
    const without = (names: string[]) => new Schema(wide.fields.filter((f) => !names.includes(f.name)), TACTICS);
    const pidOnly = await tree(uids([103, 202, 1003]), without(['ProcessGuid', 'ParentProcessGuid']));
    expect([pidOnly.parent(103), pidOnly.parent(202), pidOnly.parent(1003)]).toEqual([102, 201, null]);
    const guidOnly = await tree(uids([103, 202, 1003]), without(['ProcessId', 'ParentProcessId', 'NewProcessId']));
    expect([guidOnly.parent(103), guidOnly.parent(202), guidOnly.parent(1003)]).toEqual([null, null, 1002]);
  });

  it('stops at the ancestor limit with the nearest kept, and knows it stopped', async () => {
    const over = await db.rows(ancestorsSql(wide, uids([1003]), PROCESS_LIMIT, 1) as string);
    expect(over.map((r) => r._zl_uid)).toEqual([1002, 1001]);
    const cut = keepAncestors(over, 1);
    expect([cut.rows.map((r) => r._zl_uid), cut.capped]).toEqual([[1002], true]);
    const all = keepAncestors(await db.rows(ancestorsSql(wide, uids([1003]), PROCESS_LIMIT, 2) as string), 2);
    expect([all.rows.map((r) => r._zl_uid), all.capped]).toEqual([[1002, 1001], false]);
  });
});
