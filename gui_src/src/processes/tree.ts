/** One process start as processes.ts selects it; Sysmon and Security name the same facts differently. */
export interface RawProcess {
  _zl_uid: number;
  _zl_t: number | null;
  sysmon: boolean;
  host: string | null;
  guid: string | null;
  pguid: string | null;
  pid: string | null;
  ppid: string | null;
  newpid: string | null;
  image: string | null;
  newimage: string | null;
  pimage: string | null;
  pname: string | null;
  cmd: string | null;
  user: string | null;
  subject: string | null;
  lvl: number | null;
  hits: number;
  context: boolean;
}

export interface Process {
  uid: number;
  t: number | null;
  host: string | null;
  guid: string | null;
  parentGuid: string | null;
  pid: string | null;
  ppid: string | null;
  image: string | null;
  parentImage: string | null;
  commandLine: string | null;
  user: string | null;
  lvl: number | null;
  hits: number;
  /** An ancestor shown for context, outside the filters. */
  context: boolean;
  parent: Process | null;
  children: Process[];
}

/** A PID as one text: Security 4688 writes it in hexadecimal (0x1f4), Sysmon in decimal (500). */
export function pidText(value: string | null): string | null {
  const text = value?.trim() ?? '';
  if (!text) return null;
  if (/^0x[0-9a-f]+$/i.test(text) || /^\d+$/.test(text)) return BigInt(text).toString();
  return text;
}

function guidText(value: string | null): string | null {
  const text = value?.trim().toLowerCase() ?? '';
  return text || null;
}

export function toProcess(raw: RawProcess): Process {
  // Security 4688: NewProcessId is the new process, ProcessId the one that started it.
  const security = !raw.sysmon;
  return {
    uid: raw._zl_uid,
    t: raw._zl_t,
    host: raw.host,
    guid: guidText(raw.guid),
    parentGuid: guidText(raw.pguid),
    pid: pidText(security ? raw.newpid : raw.pid),
    ppid: pidText(security ? raw.pid : raw.ppid),
    image: security ? (raw.newimage ?? raw.image) : raw.image,
    parentImage: security ? raw.pname : raw.pimage,
    commandLine: raw.cmd,
    user: security ? (raw.subject ?? raw.user) : (raw.user ?? raw.subject),
    lvl: raw.lvl,
    hits: raw.hits,
    context: raw.context,
    parent: null,
    children: [],
  };
}

const startOrder = (a: Process, b: Process) => (a.t ?? Infinity) - (b.t ?? Infinity) || a.uid - b.uid;

/**
 * Processes linked to the start that created them, in start order. A parent
 * guid links exactly, so a child that names one is never linked any other
 * way. A child without one links to the latest earlier start of its parent
 * PID on the same host: PIDs come back after a process ends.
 */
export function buildForest(processes: Process[]): Process[] {
  const all = [...new Map(processes.map((p) => [p.uid, p])).values()].sort((a, b) => startOrder(a, b) || 0);
  for (const p of all) {
    p.parent = null;
    p.children = [];
  }
  const byGuid = new Map<string, Process>();
  for (const p of all) if (p.guid && !byGuid.has(p.guid)) byGuid.set(p.guid, p);
  const byPid = new Map<string, Process[]>();
  for (const p of all) {
    if (!p.host || !p.pid || p.t === null) continue;
    const key = `${p.host.toLowerCase()}|${p.pid}`;
    const starts = byPid.get(key);
    // `all` is in start order, so each list is too.
    if (starts) starts.push(p);
    else byPid.set(key, [p]);
  }
  const above = (candidate: Process, p: Process) => {
    for (let a: Process | null = candidate; a; a = a.parent) if (a === p) return true;
    return false;
  };
  for (const p of all) {
    let parent: Process | undefined;
    if (p.parentGuid) parent = byGuid.get(p.parentGuid);
    else if (p.host && p.ppid && p.t !== null) {
      const starts = byPid.get(`${p.host.toLowerCase()}|${p.ppid}`) ?? [];
      // Binary search: a PID reused thousands of times must not cost a scan per child.
      let lo = 0;
      let hi = starts.length;
      while (lo < hi) {
        const mid = (lo + hi) >> 1;
        if ((starts[mid].t as number) <= (p.t as number)) lo = mid + 1;
        else hi = mid;
      }
      for (let i = lo - 1; i >= 0 && !parent; i--) if (starts[i] !== p) parent = starts[i];
    }
    // A loop in the data would hang every walk up the tree; the later link is dropped.
    if (parent && parent !== p && !above(parent, p)) {
      p.parent = parent;
      parent.children.push(p);
    }
  }
  return all.filter((p) => p.parent === null);
}

export interface Row {
  process: Process;
  depth: number;
  expandable: boolean;
  expanded: boolean;
  /** 1-based place among its siblings, for aria-posinset. */
  posinset: number;
  setsize: number;
}

/** The rows the tree shows: every root, and the children of every expanded process. */
export function visibleRows(roots: Process[], expanded: ReadonlySet<number>): Row[] {
  const rows: Row[] = [];
  const stack: { list: Process[]; index: number; depth: number }[] = [{ list: roots, index: 0, depth: 0 }];
  while (stack.length) {
    const top = stack[stack.length - 1];
    if (top.index >= top.list.length) {
      stack.pop();
      continue;
    }
    const process = top.list[top.index++];
    const open = expanded.has(process.uid) && process.children.length > 0;
    rows.push({ process, depth: top.depth, expandable: process.children.length > 0, expanded: open, posinset: top.index, setsize: top.list.length });
    if (open) stack.push({ list: process.children, index: 0, depth: top.depth + 1 });
  }
  return rows;
}

/** Every process with children, for Expand all. */
export function withChildren(roots: Process[]): number[] {
  const out: number[] = [];
  const stack = [...roots];
  while (stack.length) {
    const p = stack.pop() as Process;
    if (p.children.length) {
      out.push(p.uid);
      stack.push(...p.children);
    }
  }
  return out;
}

export function basename(path: string | null): string {
  return path ? (path.split(/[\\/]/).pop() ?? '') : '';
}

/**
 * The row to keep active once `expanded` applies: the process itself while
 * every ancestor is open, else the highest closed ancestor, which is still shown.
 */
export function visibleAncestor(process: Process, expanded: ReadonlySet<number>): Process {
  let shown = process;
  for (let a = process.parent; a; a = a.parent) if (!expanded.has(a.uid)) shown = a;
  return shown;
}
