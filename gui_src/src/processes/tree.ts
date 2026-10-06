/** One process start as processes.ts selects it; Sysmon and Security name the same facts differently. */
export interface RawProcess {
  _zl_uid: number;
  _zl_t: number | null;
  sysmon: boolean;
  host: string | null;
  guid: string | null;
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
  target: string | null;
  lvl: number | null;
  hits: number;
  /** The start that created this one, resolved in SQL over every start in the package. */
  _zl_parent: number | null;
  context: boolean;
}

export interface Process {
  uid: number;
  t: number | null;
  host: string | null;
  guid: string | null;
  parentUid: number | null;
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

/**
 * The account a Security 4688 process runs as. SubjectUserName is the account
 * that started it; TargetUserName is the new process's own, or - when the
 * event names none.
 */
function runsAs(target: string | null): string | null {
  const text = target?.trim() ?? '';
  return text && text !== '-' ? text : null;
}

export function toProcess(raw: RawProcess): Process {
  // Security 4688: NewProcessId is the new process, ProcessId the one that started it.
  const security = !raw.sysmon;
  return {
    uid: raw._zl_uid,
    t: raw._zl_t,
    host: raw.host,
    guid: raw.guid?.trim().toLowerCase() || null,
    parentUid: raw._zl_parent,
    pid: pidText(security ? raw.newpid : raw.pid),
    ppid: pidText(security ? raw.pid : raw.ppid),
    image: security ? (raw.newimage ?? raw.image) : raw.image,
    parentImage: security ? raw.pname : raw.pimage,
    commandLine: raw.cmd,
    user: security ? (runsAs(raw.target) ?? raw.subject ?? raw.user) : (raw.user ?? raw.subject),
    lvl: raw.lvl,
    hits: raw.hits,
    context: raw.context,
    parent: null,
    children: [],
  };
}

const startOrder = (a: Process, b: Process) => (a.t ?? Infinity) - (b.t ?? Infinity) || a.uid - b.uid;

/**
 * Processes linked to the start that created them, in start order. SQL
 * resolved each parent over every start in the package, so the rows shown
 * never decide lineage; a start whose parent is not among them is a root.
 */
export function buildForest(processes: Process[]): Process[] {
  const all = [...new Map(processes.map((p) => [p.uid, p])).values()].sort((a, b) => startOrder(a, b) || 0);
  for (const p of all) {
    p.parent = null;
    p.children = [];
  }
  const byUid = new Map(all.map((p) => [p.uid, p]));
  // The top of each linked tree so far, path-compressed: a link that would put a start under its own
  // descendant closes a loop in the data, which would hang every walk up the tree. Each start is linked
  // at most once, so it is the top of its tree when its turn comes.
  const top = new Map(all.map((p) => [p, p]));
  const find = (p: Process): Process => {
    let root = p;
    while (top.get(root) !== root) root = top.get(root) as Process;
    for (let q = p; q !== root; ) {
      const up = top.get(q) as Process;
      top.set(q, root);
      q = up;
    }
    return root;
  };
  for (const p of all) {
    const parent = p.parentUid === null ? undefined : byUid.get(p.parentUid);
    if (!parent || find(parent) === p) continue;
    p.parent = parent;
    parent.children.push(p);
    top.set(p, find(parent));
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
