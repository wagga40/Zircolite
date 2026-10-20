/**
 * The lateral movement graph: sources on the left, the hosts they reached on
 * the right, a curve for each link. A host that reached others as well is
 * drawn on both sides: nothing in a logon tells which address is which host.
 */
import type { LateralRow } from './logons';

/** Links drawn; past this the curves blur into one another, and the table lists the rest. */
export const GRAPH_EDGES = 60;
const ROW = 24;
const PAD = 16;

export interface GraphNode {
  key: string;
  label: string;
  events: number;
  y: number;
}

export interface GraphEdge {
  row: LateralRow;
  /** Indexes into the sources and the targets. */
  from: number;
  to: number;
  width: number;
}

export interface Graph {
  sources: GraphNode[];
  targets: GraphNode[];
  edges: GraphEdge[];
  /** Links of the table the graph leaves out. */
  left: number;
  height: number;
}

interface Tally {
  key: string;
  label: string;
  events: number;
  /** For a source: the events-weighted mean position of the hosts it reached. */
  centre: number;
}

function tally(rows: LateralRow[], label: (row: LateralRow) => string, position: (row: LateralRow) => number): Tally[] {
  const byKey = new Map<string, Tally & { weighted: number }>();
  for (const row of rows) {
    const key = label(row).toLowerCase();
    const node = byKey.get(key) ?? { key, label: label(row), events: 0, centre: 0, weighted: 0 };
    node.events += row.events;
    node.weighted += row.events * position(row);
    byKey.set(key, node);
  }
  return [...byKey.values()].map(({ weighted, ...node }) => ({ ...node, centre: node.events > 0 ? weighted / node.events : 0 }));
}

const placed = (nodes: Tally[]): GraphNode[] => nodes.map(({ key, label, events }, i) => ({ key, label, events, y: PAD + i * ROW + ROW / 2 }));

export function lateralGraph(rows: LateralRow[], limit = GRAPH_EDGES): Graph {
  const shown = rows.slice(0, limit);
  const byLabel = (a: Tally, b: Tally) => a.label.toLowerCase().localeCompare(b.label.toLowerCase());
  const targets = tally(shown, (row) => row.target, () => 0).sort((a, b) => b.events - a.events || byLabel(a, b));
  const at = new Map(targets.map((node, i) => [node.key, i]));
  // Each source beside the hosts it reached keeps the curves from crossing more than they must.
  const sources = tally(shown, (row) => row.source, (row) => at.get(row.target.toLowerCase()) ?? 0)
    .sort((a, b) => a.centre - b.centre || b.events - a.events || byLabel(a, b));
  const from = new Map(sources.map((node, i) => [node.key, i]));
  const most = Math.max(1, ...shown.map((row) => row.events));
  return {
    sources: placed(sources),
    targets: placed(targets),
    edges: shown.map((row) => ({
      row,
      from: from.get(row.source.toLowerCase()) ?? 0,
      to: at.get(row.target.toLowerCase()) ?? 0,
      width: 1.5 + (3.5 * Math.log1p(row.events)) / Math.log1p(most),
    })),
    left: rows.length - shown.length,
    height: PAD * 2 + Math.max(1, sources.length, targets.length) * ROW,
  };
}
