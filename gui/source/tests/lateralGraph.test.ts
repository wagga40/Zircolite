import { describe, expect, it } from 'vitest';
import { GRAPH_EDGES, lateralGraph } from '../src/logons/graph';
import type { LateralRow } from '../src/logons/logons';

const link = (source: string, target: string, events: number, kind = '3 Network logon'): LateralRow =>
  ({ source, target, kind, events, accounts: 1, account_list: null, first: null, last: null, total: 0 });

describe('the lateral movement graph', () => {
  it('draws each source once on the left and each host once on the right, whatever its case', () => {
    const graph = lateralGraph([link('10.0.0.5', 'DC01', 3), link('10.0.0.5', 'dc01', 1, '10 Remote Desktop logon'), link('WS1', 'DC01', 2)]);
    expect(graph.sources.map((n) => n.label)).toEqual(['10.0.0.5', 'WS1']);
    expect(graph.targets.map((n) => [n.label, n.events])).toEqual([['DC01', 6]]);
    expect(graph.edges.map((e) => [e.from, e.to])).toEqual([[0, 0], [0, 0], [1, 0]]);
  });

  it('lists a host that is also a source on both sides', () => {
    const graph = lateralGraph([link('WS1', 'DC01', 1), link('10.0.0.5', 'WS1', 1)]);
    expect(graph.sources.map((n) => n.label).sort()).toEqual(['10.0.0.5', 'WS1']);
    expect(graph.targets.map((n) => n.label).sort()).toEqual(['DC01', 'WS1']);
  });

  it('puts the most reached hosts first, and each source beside the hosts it reached', () => {
    const graph = lateralGraph([link('a', 'small', 1), link('b', 'big', 5), link('c', 'big', 4), link('d', 'small', 1)]);
    expect(graph.targets.map((n) => n.label)).toEqual(['big', 'small']);
    expect(graph.sources.map((n) => n.label)).toEqual(['b', 'c', 'a', 'd']);
  });

  it('draws the first links only, and says how many it left out', () => {
    const rows = Array.from({ length: GRAPH_EDGES + 5 }, (_, i) => link(`10.0.0.${i}`, 'DC01', 1));
    const graph = lateralGraph(rows);
    expect(graph.edges).toHaveLength(GRAPH_EDGES);
    expect(graph.left).toBe(5);
    expect(graph.height).toBeGreaterThan(GRAPH_EDGES * 10);
  });

  it('draws nothing for no links', () => {
    expect(lateralGraph([])).toMatchObject({ sources: [], targets: [], edges: [], left: 0 });
  });
});
