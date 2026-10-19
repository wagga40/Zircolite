<script lang="ts">
  import { formatCount } from '../ui/format';
  import { lateralGraph, type GraphEdge } from './graph';
  import type { LateralRow } from './logons';

  let { rows, open, pending }: { rows: LateralRow[]; open: (row: LateralRow) => void; pending: boolean } = $props();

  const graph = $derived(lateralGraph(rows));
  // Drawn at the width of its box, never scaled, so labels keep the size of the text around them; a narrow
  // screen scrolls it instead.
  const LABELS = 250;
  let box = $state(960);
  const width = $derived(Math.max(640, box));
  const LEFT = LABELS;
  const RIGHT = $derived(width - LABELS);
  const KIND: Record<string, string> = { '3 Network logon': 'network', '10 Remote Desktop logon': 'rdp', '4648 Explicit credentials': 'explicit' };

  const short = (label: string) => (label.length > 32 ? `${label.slice(0, 31)}…` : label);

  function path(edge: GraphEdge): string {
    const y1 = graph.sources[edge.from].y;
    const y2 = graph.targets[edge.to].y;
    const mid = (LEFT + RIGHT) / 2;
    return `M ${LEFT} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${RIGHT} ${y2}`;
  }

  function describe(row: LateralRow): string {
    const who = row.account_list ? `, as ${row.account_list}${row.accounts > 3 ? ` and ${formatCount(row.accounts - 3)} more` : ''}` : '';
    return `${row.source} to ${row.target}: ${row.kind}, ${formatCount(row.events)} events${who}`;
  }

  function onkey(event: KeyboardEvent, row: LateralRow): void {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    open(row);
  }
</script>

{#if graph.edges.length > 0}
  <figure class="graph" class:stale={pending}>
    <div class="scroll" bind:clientWidth={box}>
      <svg id="lateral-graph" viewBox={`0 0 ${width} ${graph.height}`} {width} height={graph.height} role="group"
        aria-label="Lateral movement: sources on the left, the hosts they reached on the right">
        {#each graph.edges as edge, i (i)}
          <g class={`link ${KIND[edge.row.kind] ?? 'network'}`} role="button" tabindex="0" aria-label={`Show the events of ${describe(edge.row)}`}
            aria-disabled={pending} data-events={edge.row.events} onclick={() => !pending && open(edge.row)} onkeydown={(event) => !pending && onkey(event, edge.row)}>
            <title>{describe(edge.row)}</title>
            <path class="hit" d={path(edge)} />
            <path class="line" d={path(edge)} stroke-width={edge.width} />
          </g>
        {/each}
        {#each graph.sources as node (node.key)}
          <g class="node">
            <circle cx={LEFT} cy={node.y} r="4" />
            <text x={LEFT - 10} y={node.y} text-anchor="end" dominant-baseline="middle"><title>{node.label}: {formatCount(node.events)} events</title>{short(node.label)}</text>
          </g>
        {/each}
        {#each graph.targets as node (node.key)}
          <g class="node">
            <circle cx={RIGHT} cy={node.y} r="4" />
            <text x={RIGHT + 10} y={node.y} dominant-baseline="middle"><title>{node.label}: {formatCount(node.events)} events</title>{short(node.label)}</text>
          </g>
        {/each}
      </svg>
    </div>
    <figcaption>
      <span class="key network">Network logon (3)</span>
      <span class="key rdp">Remote Desktop logon (10)</span>
      <span class="key explicit">Explicit credentials (4648)</span>
      <span>A link shows its events. {#if graph.left > 0}The graph draws the first {formatCount(graph.edges.length)} links of the table below; {formatCount(graph.left)} more are listed there only.{/if}</span>
    </figcaption>
  </figure>
{/if}

<style>
  .graph { margin: 8px 0 12px; }
  .scroll { overflow-x: auto; }
  svg { display: block; font: 400 var(--t-12) / 1 var(--mono); }
  .stale { opacity: 0.5; }
  .node circle { fill: var(--paper); stroke: var(--ink-2); stroke-width: 1.5; }
  .node text { fill: var(--ink); }
  .link { cursor: pointer; outline: none; }
  .link[aria-disabled='true'] { cursor: default; }
  .hit { fill: none; stroke: transparent; stroke-width: 12; }
  .line { fill: none; stroke-opacity: 0.55; stroke-linecap: round; transition: stroke-opacity var(--motion); }
  .link:hover .line, .link:focus-visible .line { stroke-opacity: 1; }
  .link:focus-visible .hit { stroke: color-mix(in srgb, var(--signal) 25%, transparent); }
  .network .line { stroke: var(--signal); }
  .rdp .line { stroke: var(--sev-3); }
  .explicit .line { stroke: var(--sev-unknown); stroke-dasharray: 6 4; }
  figcaption { display: flex; flex-wrap: wrap; gap: 6px 16px; margin-top: 6px; color: var(--ink-2); font-size: var(--t-13); }
  .key::before { content: ''; display: inline-block; width: 22px; height: 0; margin-right: 6px; vertical-align: middle; border-top: 3px solid; }
  .key.network::before { border-color: var(--signal); }
  .key.rdp::before { border-color: var(--sev-3); }
  .key.explicit::before { border-top-style: dashed; border-color: var(--sev-unknown); }
  @media (prefers-reduced-motion: reduce) { .line { transition: none; } }
</style>
