<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Schema } from '../engine/schema';
  import { tacticsSql } from '../overview/overview';
  import { appendRaw } from '../search/edit';
  import type { QueryState } from '../state/query.svelte';
  import { run, runAgain } from '../state/run.svelte';
  import { view } from '../state/view.svelte';
  import { formatCount } from '../ui/format';
  import { Panel, type Slot } from '../ui/panel.svelte';
  import { ownScope } from '../ui/scope';
  import {
    detectedTechniques, heatInk, heatmap, heatmapSql, heatTerm, matrix, type MatrixMode, STORED_TECHNIQUES_SQL,
    techniqueCountsSql, unlisted, WEEKDAYS,
  } from './attack';
  import { CATALOG } from './catalog';

  let { db: page, schema, manifest, query }: { db: Db; schema: Schema; manifest: Manifest; query: QueryState } = $props();
  // svelte-ignore state_referenced_locally
  const db = ownScope(page, 'attack');

  let mode = $state<MatrixMode>('detected');
  let open = $state<string[]>([]);

  const techniques = new Panel<{ counts: Map<string, number>; stored: string[] }>();
  const tactics = new Panel<Map<string, number>>();
  const heat = new Panel<{ day: number; hour: number; events: number }[]>();

  $effect(() => {
    void run.generation;
    const where = query.where;
    techniques.load(async () => {
      const rows = await db.rows<{ id: string; events: number }>(techniqueCountsSql(where), { lane: 'techniques' });
      const stored = await db.rows<{ id: string }>(STORED_TECHNIQUES_SQL, { lane: 'techniques' });
      return { counts: new Map(rows.map((r) => [r.id, r.events])), stored: stored.map((r) => r.id) };
    });
    tactics.load(async () =>
      new Map((await db.rows<{ tactic: string; events: number }>(tacticsSql(where), { lane: 'tactics' })).map((r) => [r.tactic, r.events])));
    heat.load(() => db.rows<{ day: number; hour: number; events: number }>(heatmapSql(where), { lane: 'heatmap' }));
  });

  const counts = $derived(techniques.slot.data?.counts ?? null);
  const columns = $derived(counts ? matrix(counts, mode) : []);
  const others = $derived(techniques.slot.data ? unlisted(techniques.slot.data.stored, techniques.slot.data.counts) : []);
  const detected = $derived(counts ? detectedTechniques(counts) : null);
  const grid = $derived(heat.slot.data ? heatmap(heat.slot.data) : null);
  const filtered = $derived(query.where !== 'TRUE');
  const nothing = $derived(counts !== null && mode === 'detected' && columns.every((c) => c.cells.length === 0));
  const anyStopped = $derived([techniques.slot, tactics.slot, heat.slot].some((slot) => slot.stopped));
  const pad = (hour: number) => String(hour).padStart(2, '0');

  function explore(term: string, detectionsOnly = false): void {
    view.q = appendRaw(view.q, term);
    if (detectionsOnly) view.d = true;
    view.route = 'explore';
  }

  function toggle(id: string): void {
    open = open.includes(id) ? open.filter((x) => x !== id) : [...open, id];
  }
</script>

{#snippet problem(slot: Slot<unknown>, what: string)}
  {#if slot.failure}
    <p class="note failure" role="alert">The {what} could not be counted: {slot.failure}. Change the search, or reload the page if this repeats.</p>
  {:else if slot.stopped}
    <p class="note" role="status">Stopped.</p>
  {/if}
{/snippet}

<main class="attack" aria-busy={techniques.slot.pending || tactics.slot.pending || heat.slot.pending}>
  <header>
    <h1 tabindex="-1">ATT&CK</h1>
    <output class:stale={techniques.slot.pending} aria-busy={techniques.slot.pending}>
      {#if detected !== null && !techniques.slot.pending}{formatCount(detected)} {detected === 1 ? 'technique' : 'techniques'} detected{filtered ? ' under the current filters' : ''}{:else if techniques.slot.stopped}Stopped{:else}Counting techniques{/if}
    </output>
    <span class="modes" role="group" aria-label="Techniques shown">
      <button type="button" aria-pressed={mode === 'detected'} onclick={() => (mode = 'detected')}>Detected techniques</button>
      <button type="button" aria-pressed={mode === 'full'} onclick={() => (mode = 'full')}>Full matrix</button>
    </span>
    {#if anyStopped}<button type="button" class="again" onclick={runAgain}>Run again</button>{/if}
  </header>
  <p class="note">ATT&CK {CATALOG.version}. A technique under several tactics shows the same count in each; a technique counts its sub-techniques' events.</p>

  <section id="attack-matrix" class="matrix" aria-label="ATT&CK matrix" class:stale={(techniques.slot.pending || tactics.slot.pending) && counts !== null}
    aria-busy={techniques.slot.pending || tactics.slot.pending}
    data-techniques={techniques.slot.pending || detected === null ? '' : detected}>
    {#if nothing}<p class="empty">No technique is detected under these filters.</p>{/if}
    <div class="columns" class:hidden={nothing}>
      {#each columns as column (column.tactic)}
        <div class="column" role="group" aria-label={column.name}>
          <button type="button" class="tactic" data-tactic={column.tactic} data-events={tactics.slot.data ? (tactics.slot.data.get(column.tactic) ?? 0) : ''}
            title={`Events detected under ${column.name}`} onclick={() => explore(`tactic:${column.tactic}`)}>
            <span class="name">{column.name}</span>
            <span class="n">{tactics.slot.data ? formatCount(tactics.slot.data.get(column.tactic) ?? 0) : ''}</span>
          </button>
          {#each column.cells as cell (cell.id)}
            <div class="cell" class:none={cell.events === 0} style:background={heatInk(cell.share)}>
              <button type="button" class="technique" data-technique={cell.id} data-events={cell.events}
                onclick={() => explore(`technique:${cell.id}`)}>
                <span class="tname">{cell.name}</span>
                <span class="id">{cell.id}</span>
                <span class="n">{formatCount(cell.events)}</span>
              </button>
              {#if cell.subs.length}
                <button type="button" class="subs-toggle" aria-expanded={open.includes(cell.id)} onclick={() => toggle(cell.id)}>
                  {cell.subs.length} {cell.subs.length === 1 ? 'sub-technique' : 'sub-techniques'}
                </button>
                {#if open.includes(cell.id)}
                  <ul class="subs">
                    {#each cell.subs as sub (sub.id)}
                      <li style:background={heatInk(sub.share)} class:none={sub.events === 0}>
                        <button type="button" class="technique" data-technique={sub.id} data-events={sub.events}
                          onclick={() => explore(`technique:${sub.id}`)}>
                          <span class="tname">{sub.name}</span>
                          <span class="id">{sub.id}</span>
                          <span class="n">{formatCount(sub.events)}</span>
                        </button>
                      </li>
                    {/each}
                  </ul>
                {/if}
              {/if}
            </div>
          {:else}
            {#if counts && !nothing}<p class="empty">None detected</p>{/if}
          {/each}
        </div>
      {/each}
    </div>
  </section>
  {@render problem(techniques.slot, 'techniques')}
  {@render problem(tactics.slot, 'tactic counts')}

  {#if others.length}
    <section class="others" aria-labelledby="others-title">
      <h2 id="others-title">Tags ATT&CK {CATALOG.version} does not list</h2>
      <table>
        <thead><tr><th scope="col">Tag</th><th scope="col">Replaced by</th><th scope="col" class="num">Events</th></tr></thead>
        <tbody>
          {#each others as other (other.id)}
            <tr>
              <td><button type="button" class="link" data-technique={other.id} data-events={other.events} onclick={() => explore(`technique:${other.id}`)}>{other.id}</button></td>
              <td>{other.replacement ? `${other.replacement.id} ${other.replacement.name}` : other.status === 'retired' ? 'Retired' : 'Unknown'}</td>
              <td class="num">{formatCount(other.events)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}

  <section class="heat" aria-labelledby="heat-title">
    <h2 id="heat-title">When detections happen (UTC)</h2>
    {#if grid}
      <div class="grid-wrap" class:stale={heat.slot.pending}>
        <table class="heatmap">
          <thead>
            <tr><td></td>{#each { length: 24 } as _, hour (hour)}<th scope="col">{#if hour % 3 === 0}{pad(hour)}<span class="sr">:00</span>{:else}<span class="sr">{pad(hour)}:00</span>{/if}</th>{/each}</tr>
          </thead>
          <tbody>
            {#each grid.cells as row, d (d)}
              <tr>
                <th scope="row">{WEEKDAYS[d].slice(0, 3)}</th>
                {#each row as cell (cell.hour)}
                  <td>
                    <button type="button" class="hc" data-day={cell.day} data-hour={cell.hour} data-events={cell.events}
                      disabled={cell.events === 0} style:background={heatInk(cell.share)}
                      aria-label={`${WEEKDAYS[d]} ${pad(cell.hour)}:00 UTC, ${formatCount(cell.events)} ${cell.events === 1 ? 'event' : 'events'}`}
                      title={`${WEEKDAYS[d]} ${pad(cell.hour)}:00 UTC: ${formatCount(cell.events)}`}
                      onclick={() => explore(heatTerm(cell.day, cell.hour), true)}></button>
                  </td>
                {/each}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <p class="note">Darker means more events with detections; the busiest hour holds {formatCount(grid.busiest)}. Events without a time are left out.</p>
    {/if}
    {@render problem(heat.slot, 'hours')}
  </section>
</main>

<style>
  .attack { overflow: auto; padding: 16px 24px 32px; background: var(--paper); min-width: 0; }
  header { display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px 16px; }
  h1 { margin: 0; font-size: var(--t-18); }
  h2 { margin: 24px 0 8px; font-size: var(--t-15); }
  output { font-weight: 600; }
  .modes { display: inline-flex; gap: 6px; }
  .modes button, .again { min-height: 28px; padding: 3px 10px; background: none; border: 1px solid var(--rule); border-radius: var(--radius); cursor: pointer; }
  .modes button[aria-pressed='true'] { border-color: var(--signal); color: var(--ink); font-weight: 600; }
  .note { margin: 6px 0; color: var(--ink-2); font-size: var(--t-13); }
  .failure { color: var(--danger); }
  .stale { opacity: 0.5; }
  .matrix { overflow: auto; max-height: 70vh; margin-top: 12px; border-top: 1px solid var(--rule); border-left: 1px solid var(--rule); }
  .columns { display: grid; align-items: start; grid-auto-flow: column; grid-auto-columns: minmax(136px, 1fr); }
  .column { border-right: 1px solid var(--rule); min-width: 0; }
  .tactic { display: grid; gap: 2px; width: 100%; min-height: 48px; padding: 8px; text-align: left; background: var(--panel); border: 0; border-bottom: 1px solid var(--rule); cursor: pointer; position: sticky; top: 0; }
  .tactic .name { font-size: var(--t-13); font-weight: 600; }
  .tactic .n { font-size: var(--t-12); color: var(--ink-2); font-variant-numeric: tabular-nums; }
  .cell { border-bottom: 1px solid var(--rule); background: var(--panel); }
  .cell.none, .subs li.none { color: var(--ink-2); }
  .technique { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 2px 6px; width: 100%; min-height: 40px; padding: 6px 8px; text-align: left; background: none; border: 0; cursor: pointer; color: inherit; }
  .tname { grid-column: 1; font-size: var(--t-12); overflow-wrap: anywhere; display: -webkit-box; -webkit-line-clamp: 3; line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }
  .id { grid-column: 1; font: 400 11px / 1.3 var(--mono); color: var(--ink-2); }
  .technique .n { grid-column: 2; grid-row: 1 / span 2; align-self: center; font-size: var(--t-12); font-variant-numeric: tabular-nums; }
  .subs-toggle { display: block; min-height: 24px; margin: 0 8px 6px; padding: 0; background: none; border: 0; color: var(--ink-2); font-size: var(--t-12); cursor: pointer; text-decoration: underline; }
  .subs { list-style: none; margin: 0; padding: 0 0 4px 12px; }
  .subs li { border-top: 1px solid color-mix(in srgb, var(--rule) 60%, transparent); }
  .empty { margin: 8px; color: var(--ink-2); font-size: var(--t-12); }
  .others table { border-collapse: collapse; font-size: var(--t-13); }
  .others th, .others td { text-align: left; padding: 4px 12px 4px 0; border-bottom: 1px solid var(--rule); }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .link { min-height: 24px; padding: 0; background: none; border: 0; color: var(--signal); font: 400 var(--t-13) / 1.4 var(--mono); cursor: pointer; text-decoration: underline; }
  .grid-wrap { overflow-x: auto; }
  .heatmap { border-collapse: separate; border-spacing: 2px; }
  .heatmap th { position: relative; font: 400 11px / 1.2 var(--mono); color: var(--ink-2); padding: 0 4px; text-align: left; white-space: nowrap; }
  .heatmap td { padding: 0; }
  .hc { display: block; width: 24px; height: 24px; padding: 0; border: 1px solid var(--rule); border-radius: 2px; background: var(--panel); cursor: pointer; }
  .hidden { display: none; }
  .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
  @media (max-width: 720px) { .matrix { max-height: 55vh; } }
  .hc:disabled { cursor: default; }
</style>
