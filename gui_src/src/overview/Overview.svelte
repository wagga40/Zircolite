<script lang="ts">
  import { untrack } from 'svelte';
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import { isSuperseded } from '../engine/queries';
  import type { Field, Schema } from '../engine/schema';
  import Strip from '../explore/Strip.svelte';
  import { topValuesSql } from '../explore/sidebar';
  import { appendRaw, appendTerm, quoteValue } from '../search/edit';
  import type { QueryState } from '../state/query.svelte';
  import { run, runAgain } from '../state/run.svelte';
  import { view } from '../state/view.svelte';
  import { formatCount } from '../ui/format';
  import {
    entityField, type TacticCell, tacticCells, tacticsSql, type Tile, tileEventsSql, tileRulesSql, tiles, topRulesSql,
  } from './overview';

  let { db, schema, manifest, query }: { db: Db; schema: Schema; manifest: Manifest; query: QueryState } = $props();

  interface TopRule { key: string; title: string; rank: number; events: number }
  interface TopValue { v: string; n: number; total: number }
  interface Slot<T> {
    data: T | null;
    pending: boolean;
    failure: string | null;
    stopped: boolean;
  }

  const empty = <T,>(): Slot<T> => ({ data: null, pending: true, failure: null, stopped: false });

  const host = $derived(entityField('host', schema));
  const user = $derived(entityField('user', schema));
  let tileSlot = $state.raw<Slot<Tile[]>>(empty());
  let tacticSlot = $state.raw<Slot<TacticCell[]>>(empty());
  let ruleSlot = $state.raw<Slot<TopRule[]>>(empty());
  let hostSlot = $state.raw<Slot<TopValue[]>>(empty());
  let userSlot = $state.raw<Slot<TopValue[]>>(empty());
  // One ticket per panel: a panel only accepts the answer to its own latest request.
  const tickets = { tiles: 0, tactics: 0, rules: 0, hosts: 0, users: 0 };

  function load<T>(name: keyof typeof tickets, get: () => Slot<T>, set: (slot: Slot<T>) => void, fetch: () => Promise<T>): void {
    const mine = ++tickets[name];
    set({ ...untrack(get), pending: true, failure: null, stopped: false });
    void (async () => {
      try {
        const data = await fetch();
        if (mine === tickets[name]) set({ data, pending: false, failure: null, stopped: false });
      } catch (error) {
        if (mine !== tickets[name]) return;
        // Whatever is on screen belongs to an earlier filter, so it goes.
        if (isSuperseded(error)) set({ data: null, pending: false, failure: null, stopped: run.stopped });
        else set({ data: null, pending: false, failure: error instanceof Error ? error.message : String(error), stopped: false });
      }
    })();
  }

  $effect(() => {
    void run.generation;
    const where = query.where;
    const hostField = host;
    const userField = user;
    load('tiles', () => tileSlot, (s) => (tileSlot = s), async () => {
      const eventRows = await db.rows<{ rank: number; events: number }>(tileEventsSql(where), { lane: 'overview-tiles' });
      const ruleRows = await db.rows<{ rank: number; rules: number }>(tileRulesSql(where), { lane: 'overview-tiles' });
      return tiles(eventRows, ruleRows);
    });
    load('tactics', () => tacticSlot, (s) => (tacticSlot = s), async () =>
      tacticCells(manifest.tactics, await db.rows<{ tactic: string; events: number }>(tacticsSql(where), { lane: 'overview-tactics' })));
    load('rules', () => ruleSlot, (s) => (ruleSlot = s), () => db.rows<TopRule>(topRulesSql(where), { lane: 'overview-rules' }));
    const top = (field: Field | undefined, kind: string): Promise<TopValue[]> =>
      field ? db.rows<TopValue>(topValuesSql(field, where, 8), { lane: `overview-top:${kind}` }) : Promise.resolve([]);
    load('hosts', () => hostSlot, (s) => (hostSlot = s), () => top(hostField, 'host'));
    load('users', () => userSlot, (s) => (userSlot = s), () => top(userField, 'user'));
  });

  const tileTotal = $derived(tileSlot.data ? tileSlot.data.reduce((sum, tile) => sum + tile.events, 0) : null);
  const filtered = $derived(query.where !== 'TRUE');
  const busy = $derived([tileSlot, tacticSlot, ruleSlot, hostSlot, userSlot].some((slot) => slot.pending));

  function explore(term: string): void {
    view.q = appendRaw(view.q, term);
    view.route = 'explore';
  }

  function exploreValue(field: Field, value: string): void {
    view.q = appendTerm(view.q, field.name, value, false);
    view.route = 'explore';
  }

  const lists = $derived([
    { label: 'Top hosts', field: host, slot: hostSlot },
    { label: 'Top users', field: user, slot: userSlot },
  ]);
</script>

{#snippet problem(slot: Slot<unknown>, what: string)}
  {#if slot.failure}
    <p class="note failure" role="alert">The {what} could not be counted: {slot.failure}. Change the search, or reload the page if this repeats.</p>
  {:else if slot.stopped}
    <p class="note" role="status">Stopped. <button type="button" class="again" onclick={runAgain}>Run again</button></p>
  {/if}
{/snippet}

<main class="overview" aria-busy={busy}>
  <div class="page">
    <header>
      <h1 tabindex="-1">Overview</h1>
      <output id="overview-summary">
        {#if tileTotal !== null}{formatCount(tileTotal)} {tileTotal === 1 ? 'event' : 'events'} with detections{filtered ? ' under the current filters' : ''}{:else if tileSlot.stopped}Stopped{:else}Counting detections{/if}
      </output>
    </header>

    <section id="overview-tiles" class="tiles" class:stale={tileSlot.pending && tileSlot.data !== null} aria-label="Events by highest detection level" data-events={tileTotal ?? ''}>
      {#each tileSlot.data ?? [] as tile (tile.rank)}
        <button type="button" class="tile" data-rank={tile.rank} data-events={tile.events}
          title={`Events whose highest detection is ${tile.level}`} onclick={() => explore(`level:${tile.level}`)}>
          <span class="name"><i style:background={`var(--sev-${tile.rank})`}></i>{tile.level[0].toUpperCase() + tile.level.slice(1)}</span>
          <span class="count">{formatCount(tile.events)}</span>
          <span class="unit">{tile.events === 1 ? 'event' : 'events'}</span>
          <span class="rules">{formatCount(tile.rules)} {tile.rules === 1 ? 'rule' : 'rules'}</span>
        </button>
      {/each}
    </section>
    {@render problem(tileSlot, 'severity counts')}

    <Strip {db} {manifest} where={query.whereWithoutTime} />

    <section class="tactics" aria-label="Events by ATT&CK tactic">
      <h2>ATT&amp;CK tactics{filtered ? ', under the current filters' : ''}</h2>
      {@render problem(tacticSlot, 'tactics')}
      <div class="cells" class:stale={tacticSlot.pending && tacticSlot.data !== null}>
        {#each tacticSlot.data ?? [] as cell (cell.tactic)}
          <button type="button" class="cell" class:none={cell.events === 0} data-tactic={cell.tactic}
            style:background={cell.events ? `color-mix(in srgb, var(--signal) ${Math.round(8 + 40 * cell.share)}%, var(--panel))` : undefined}
            onclick={() => explore(`tactic:${cell.tactic}`)}>
            <span class="label">{cell.label}</span>
            <span class="count">{formatCount(cell.events)}</span>
          </button>
        {/each}
      </div>
    </section>

    <div class="columns">
      <section aria-label="Top rules" class:stale={ruleSlot.pending && ruleSlot.data !== null}>
        <h2>Top rules{filtered ? ', under the current filters' : ''}</h2>
        {@render problem(ruleSlot, 'rules')}
        {#if ruleSlot.data && ruleSlot.data.length === 0}<p class="note">No detection under the current filters.</p>{/if}
        <ol class="list" id="overview-rules">
          {#each ruleSlot.data ?? [] as rule (rule.key)}
            <li><button type="button" data-key={rule.key} data-events={rule.events} onclick={() => explore(`rulekey:${quoteValue(rule.key)}`)}>
              <i style:background={`var(--sev-${Math.max(0, rule.rank)})`}></i><span class="text">{rule.title}</span><span class="n">{formatCount(rule.events)}</span>
            </button></li>
          {/each}
        </ol>
      </section>
      <div>
        {#each lists as list (list.label)}
          <section aria-label={list.label} class:stale={list.slot.pending && list.slot.data !== null}>
            <h2>{list.label}{#if list.field}<span class="field"> ({list.field.name})</span>{/if}</h2>
            {#if !list.field}<p class="note">This package has no such field.</p>{/if}
            {@render problem(list.slot, list.label.toLowerCase())}
            {#if list.field && list.slot.data && list.slot.data.length === 0}<p class="note">Nothing under the current filters.</p>{/if}
            <ol class="list">
              {#each list.slot.data ?? [] as row (row.v)}
                <li><button type="button" onclick={() => list.field && exploreValue(list.field, row.v)}>
                  <span class="text mono">{row.v === '' ? 'empty text' : row.v}</span><span class="n">{formatCount(row.n)}</span>
                </button></li>
              {/each}
            </ol>
          </section>
        {/each}
      </div>
    </div>

    <section class="warnings" aria-label="Run warnings">
      <h2>Run warnings</h2>
      {#if manifest.warnings.length === 0}
        <p class="note">No warnings for this run.</p>
      {:else}
        <ul>{#each manifest.warnings as warning}<li>{warning}</li>{/each}</ul>
      {/if}
      <p class="note">Event filtering: {manifest.run.event_filter}.</p>
    </section>
  </div>
</main>

<style>
  .overview { min-height: 0; overflow: auto; background: var(--paper); }
  .page { max-width: 1200px; padding: 16px; display: grid; gap: 20px; }
  header { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 16px; }
  h1 { margin: 0; font-size: var(--t-18); }
  output { font-weight: 600; }
  .stale { opacity: 0.5; transition: opacity var(--motion); }
  h2 { margin: 0 0 8px; font-size: var(--t-15); }
  .tiles { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); border: 1px solid var(--rule); background: var(--panel); min-height: 92px; }
  .tile { display: grid; gap: 2px; padding: 12px 14px; text-align: left; background: none; border: 0; border-right: 1px solid var(--rule); cursor: pointer; }
  .tile:last-child { border-right: 0; }
  .tile:hover { background: color-mix(in srgb, var(--signal) 6%, transparent); }
  .name { display: inline-flex; align-items: center; gap: 6px; font-size: var(--t-13); }
  .name i, .list i { width: 8px; height: 8px; border-radius: 1px; flex: none; }
  .tile .count { font: 600 var(--t-22) / 1.1 var(--sans); font-variant-numeric: tabular-nums; }
  .unit, .rules { font-size: var(--t-13); color: var(--ink-2); }
  .cells { display: grid; grid-template-columns: repeat(auto-fill, minmax(118px, 1fr)); gap: 1px; background: var(--rule); border: 1px solid var(--rule); min-height: 58px; }
  .cell { display: grid; gap: 2px; min-height: 56px; padding: 8px; text-align: left; border: 0; background: var(--panel); cursor: pointer; }
  .cell .label { font-size: var(--t-12); }
  .cell .count { font: 600 var(--t-15) / 1.2 var(--sans); font-variant-numeric: tabular-nums; }
  .cell.none { color: var(--ink-2); }
  .columns { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 24px; }
  .list { list-style: none; margin: 0 0 16px; padding: 0; }
  .list button { display: flex; align-items: center; gap: 8px; width: 100%; min-height: 28px; padding: 2px 4px; text-align: left; background: none; border: 0; border-bottom: 1px solid color-mix(in srgb, var(--rule) 60%, transparent); cursor: pointer; }
  .list button:hover { background: color-mix(in srgb, var(--signal) 6%, transparent); }
  .text { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .mono { font: 400 var(--t-13) / 1.4 var(--mono); }
  .n { font: 400 var(--t-13) / 1 var(--mono); font-variant-numeric: tabular-nums; }
  .field { margin-left: 6px; font-weight: 400; color: var(--ink-2); font-size: var(--t-13); }
  .warnings ul { margin: 0; padding-left: 18px; }
  .note { margin: 4px 0; color: var(--ink-2); font-size: var(--t-13); }
  .failure { color: var(--danger); }
  .again { min-height: 28px; background: none; border: 1px solid var(--rule); border-radius: var(--radius); padding: 3px 10px; cursor: pointer; }
  @media (max-width: 720px) {
    .tiles { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .tile { border-bottom: 1px solid var(--rule); }
    .tile:nth-child(2n) { border-right: 0; }
    .tile:last-child { grid-column: 1 / -1; border-bottom: 0; }
    .columns { grid-template-columns: minmax(0, 1fr); }
  }
</style>
