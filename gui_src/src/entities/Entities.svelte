<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Schema } from '../engine/schema';
  import { valueLabel } from '../explore/sidebar';
  import { appendRaw } from '../search/edit';
  import type { QueryState } from '../state/query.svelte';
  import { run, runAgain } from '../state/run.svelte';
  import { view } from '../state/view.svelte';
  import { formatCount, isoTime } from '../ui/format';
  import { Panel } from '../ui/panel.svelte';
  import { ownScope } from '../ui/scope';
  import { ENTITY_KINDS, ENTITY_LIMIT, entitiesSql, entityFields, type EntityKind, type EntityOrder, type EntityRow, entityTerm } from './entities';

  let { db: page, schema, manifest, query }: { db: Db; schema: Schema; manifest: Manifest; query: QueryState } = $props();
  // svelte-ignore state_referenced_locally
  const db = ownScope(page, 'entities');

  let kind = $state<EntityKind>(ENTITY_KINDS[0]);
  let filter = $state('');
  let applied = $state('');
  let order = $state<EntityOrder>('events');
  const fields = $derived(entityFields(kind, schema));
  const list = new Panel<EntityRow[]>();

  // Typing a filter asks once it pauses, not on every key.
  $effect(() => {
    const text = filter.trim();
    const timer = setTimeout(() => (applied = text), 250);
    return () => clearTimeout(timer);
  });

  $effect(() => {
    void run.generation;
    const where = query.where;
    const chosen = fields;
    const text = applied;
    const by = order;
    if (chosen.length === 0) return;
    list.load(() => db.rows<EntityRow>(entitiesSql(chosen, where, text, by), { lane: 'list' }));
  });

  const rows = $derived(list.slot.data ?? []);
  const total = $derived(rows[0]?.total ?? 0);
  const filtered = $derived(query.where !== 'TRUE');

  function explore(value: string): void {
    view.q = appendRaw(view.q, entityTerm(fields, value));
    view.route = 'explore';
  }
</script>

<main class="entities">
  <header>
    <h1 tabindex="-1">Entities</h1>
    {#if list.slot.stopped}<button type="button" class="again" onclick={runAgain}>Run again</button>{/if}
  </header>
  <div class="kinds" role="group" aria-label="Kind of entity">
    {#each ENTITY_KINDS as k (k.kind)}
      <button type="button" aria-pressed={kind.kind === k.kind} onclick={() => (kind = k)}>{k.label}</button>
    {/each}
  </div>

  {#if fields.length === 0}
    <p class="note">This package has no field for {kind.noun} (looked for {kind.fields.join(', ')}).</p>
  {:else}
    <p class="note">Fields: {fields.map((f) => f.name).join(', ')}. Values are grouped ignoring case; an event counts once per value{filtered ? ', under the current filters' : ''}.</p>
    <div class="controls">
      <label>Filter values <input type="search" bind:value={filter} spellcheck="false" autocomplete="off" /></label>
      <label>Sort by
        <select bind:value={order}>
          <option value="events">Most events</option>
          <option value="detections">Most events with detections</option>
          <option value="first">First seen</option>
          <option value="last">Last seen</option>
        </select>
      </label>
    </div>
    {#if list.slot.failure}
      <p class="note failure" role="alert">The {kind.noun} could not be listed: {list.slot.failure}. Change the search, or reload the page if this repeats.</p>
    {:else if list.slot.stopped}
      <p class="note" role="status">Stopped.</p>
    {:else}
      {#if total > rows.length}
        <p class="note">Showing {formatCount(rows.length)} of {formatCount(total)} values. Type in the filter to find the others.</p>
      {/if}
      <div class="wrap">
        <table id="entities-table" data-kind={kind.kind} data-rows={list.slot.pending || list.slot.data === null ? '' : rows.length}
          class:stale={list.slot.pending && list.slot.data !== null} aria-busy={list.slot.pending}>
          <thead>
            <tr>
              <th scope="col">{kind.label}</th>
              <th scope="col" class="num">Events</th>
              <th scope="col" class="num">With detections</th>
              <th scope="col">First seen (UTC)</th>
              <th scope="col">Last seen (UTC)</th>
            </tr>
          </thead>
          <tbody>
            {#each rows as row, i (i)}
              <tr>
                <td><button type="button" class="value" data-events={row.events} disabled={list.slot.pending} title={`Show the ${formatCount(row.events)} events of ${valueLabel(row.v)}`} onclick={() => explore(row.v)}>{valueLabel(row.v)}</button></td>
                <td class="num">{formatCount(row.events)}</td>
                <td class="num">{formatCount(row.detections)}</td>
                <td class="time">{row.first === null ? 'No time' : isoTime(row.first, false)}</td>
                <td class="time">{row.last === null ? 'No time' : isoTime(row.last, false)}</td>
              </tr>
            {:else}
              {#if !list.slot.pending}<tr><td colspan="5" class="note">No {kind.noun} {applied ? `contain "${applied}"` : 'among these events'}.</td></tr>{/if}
            {/each}
          </tbody>
        </table>
      </div>
      {#if total > ENTITY_LIMIT && rows.length === ENTITY_LIMIT}<p class="note">The table stops at {formatCount(ENTITY_LIMIT)} rows.</p>{/if}
    {/if}
  {/if}
</main>

<style>
  .entities { overflow: auto; padding: 16px 24px 32px; background: var(--paper); min-width: 0; }
  header { display: flex; align-items: baseline; gap: 12px; }
  h1 { margin: 0; font-size: var(--t-18); }
  .kinds { display: flex; flex-wrap: wrap; gap: 6px; margin: 12px 0 4px; }
  .kinds button, .again { min-height: 28px; padding: 3px 10px; background: none; border: 1px solid var(--rule); border-radius: var(--radius); cursor: pointer; }
  .kinds button[aria-pressed='true'] { border-color: var(--signal); font-weight: 600; color: var(--ink); }
  .note { margin: 6px 0; color: var(--ink-2); font-size: var(--t-13); }
  .failure { color: var(--danger); }
  .controls { display: flex; flex-wrap: wrap; gap: 8px 16px; margin: 8px 0; font-size: var(--t-13); }
  .controls input, .controls select { margin-left: 6px; min-height: 28px; font: inherit; color: var(--ink); background: var(--paper); border: 1px solid var(--rule); border-radius: var(--radius); padding: 2px 8px; }
  .wrap { overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; font-size: var(--t-13); }
  th { position: sticky; top: 0; background: var(--paper); text-align: left; font-weight: 600; padding: 6px 12px 6px 0; border-bottom: 1px solid var(--rule); white-space: nowrap; }
  td { padding: 3px 12px 3px 0; border-bottom: 1px solid color-mix(in srgb, var(--rule) 60%, transparent); }
  /* Anywhere-wrapping values collapse to a few characters in a narrow table; the wrapper scrolls instead. */
  td:first-child { min-width: 200px; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .time { font-family: var(--mono); white-space: nowrap; }
  .value { min-height: 24px; padding: 0; text-align: left; background: none; border: 0; color: var(--signal); font: 400 var(--t-13) / 1.4 var(--mono); cursor: pointer; overflow-wrap: anywhere; }
  .stale { opacity: 0.5; }
</style>
