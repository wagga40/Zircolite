<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Schema } from '../engine/schema';
  import { valueLabel } from '../explore/sidebar';
  import { appendRaw } from '../search/edit';
  import type { QueryState } from '../state/query.svelte';
  import { run, runAgain } from '../state/run.svelte';
  import { view } from '../state/view.svelte';
  import { formatCount } from '../ui/format';
  import { Panel } from '../ui/panel.svelte';
  import { ownScope } from '../ui/scope';
  import LocalTable from '../ui/LocalTable.svelte';
  import { type LocalSort, localSchema, localWhere, sortClause, type TableColumn } from '../ui/localFilters';
  import { ENTITY_COLUMNS, ENTITY_KINDS, ENTITY_LIMIT, ENTITY_ORDER, entitiesSql, entityFields, type EntityKind, type EntityKindName, type EntityRow, entityTerm } from './entities';

  let { db: page, schema, manifest, query }: { db: Db; schema: Schema; manifest: Manifest; query: QueryState } = $props();
  // svelte-ignore state_referenced_locally
  const db = ownScope(page, 'entities');

  let kind = $state<EntityKind>(ENTITY_KINDS[0]);
  // The table's own column filters, in the search grammar over its columns; the page's search is untouched.
  let filters = $state('');
  let sort = $state<LocalSort | null>(null);
  const columns = localSchema([...ENTITY_COLUMNS]);
  const fields = $derived(entityFields(kind, schema));
  const list = new Panel<{ kind: EntityKindName; rows: EntityRow[] }>();
  const tableColumns = $derived<TableColumn<EntityRow>[]>([
    { column: ENTITY_COLUMNS[0], label: kind.label },
    { column: ENTITY_COLUMNS[1], label: 'Events' },
    { column: ENTITY_COLUMNS[2], label: 'With detections' },
    { column: ENTITY_COLUMNS[3], label: 'First seen (UTC)' },
    { column: ENTITY_COLUMNS[4], label: 'Last seen (UTC)' },
  ]);

  $effect(() => {
    void run.generation;
    const where = query.where;
    const chosen = fields;
    const filter = localWhere(filters, columns);
    const order = sortClause(sort, ENTITY_ORDER);
    const asked = kind.kind;
    if (chosen.length === 0) return;
    list.load(async () => ({ kind: asked, rows: await db.rows<EntityRow>(entitiesSql(chosen, where, filter, order), { lane: 'list' }) }));
  });

  // Another kind's values never sit under this kind's header: after a switch the table waits empty.
  const answer = $derived(list.slot.data?.kind === kind.kind ? list.slot.data : null);
  const rows = $derived(answer?.rows ?? []);
  const total = $derived(rows[0]?.total ?? 0);
  const filtered = $derived(query.where !== 'TRUE');

  const summary = $derived.by(() => {
    if (list.slot.stopped) return 'Stopped';
    if (list.slot.failure) return '';
    if (answer === null) return `Counting ${kind.noun}`;
    if (rows.length === 0) return filters ? `No ${kind.noun} pass the column filters` : `No ${kind.noun} among these events`;
    return `${formatCount(total)} ${kind.noun}${filtered ? ' under the current filters' : ''}`;
  });

  function explore(value: string): void {
    view.q = appendRaw(view.q, entityTerm(fields, value));
    view.route = 'explore';
  }
</script>

<main class="entities">
  <header>
    <h1 tabindex="-1">Entities</h1>
    {#if fields.length > 0}
      <output class:stale={list.slot.pending && answer !== null} aria-busy={list.slot.pending}>{summary}</output>
    {/if}
    {#if fields.length > 0 && list.slot.stopped}<button type="button" class="again" onclick={runAgain}>Run again</button>{/if}
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
    {#if list.slot.failure}
      <p class="note failure" role="alert">The {kind.noun} could not be listed: {list.slot.failure}. Change the search, or reload the page if this repeats.</p>
    {:else if list.slot.stopped}
      <p class="note" role="status">Stopped.</p>
    {:else}
      {#if total > rows.length}
        <p class="note">Showing {formatCount(rows.length)} of {formatCount(total)} values. Filter a column to find the others.</p>
      {/if}
      <LocalTable id="entities-table" columns={tableColumns} {rows} pending={list.slot.pending} answered={answer !== null} bind:filters bind:sort
        order={{ column: 'events', desc: true }} empty={`No ${kind.noun} ${filters ? 'pass the column filters' : 'among these events'}.`}
        pivot={{ events: (row) => row.events, open: (row) => explore(row.v), title: (row) => `Show the ${formatCount(row.events)} events of ${valueLabel(row.v)}` }} />
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
  output { color: var(--ink-2); font-size: var(--t-13); }
  .stale { opacity: 0.5; }
</style>
