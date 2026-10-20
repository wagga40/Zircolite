<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Field, Schema } from '../engine/schema';
  import { asciiLower } from '../engine/sql';
  import { appendRaw } from '../search/edit';
  import { findShortcut } from '../search/shortcuts';
  import type { QueryState } from '../state/query.svelte';
  import { run, runAgain } from '../state/run.svelte';
  import { view } from '../state/view.svelte';
  import { formatCount } from '../ui/format';
  import LocalTable from '../ui/LocalTable.svelte';
  import { type LocalSort, localSchema, localWhere, sortClause, type TableColumn } from '../ui/localFilters';
  import { Panel } from '../ui/panel.svelte';
  import { ownScope } from '../ui/scope';
  import { stackChoice } from './choice.svelte';
  import { STACK_COLUMNS, STACK_FIELDS, STACK_LIMIT, STACK_ORDER, stackPresets, type StackRow, stackSql, stackTerms } from './stack';

  let { db: page, schema, manifest, query }: { db: Db; schema: Schema; manifest: Manifest; query: QueryState } = $props();
  // svelte-ignore state_referenced_locally
  const db = ownScope(page, 'stacking');

  const presets = $derived(stackPresets(schema));
  const host = $derived((findShortcut('host')?.fields ?? []).map((name) => schema.find(name)).find((field) => field !== undefined) ?? null);
  // The first preset until the person picks; a name this package lacks is dropped, as a link's columns are.
  const fields = $derived.by((): Field[] => {
    const names = stackChoice.fields ?? presets[0]?.map((field) => field.name) ?? [];
    return names.map((name) => schema.find(name)).filter((field): field is Field => field !== undefined).slice(0, STACK_FIELDS);
  });
  const signature = $derived(fields.map((field) => field.key).join('\u0000'));
  const LABELS: Record<string, string> = { events: 'Events', hosts: 'Hosts', detections: 'With detections', first: 'First seen (UTC)', last: 'Last seen (UTC)' };
  const tableColumns = $derived<TableColumn<StackRow>[]>(STACK_COLUMNS(fields.length)
    .filter((column) => column.name !== 'hosts' || host !== null)
    .map((column) => ({ column, label: column.name.startsWith('v') ? fields[Number(column.name.slice(1))].name : LABELS[column.name] })));
  const columnSchema = $derived(localSchema(STACK_COLUMNS(fields.length)));
  let filters = $state('');
  let sort = $state<LocalSort | null>(null);
  let adding = $state('');
  const list = new Panel<{ signature: string; rows: StackRow[] }>();

  // Other fields are other columns: their filters and order no longer apply.
  $effect(() => {
    void signature;
    filters = '';
    sort = null;
  });

  $effect(() => {
    void run.generation;
    const where = query.where;
    const chosen = fields;
    const asked = signature;
    if (chosen.length === 0) return;
    const sql = stackSql(chosen, where, host, {
      missing: stackChoice.missing, filter: localWhere(filters, columnSchema), order: sortClause(sort, STACK_ORDER),
    });
    list.load(async () => ({ signature: asked, rows: await db.rows<StackRow>(sql, { lane: 'list' }) }));
  });

  const answer = $derived(list.slot.data?.signature === signature ? list.slot.data : null);
  const rows = $derived(answer?.rows ?? []);
  const total = $derived(rows[0]?.total ?? 0);

  function choose(names: string[]): void {
    stackChoice.fields = names.slice(0, STACK_FIELDS);
  }

  function add(): void {
    const field = schema.find(adding.trim());
    if (!field || fields.some((f) => f.key === field.key) || fields.length >= STACK_FIELDS) return;
    choose([...fields.map((f) => f.name), field.name]);
    adding = '';
  }

  function explore(row: StackRow): void {
    view.q = appendRaw(view.q, stackTerms(fields, row));
    view.route = 'explore';
  }

  const presetLabel = (preset: Field[]) => preset.map((field) => field.name).join(' + ');
  const isChosen = (preset: Field[]) => preset.length === fields.length && preset.every((field, i) => field.key === fields[i].key);
</script>

<main class="stacking">
  <header>
    <h1 tabindex="-1">Stacking</h1>
    {#if fields.length > 0 && answer}
      <output class:stale={list.slot.pending} aria-busy={list.slot.pending}>{formatCount(total)} {total === 1 ? 'combination' : 'combinations'}{query.where !== 'TRUE' ? ' under the current filters' : ''}</output>
    {/if}
    {#if list.slot.stopped}<button type="button" class="again" onclick={runAgain}>Run again</button>{/if}
  </header>
  <p class="note">Each value of the stacked fields, rarest first: what few events on few hosts carry is where unusual activity hides. Values are grouped ignoring case; a row opens its events in Explore.</p>

  <div class="pick">
    {#if presets.length > 0}
      <div class="presets" role="group" aria-label="Stack">
        {#each presets as preset (presetLabel(preset))}
          <button type="button" aria-pressed={isChosen(preset)} onclick={() => choose(preset.map((field) => field.name))}>{presetLabel(preset)}</button>
        {/each}
      </div>
    {/if}
    <ul class="chosen" aria-label="Stacked fields">
      {#each fields as field (field.key)}
        <li>{field.name}<button type="button" aria-label={`Stop stacking ${field.name}`} onclick={() => choose(fields.filter((f) => f !== field).map((f) => f.name))}>×</button></li>
      {/each}
    </ul>
    {#if fields.length < STACK_FIELDS}
      <form class="add" onsubmit={(event) => { event.preventDefault(); add(); }}>
        <input type="text" list="stack-fields" aria-label="Field to stack" placeholder="Add a field" bind:value={adding} spellcheck="false" autocomplete="off" />
        <datalist id="stack-fields">
          {#each schema.fields as field (field.key)}{#if !fields.some((f) => f.key === field.key)}<option value={field.name}></option>{/if}{/each}
        </datalist>
        <button type="submit" disabled={!schema.find(adding.trim()) || fields.some((f) => f.key === asciiLower(adding.trim()))}>Add</button>
      </form>
    {/if}
    <button type="button" class="toggle" aria-pressed={stackChoice.missing} onclick={() => (stackChoice.missing = !stackChoice.missing)}
      title="List events that lack a stacked field as a value of their own">Include missing values</button>
  </div>

  {#if fields.length === 0}
    <p class="note">Pick a field to stack{presets.length === 0 ? '' : ', or a preset above'}.</p>
  {:else if list.slot.failure}
    <p class="note failure" role="alert">The values could not be stacked: {list.slot.failure}. Change the search, or reload the page if this repeats.</p>
  {:else if list.slot.stopped}
    <p class="note" role="status">Stopped.</p>
  {:else}
    {#if total > rows.length}<p class="note">Showing {formatCount(rows.length)} of {formatCount(total)} combinations. Filter a column to find the others.</p>{/if}
    <LocalTable id="stacking-table" columns={tableColumns} {rows} pending={list.slot.pending} answered={answer !== null} bind:filters bind:sort
      order={{ column: 'events', desc: false }} missing="(missing)" empty={`No combination ${filters ? 'passes the column filters' : 'among these events'}.`}
      pivot={{ events: (row) => row.events, open: explore, title: (row) => `Show the ${formatCount(row.events)} events of this combination` }} />
    {#if total > STACK_LIMIT && rows.length === STACK_LIMIT}<p class="note">The table stops at {formatCount(STACK_LIMIT)} rows.</p>{/if}
  {/if}
</main>

<style>
  .stacking { overflow: auto; padding: 16px 24px 32px; background: var(--paper); min-width: 0; }
  header { display: flex; align-items: baseline; gap: 12px; }
  h1 { margin: 0; font-size: var(--t-18); }
  output { color: var(--ink-2); font-size: var(--t-13); }
  .note { margin: 6px 0; color: var(--ink-2); font-size: var(--t-13); }
  .failure { color: var(--danger); }
  .pick { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 12px; margin: 10px 0; }
  .presets { display: flex; flex-wrap: wrap; gap: 6px; }
  button { min-height: 28px; padding: 3px 10px; background: none; border: 1px solid var(--rule); border-radius: var(--radius); cursor: pointer; color: var(--ink); font: inherit; font-size: var(--t-13); }
  button:disabled { opacity: 0.5; cursor: default; }
  button[aria-pressed='true'] { border-color: var(--signal); color: var(--signal); }
  .chosen { display: flex; flex-wrap: wrap; gap: 6px; list-style: none; margin: 0; padding: 0; }
  .chosen li { display: inline-flex; align-items: center; gap: 2px; padding: 0 2px 0 8px; border: 1px solid var(--signal); border-radius: var(--radius); font: 400 var(--t-13) / 26px var(--mono); }
  .chosen button { min-height: 24px; border: 0; padding: 0 6px; color: var(--ink-2); }
  .add { display: inline-flex; gap: 6px; }
  .add input { min-height: 28px; box-sizing: border-box; padding: 0 8px; font: 400 var(--t-13) / 1 var(--mono); color: var(--ink); background: var(--paper); border: 1px solid var(--rule); border-radius: var(--radius); }
  .again { margin-left: 8px; }
  .stale { opacity: 0.5; }
</style>
