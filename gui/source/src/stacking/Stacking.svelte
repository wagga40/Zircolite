<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Field, Schema } from '../engine/schema';
  import { asciiLower } from '../engine/sql';
  import { valueLabel } from '../explore/sidebar';
  import { appendRaw } from '../search/edit';
  import { findShortcut } from '../search/shortcuts';
  import type { QueryState } from '../state/query.svelte';
  import { run, runAgain } from '../state/run.svelte';
  import { view } from '../state/view.svelte';
  import FilterCell from '../ui/FilterCell.svelte';
  import { formatCount, isoTime } from '../ui/format';
  import { applyLocalCell, cellHint, type LocalColumn, localCellText, type LocalSort, localSchema, localWhere, sortClause } from '../ui/localFilters';
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
  const columns = $derived(STACK_COLUMNS(fields.length).filter((column) => column.name !== 'hosts' || host !== null));
  const columnSchema = $derived(localSchema(STACK_COLUMNS(fields.length)));
  let filters = $state('');
  let sort = $state<LocalSort | null>(null);
  let cellProblem = $state<string | null>(null);
  let adding = $state('');
  const list = new Panel<{ signature: string; rows: StackRow[] }>();

  // Other fields are other columns: their filters and order no longer apply.
  $effect(() => {
    void signature;
    filters = '';
    sort = null;
    cellProblem = null;
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
  const LABELS: Record<string, string> = { events: 'Events', hosts: 'Hosts', detections: 'With detections', first: 'First seen (UTC)', last: 'Last seen (UTC)' };
  const label = (column: LocalColumn) => (column.name.startsWith('v') ? fields[Number(column.name.slice(1))]?.name ?? column.name : LABELS[column.name]);
  const shownSort = $derived(sort ?? { column: 'events', desc: false });

  function choose(names: string[]): void {
    stackChoice.fields = names.slice(0, STACK_FIELDS);
  }

  function add(): void {
    const field = schema.find(adding.trim());
    if (!field || fields.some((f) => f.key === field.key) || fields.length >= STACK_FIELDS) return;
    choose([...fields.map((f) => f.name), field.name]);
    adding = '';
  }

  function applyCell(column: LocalColumn, text: string): string | null {
    const result = applyLocalCell(filters, column, text, columnSchema);
    if ('problem' in result) return result.problem;
    filters = result.query;
    return null;
  }

  function sortBy(column: LocalColumn): void {
    if (shownSort.column === column.name) sort = { column: column.name, desc: !shownSort.desc };
    else sort = { column: column.name, desc: false };
  }

  function ariaSort(column: LocalColumn): 'ascending' | 'descending' | undefined {
    return shownSort.column === column.name ? (shownSort.desc ? 'descending' : 'ascending') : undefined;
  }

  function explore(row: StackRow): void {
    view.q = appendRaw(view.q, stackTerms(fields, row));
    view.route = 'explore';
  }

  function shown(value: string | null): string {
    return value === null ? '(missing)' : valueLabel(value);
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
    {#if cellProblem}<p class="note failure" role="alert">{cellProblem}</p>{/if}
    {#if total > rows.length}<p class="note">Showing {formatCount(rows.length)} of {formatCount(total)} combinations. Filter a column to find the others.</p>{/if}
    <div class="wrap">
      <table id="stacking-table" data-rows={list.slot.pending || answer === null ? '' : rows.length} class:stale={list.slot.pending && answer !== null} aria-busy={list.slot.pending}>
        <thead>
          <tr>
            {#each columns as column (column.name)}
              <th scope="col" class:num={column.type === 'number'} aria-sort={ariaSort(column)}>
                <button type="button" class="sort" aria-label={`Sort by ${label(column)}`} onclick={() => sortBy(column)}>{label(column)}{ariaSort(column) === 'descending' ? ' ↓' : ariaSort(column) === 'ascending' ? ' ↑' : ''}</button>
                <FilterCell label={label(column)} text={localCellText(filters, column)} apply={(text) => applyCell(column, text)}
                  onclear={() => applyCell(column, '')} onproblem={(problem) => (cellProblem = problem)} hint={cellHint(column.type)} />
              </th>
            {/each}
          </tr>
        </thead>
        <tbody>
          {#each rows as row, i (i)}
            <tr>
              {#each fields as _field, j (j)}
                <td class:missing={row[`v${j}`] === null}>
                  {#if j === 0}
                    <button type="button" class="value" data-events={row.events} disabled={list.slot.pending}
                      title={`Show the ${formatCount(row.events)} events of this combination`} onclick={() => explore(row)}>{shown(row[`v${j}`])}</button>
                  {:else}
                    {shown(row[`v${j}`])}
                  {/if}
                </td>
              {/each}
              <td class="num">{formatCount(row.events)}</td>
              {#if host}<td class="num">{formatCount(row.hosts ?? 0)}</td>{/if}
              <td class="num">{formatCount(row.detections)}</td>
              <td class="time">{row.first === null ? 'No time' : isoTime(row.first, false)}</td>
              <td class="time">{row.last === null ? 'No time' : isoTime(row.last, false)}</td>
            </tr>
          {:else}
            {#if !list.slot.pending}<tr><td colspan={columns.length} class="note">No combination {filters ? 'passes the column filters' : 'among these events'}.</td></tr>{/if}
          {/each}
        </tbody>
      </table>
    </div>
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
  .wrap { overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; font-size: var(--t-13); }
  th { position: sticky; top: 0; z-index: 1; background: var(--paper); text-align: left; font-weight: 600; padding: 6px 12px 6px 0; border-bottom: 1px solid var(--rule); white-space: nowrap; vertical-align: top; }
  th .sort { display: block; min-height: 24px; margin-bottom: 4px; padding: 0; border: 0; font-weight: 600; text-align: inherit; }
  th.num .sort { margin-left: auto; }
  td { padding: 3px 12px 3px 0; border-bottom: 1px solid color-mix(in srgb, var(--rule) 60%, transparent); font-family: var(--mono); overflow-wrap: anywhere; }
  td:first-child { min-width: 200px; }
  .missing { color: var(--ink-2); font-style: italic; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .time { white-space: nowrap; }
  .value { min-height: 24px; padding: 0; text-align: left; border: 0; color: var(--signal); font: 400 var(--t-13) / 1.4 var(--mono); overflow-wrap: anywhere; }
  .stale { opacity: 0.5; }
</style>
