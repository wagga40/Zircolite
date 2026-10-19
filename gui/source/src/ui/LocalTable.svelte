<script lang="ts" generics="T extends object">
  import FilterCell from './FilterCell.svelte';
  import { formatCount, isoTime } from './format';
  import { applyLocalCell, cellHint, type LocalColumn, localCellText, type LocalSort, localSchema, type TableColumn } from './localFilters';

  let {
    id, columns, rows, pending, answered, filters = $bindable(''), sort = $bindable(null), order, pivot, empty, missing = '',
  }: {
    id: string;
    columns: TableColumn<T>[];
    rows: T[];
    pending: boolean;
    /** Whether the rows answer the table's current question; until then the table holds no row count. */
    answered: boolean;
    /** The table's own column filters, in the search grammar over its columns. */
    filters?: string;
    sort?: LocalSort | null;
    /** The order with no column picked, for the header to show. */
    order: LocalSort;
    /** The first column opens a row's events: how many there are, when the table knows, and how to open them. */
    pivot: { events?: (row: T) => number; open: (row: T) => void; title: (row: T) => string };
    /** What the table says when it has no row. */
    empty: string;
    /** How a missing text value reads; empty leaves the cell blank. */
    missing?: string;
  } = $props();

  let problem = $state<string | null>(null);
  const schema = $derived(localSchema(columns.map((c) => c.column)));
  const shownSort = $derived(sort ?? order);

  function value(row: T, name: string): unknown {
    return (row as Record<string, unknown>)[name];
  }

  function cell(row: T, column: TableColumn<T>): string {
    if (column.show) return column.show(row);
    const raw = value(row, column.column.name);
    if (column.column.type === 'number') return raw === null || raw === undefined ? '' : formatCount(Number(raw));
    if (column.column.type === 'time') return raw === null || raw === undefined ? 'No time' : isoTime(Number(raw), false);
    return raw === null || raw === undefined ? missing : raw === '' ? 'empty text' : String(raw);
  }

  function apply(column: LocalColumn, text: string): string | null {
    const result = applyLocalCell(filters, column, text, schema);
    if ('problem' in result) return result.problem;
    filters = result.query;
    return null;
  }

  // A count is most telling from the largest down, a value or a time from the start.
  function sortBy(column: LocalColumn): void {
    if (shownSort.column === column.name) sort = { column: column.name, desc: !shownSort.desc };
    else sort = { column: column.name, desc: column.type === 'number' };
  }

  function ariaSort(column: LocalColumn): 'ascending' | 'descending' | undefined {
    return shownSort.column === column.name ? (shownSort.desc ? 'descending' : 'ascending') : undefined;
  }
</script>

{#if problem}<p class="note failure" role="alert">{problem}</p>{/if}
<div class="wrap">
  <table {id} data-rows={pending || !answered ? '' : rows.length} class:stale={pending && answered} aria-busy={pending}>
    <thead>
      <tr>
        {#each columns as { column, label } (column.name)}
          <th scope="col" class:num={column.type === 'number'} aria-sort={ariaSort(column)}>
            <button type="button" class="sort" aria-label={`Sort by ${label}`} onclick={() => sortBy(column)}>{label}{ariaSort(column) === 'descending' ? ' ↓' : ariaSort(column) === 'ascending' ? ' ↑' : ''}</button>
            <FilterCell {label} text={localCellText(filters, column)} apply={(text) => apply(column, text)} onclear={() => apply(column, '')}
              onproblem={(next) => (problem = next)} hint={cellHint(column.type)} />
          </th>
        {/each}
      </tr>
    </thead>
    <tbody>
      {#each rows as row, i (i)}
        <tr>
          {#each columns as column, j (column.column.name)}
            {@const raw = value(row, column.column.name)}
            <td class:num={column.column.type === 'number'} class:time={column.column.type === 'time'} class:missing={column.column.type === 'text' && (raw === null || raw === '')}>
              {#if j === 0}
                <button type="button" class="value" data-events={pivot.events?.(row)} disabled={pending} title={pivot.title(row)} onclick={() => pivot.open(row)}>{cell(row, column) || '(missing)'}</button>
              {:else}
                {cell(row, column)}
              {/if}
            </td>
          {/each}
        </tr>
      {:else}
        {#if !pending}<tr><td colspan={columns.length} class="note">{empty}</td></tr>{/if}
      {/each}
    </tbody>
  </table>
</div>

<style>
  .note { margin: 6px 0; color: var(--ink-2); font-size: var(--t-13); }
  .failure { color: var(--danger); }
  .wrap { overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; font-size: var(--t-13); }
  th { position: sticky; top: 0; z-index: 1; background: var(--paper); text-align: left; font-weight: 600; padding: 6px 12px 6px 0; border-bottom: 1px solid var(--rule); white-space: nowrap; vertical-align: top; }
  .sort { display: block; min-height: 24px; margin-bottom: 4px; padding: 0; background: none; border: 0; font: inherit; color: inherit; cursor: pointer; text-align: inherit; }
  th.num .sort { margin-left: auto; }
  td { padding: 3px 12px 3px 0; border-bottom: 1px solid color-mix(in srgb, var(--rule) 60%, transparent); font-family: var(--mono); overflow-wrap: anywhere; }
  td:first-child { min-width: 200px; }
  .missing { color: var(--ink-2); font-style: italic; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .time { white-space: nowrap; }
  .value { min-height: 24px; padding: 0; text-align: left; background: none; border: 0; color: var(--signal); font: 400 var(--t-13) / 1.4 var(--mono); cursor: pointer; overflow-wrap: anywhere; }
  .value:disabled { cursor: default; }
  .stale { opacity: 0.5; }
</style>
