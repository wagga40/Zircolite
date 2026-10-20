<script lang="ts" generics="Row extends { total: number }">
  import type { Snippet } from 'svelte';
  import { runAgain } from '../state/run.svelte';
  import { formatCount } from '../ui/format';
  import LocalTable from '../ui/LocalTable.svelte';
  import type { LocalSort, TableColumn } from '../ui/localFilters';
  import { LOGON_LIMIT } from './logons';
  import type { LogonTable } from './table.svelte';

  let { title, note, table, id, columns, order, events, open, opens, noun, unavailable, figure }: {
    title: string;
    note: string;
    table: LogonTable<Row>;
    id: string;
    columns: TableColumn<Row>[];
    order: LocalSort;
    /** How many events a row lists in Explore, when the table counts them. */
    events?: (row: Row) => number;
    open: (row: Row) => void;
    /** What opening a row shows, for its button's title. */
    opens?: (row: Row) => string;
    noun: string;
    /** Why the package cannot answer this table, said in its place. */
    unavailable: string;
    /** Drawn above the table, from the same rows. */
    figure?: Snippet;
  } = $props();

  const rows = $derived(table.answer?.rows ?? []);
  const total = $derived(rows[0]?.total ?? 0);
</script>

<section aria-labelledby={`${id}-title`}>
  <h2 id={`${id}-title`}>{title}</h2>
  <p class="note">{note}</p>
  {#if table.unavailable}
    <p class="note">{unavailable}</p>
  {:else if table.list.slot.failure}
    <p class="note failure" role="alert">The {noun} could not be listed: {table.list.slot.failure}. Change the search, or reload the page if this repeats.</p>
  {:else if table.list.slot.stopped}
    <p class="note" role="status">Stopped. <button type="button" onclick={runAgain}>Run again</button></p>
  {:else}
    {#if total > rows.length}<p class="note">Showing {formatCount(rows.length)} of {formatCount(total)} rows. Filter a column to find the others.</p>{/if}
    {@render figure?.()}
    <LocalTable {id} {columns} {rows} pending={table.list.slot.pending} answered={table.answer !== null} bind:filters={table.filters} bind:sort={table.sort}
      {order} empty={`No ${noun} ${table.filters ? 'pass the column filters' : 'among these events'}.`} loading={`Listing the ${noun}`}
      pivot={{ events, open, title: (row) => opens?.(row) ?? `Show the ${formatCount(events?.(row) ?? 0)} events of this row` }} />
    {#if rows.length === LOGON_LIMIT}<p class="note">The table stops at {formatCount(LOGON_LIMIT)} rows.</p>{/if}
  {/if}
</section>

<style>
  h2 { margin: 24px 0 4px; font-size: var(--t-15); }
  .note { margin: 6px 0; color: var(--ink-2); font-size: var(--t-13); }
  .failure { color: var(--danger); }
  button { min-height: 28px; padding: 3px 10px; background: none; border: 1px solid var(--rule); border-radius: var(--radius); cursor: pointer; color: var(--ink); font: inherit; font-size: var(--t-13); }
</style>
