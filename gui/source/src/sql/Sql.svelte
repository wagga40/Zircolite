<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Schema } from '../engine/schema';
  import { ident } from '../engine/sql';
  import { csvLine } from '../explore/export';
  import type { QueryState } from '../state/query.svelte';
  import { run, runAgain, stopAll } from '../state/run.svelte';
  import { download } from '../ui/download';
  import { formatCount } from '../ui/format';
  import { Panel } from '../ui/panel.svelte';
  import { ownScope } from '../ui/scope';
  import { windowOf } from '../ui/virtual';
  import { columnWidths, numericType, type Result, runQuery, SQL_ROW_LIMIT, TABLES_SQL } from './console';
  import { sqlDraft } from './draft.svelte';

  let { db: page, schema, manifest, query }: { db: Db; schema: Schema; manifest: Manifest; query: QueryState } = $props();
  // svelte-ignore state_referenced_locally
  const db = ownScope(page, 'sql');
  const ROW = 28;

  const result = new Panel<Result>(false);
  const tables = new Panel<{ table: string; columns: { name: string; type: string }[] }[]>();
  let editor = $state<HTMLTextAreaElement>();
  let scrollTop = $state(0);
  let height = $state(0);

  $effect(() => {
    void run.generation;
    tables.load(async () => {
      const rows = await db.rows<{ t: string; c: string; type: string }>(TABLES_SQL, { lane: 'tables' });
      const grouped = new Map<string, { name: string; type: string }[]>();
      for (const row of rows) grouped.set(row.t, [...(grouped.get(row.t) ?? []), { name: row.c, type: row.type }]);
      return [...grouped].map(([table, columns]) => ({ table, columns }));
    });
  });

  function execute(): void {
    run.stopped = false;
    const text = sqlDraft.text;
    // Never cached: the same text is asked again on purpose, and the console's queries are the person's own.
    // The logging reset runs on the page, outside this view's scope, so it still runs after a stop or once the
    // view is gone; its own lane means it replaces nothing but an earlier reset.
    result.load(() =>
      runQuery((sql) => db.rows(sql, { lane: 'run', cache: false }), text, (sql) => page.rows(sql, { lane: 'sql-logging', cache: false })));
  }

  function onkeydown(event: KeyboardEvent): void {
    if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      // As the Run button: a run in progress is stopped with Stop, not replaced by a keystroke.
      if (!result.slot.pending) execute();
    }
  }

  function insert(text: string): void {
    if (!editor) return;
    const start = editor.selectionStart ?? sqlDraft.text.length;
    const end = editor.selectionEnd ?? start;
    sqlDraft.text = sqlDraft.text.slice(0, start) + text + sqlDraft.text.slice(end);
    const caret = start + text.length;
    queueMicrotask(() => {
      editor?.focus();
      editor?.setSelectionRange(caret, caret);
    });
  }

  // Anything but plain lowercase snake case is quoted: that covers reserved words such as Group and Order.
  const name = (text: string) => (/^[a-z_][a-z0-9_]*$/.test(text) && !RESERVED.has(text) ? text : ident(text));
  const RESERVED = new Set(['all', 'and', 'as', 'asc', 'between', 'by', 'case', 'check', 'column', 'create', 'default', 'desc', 'distinct', 'else', 'end', 'from', 'group', 'having', 'in', 'is', 'join', 'like', 'limit', 'not', 'null', 'on', 'or', 'order', 'select', 'table', 'then', 'union', 'using', 'when', 'where', 'with']);
  const data = $derived(result.slot.data);
  const win = $derived(windowOf(scrollTop, Math.max(0, height - ROW), data?.rows.length ?? 0, ROW));

  const widths = $derived(data ? columnWidths(data.columns, data.rows) : []);
  const numeric = $derived(data ? data.columns.map((c) => numericType(c.type)) : []);
  const total = $derived(widths.reduce((sum, w) => sum + w, 0));

  function exportCsv(): void {
    if (!data) return;
    download('zircolite-query.csv', ['\uFEFF', csvLine(data.columns.map((c) => c.name)), ...data.rows.map((row) => csvLine(row, numeric))], 'text/csv;charset=utf-8');
  }
</script>

<main class="sql">
  <header>
    <h1 tabindex="-1">SQL</h1>
    <p class="note">One SELECT at a time over events, rules, hits, alerts and alert_events. The package's tables cannot change.</p>
  </header>
  <div class="top">
    <div class="edit">
      <label class="visually-hidden" for="sql-editor">SQL query</label>
      <textarea id="sql-editor" bind:this={editor} bind:value={sqlDraft.text} rows="8" spellcheck="false" autocomplete="off" {onkeydown}></textarea>
      <div class="actions">
        <button type="button" onclick={execute} disabled={result.slot.pending}>Run</button>
        <span class="hint">Ctrl or ⌘ with Enter runs it.</span>
        {#if result.slot.pending}<button type="button" onclick={() => stopAll(db)}>Stop</button>{/if}
        <button type="button" disabled={!data || data.rows.length === 0} onclick={exportCsv}>Export CSV</button>
      </div>
    </div>
    <details class="tables">
      <summary>Tables</summary>
      {#if tables.slot.data}
        {#each tables.slot.data as table (table.table)}
          <details>
            <summary>{table.table} <span class="count">{formatCount(table.columns.length)} columns</span></summary>
            <ul>
              <li><button type="button" class="insert" onclick={() => insert(table.table)}>Insert {table.table}</button></li>
              {#each table.columns as column (column.name)}
                <li><button type="button" class="insert" title={column.type} onclick={() => insert(name(column.name))}>{column.name}</button></li>
              {/each}
            </ul>
          </details>
        {/each}
      {:else if tables.slot.stopped}
        <p class="note" role="status">Stopped. <button type="button" onclick={runAgain}>Run again</button></p>
      {:else if tables.slot.failure}
        <p class="note failure">The tables could not be listed: {tables.slot.failure}.</p>
      {/if}
    </details>
  </div>

  {#if result.slot.failure}
    <p class="note failure" role="alert">The query did not run: {result.slot.failure}.</p>
  {:else if result.slot.stopped}
    <p class="note" role="status">Stopped. <button type="button" onclick={() => { runAgain(); execute(); }}>Run again</button></p>
  {:else if data}
    <p class="note" class:stale={result.slot.pending}>
      {data.more ? `The first ${formatCount(SQL_ROW_LIMIT)} rows; add a WHERE or LIMIT to see others.` : `${formatCount(data.rows.length)} ${data.rows.length === 1 ? 'row' : 'rows'}`}
    </p>
  {/if}
  <div id="sql-result" class="grid" role="table" aria-label="Query result" aria-rowcount={(data?.rows.length ?? 0) + 1} aria-busy={result.slot.pending}
    data-rows={result.slot.pending || !data ? '' : data.rows.length} class:stale={result.slot.pending && data !== null}
    bind:clientHeight={height} onscroll={(e) => (scrollTop = e.currentTarget.scrollTop)}>
    {#if data}
      <div class="head" role="row" aria-rowindex="1" style:width={`${total}ch`}>
        {#each data.columns as column, i (i)}<span role="columnheader" class:num={numeric[i]} style:width={`${widths[i]}ch`} title={`${column.name} (${column.type})`}>{column.name}</span>{/each}
      </div>
      <div class="spacer" style:height={`${data.rows.length * ROW}px`} style:width={`${total}ch`}>
        {#each data.rows.slice(win.first, win.first + win.count) as row, i (win.first + i)}
          <div class="row" role="row" aria-rowindex={win.first + i + 2} style:top={`${(win.first + i) * ROW}px`} style:width={`${total}ch`}>
            {#each row as cell, j (j)}<span role="cell" class:num={numeric[j]} class:null={cell === null} style:width={`${widths[j]}ch`} title={cell ?? 'NULL'} aria-label={cell === null ? 'null value' : undefined}>{cell ?? 'NULL'}</span>{/each}
          </div>
        {/each}
      </div>
    {/if}
  </div>
</main>

<style>
  .sql { display: grid; grid-template-rows: auto auto auto minmax(0, 1fr); min-height: 0; padding: 16px 24px 0; background: var(--paper); min-width: 0; }
  header { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 16px; }
  h1 { margin: 0; font-size: var(--t-18); }
  .note { margin: 6px 0; color: var(--ink-2); font-size: var(--t-13); }
  .failure { color: var(--danger); }
  .top { display: grid; grid-template-columns: minmax(0, 1fr) 280px; gap: 16px; align-items: start; }
  textarea { width: 100%; min-height: 8lh; resize: vertical; font: 400 var(--t-13) / 1.5 var(--mono); color: var(--ink); background: var(--panel); border: 1px solid var(--rule); border-radius: var(--radius); padding: 8px 10px; box-sizing: border-box; }
  .actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 6px 0; }
  .actions button, .note button { min-height: 28px; padding: 3px 10px; background: none; border: 1px solid var(--rule); border-radius: var(--radius); cursor: pointer; }
  .hint { color: var(--ink-2); font-size: var(--t-12); }
  .tables { font-size: var(--t-13); max-height: 320px; overflow: auto; border: 1px solid var(--rule); border-radius: var(--radius); padding: 6px 10px; }
  .tables ul { list-style: none; margin: 0 0 6px; padding-left: 12px; }
  .insert { min-height: 24px; padding: 0; background: none; border: 0; color: var(--signal); font: 400 var(--t-12) / 1.4 var(--mono); cursor: pointer; text-align: left; }
  .count { color: var(--ink-2); font-size: var(--t-12); }
  .grid { font: 400 var(--t-13) / 28px var(--mono); position: relative; overflow: auto; min-height: 200px; border-top: 1px solid var(--rule); }
  .head { position: sticky; top: 0; z-index: 1; display: flex; height: 28px; background: var(--panel); border-bottom: 1px solid var(--rule); }
  .head span, .row span { flex: none; padding: 0 8px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; box-sizing: border-box; font: 400 var(--t-13) / 28px var(--mono); }
  .head span { font-weight: 600; }
  .spacer { position: relative; }
  .row { position: absolute; left: 0; display: flex; height: 28px; border-bottom: 1px solid color-mix(in srgb, var(--rule) 50%, transparent); }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .null { color: var(--ink-2); font-style: italic; }
  .stale { opacity: 0.5; }
  .visually-hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
  @media (max-width: 1100px) {
    .top { grid-template-columns: minmax(0, 1fr); }
  }
  @media (max-width: 720px) {
    .sql { padding: 12px 12px 0; }
  }
</style>
