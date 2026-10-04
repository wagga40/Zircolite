<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Field, Schema } from '../engine/schema';
  import { view } from '../state/view.svelte';
  import { download } from '../ui/download';
  import { formatCount, isoTime, levelName } from '../ui/format';
  import { typing } from '../ui/keys';
  import { ui } from '../ui/ui.svelte';
  import { csvExport, EXPORT_LIMIT, jsonExport, prepareExport } from './export';
  import { COUNT_SQL, ensureVisible, geometry, HEAD, idsSql, PAGE, pageSql, type PageRow, ROW } from './table';

  let { db, schema, manifest, where, columns }: { db: Db; schema: Schema; manifest: Manifest; where: string; columns: Field[] } = $props();

  const CACHED_PAGES = 40;
  const TIME_WIDTH = 224;
  const LEVEL_WIDTH = 112;
  const COLUMN_WIDTH = 160;

  let scroller = $state<HTMLDivElement>();
  let height = $state(0);
  let scrollTop = $state(0);
  let total = $state(0);
  let detected = $state(0);
  // The result list on screen; 0 until the first one is built.
  let current = $state(0);
  let busy = $state(true);
  let failure = $state<string | null>(null);
  let pages = $state.raw(new Map<string, PageRow[]>());
  let active = $state(0);
  let follow = $state(false);
  let exporting = $state<{ done: number; total: number } | null>(null);
  let exportNote = $state<string | null>(null);
  // Plain counters: tickets for the newest request, never read by the template.
  let build = 0;
  let cancel = false;
  const requested = new Set<string>();

  const viewport = $derived(Math.max(0, height - HEAD));
  const slice = $derived(geometry(total, viewport, scrollTop));
  const positions = $derived(Array.from({ length: slice.count }, (_, i) => slice.first + i));
  const signature = $derived(columns.map((field) => field.key).join('\u0000'));
  const template = $derived(`${TIME_WIDTH}px ${LEVEL_WIDTH}px ${columns.map(() => `minmax(${COLUMN_WIDTH}px, 1fr)`).join(' ')}`);
  const minWidth = $derived(TIME_WIDTH + LEVEL_WIDTH + columns.length * COLUMN_WIDTH);

  function message(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
  }

  function pageKey(page: number): string {
    return `${current}\u0001${signature}\u0001${page}`;
  }

  function rowAt(position: number): PageRow | undefined {
    return pages.get(pageKey(Math.floor(position / PAGE)))?.[position % PAGE];
  }

  // Rebuild the result list whenever the filters or the order change.
  $effect(() => {
    const sql = idsSql(where, view.desc);
    const mine = ++build;
    busy = true;
    failure = null;
    void (async () => {
      try {
        await db.exec(sql);
        const [counts] = await db.rows<{ n: number; d: number }>(COUNT_SQL, { cache: false });
        if (mine !== build) return;
        requested.clear();
        pages = new Map();
        total = counts.n;
        detected = counts.d;
        active = 0;
        scrollTop = 0;
        if (scroller) scroller.scrollTop = 0;
        current = mine;
        busy = false;
      } catch (error) {
        if (mine !== build) return;
        failure = message(error);
        busy = false;
      }
    })();
  });

  // Load the pages the visible rows fall in. A page requested while a newer
  // list is being built would read that list, so none is requested until it is ready.
  $effect(() => {
    if (current === 0 || current !== build || total === 0 || slice.count === 0) return;
    const fields = columns;
    const mine = current;
    const firstPage = Math.floor(slice.first / PAGE);
    const lastPage = Math.floor((slice.first + slice.count - 1) / PAGE);
    for (let page = firstPage; page <= lastPage; page++) {
      const key = pageKey(page);
      if (requested.has(key)) continue;
      requested.add(key);
      db.rows<PageRow>(pageSql(fields, page * PAGE, (page + 1) * PAGE), { cache: false }).then(
        (rows) => {
          if (mine !== build || mine !== current) return;
          const next = new Map(pages);
          next.set(key, rows);
          for (const old of next.keys()) {
            if (next.size <= CACHED_PAGES) break;
            next.delete(old);
            requested.delete(old);
          }
          pages = next;
        },
        (error: unknown) => {
          requested.delete(key);
          if (mine === build) failure = message(error);
        },
      );
    }
  });

  // With the event view open, j and k carry it along to the next event once its row has loaded.
  $effect(() => {
    if (!follow) return;
    const row = rowAt(active);
    if (row) {
      follow = false;
      view.uid = row._zl_uid;
    }
  });

  function moveTo(position: number): void {
    if (!total) return;
    active = Math.min(total - 1, Math.max(0, position));
    const next = ensureVisible(active, scrollTop, total, viewport);
    if (next !== scrollTop && scroller) {
      scroller.scrollTop = next;
      scrollTop = next;
    }
    if (view.uid !== null) follow = true;
  }

  function open(position: number): void {
    const row = rowAt(position);
    if (!row) return;
    active = position;
    view.uid = row._zl_uid;
  }

  function onwindowkey(event: KeyboardEvent): void {
    if (event.metaKey || event.ctrlKey || event.altKey || typing(event)) return;
    if (event.key === 'j') moveTo(active + 1);
    else if (event.key === 'k') moveTo(active - 1);
    else return;
    event.preventDefault();
  }

  function ongridkey(event: KeyboardEvent): void {
    const step = Math.max(1, Math.floor(viewport / ROW) - 1);
    if (event.key === 'ArrowDown') moveTo(active + 1);
    else if (event.key === 'ArrowUp') moveTo(active - 1);
    else if (event.key === 'PageDown') moveTo(active + step);
    else if (event.key === 'PageUp') moveTo(active - step);
    else if (event.key === 'Home') moveTo(0);
    else if (event.key === 'End') moveTo(total - 1);
    else if (event.key === 'Enter') open(active);
    else return;
    event.preventDefault();
    event.stopPropagation();
  }

  async function runExport(kind: 'csv' | 'json'): Promise<void> {
    exportNote = null;
    cancel = false;
    try {
      const count = await prepareExport(db);
      if (count > EXPORT_LIMIT) {
        exportNote = `An export holds at most ${formatCount(EXPORT_LIMIT)} events and these results have ${formatCount(count)}. Narrow the search or the time range first.`;
        return;
      }
      exporting = { done: 0, total: count };
      const progress = (done: number) => (exporting = { done, total: count });
      const parts =
        kind === 'csv'
          ? await csvExport(db, columns, count, progress, () => cancel)
          : await jsonExport(db, schema.fields, manifest, count, progress, () => cancel);
      if (parts === null) exportNote = 'Export cancelled.';
      else if (kind === 'csv') download('zircolite-events.csv', parts, 'text/csv;charset=utf-8');
      else download('zircolite-events.ndjson', parts, 'application/x-ndjson');
    } catch (error) {
      exportNote = `The export failed: ${message(error)}`;
    } finally {
      exporting = null;
    }
  }
</script>

<svelte:window onkeydown={onwindowkey} />

<div class="table">
  <div class="bar">
    <button type="button" id="fields-toggle" class="fields-toggle" aria-expanded={ui.fieldsOpen} aria-controls="field-sidebar" onclick={() => (ui.fieldsOpen = !ui.fieldsOpen)}>Fields</button>
    <output id="result-count" data-count={busy ? '' : total} data-detected={busy ? '' : detected} data-build={current} data-busy={busy} aria-live="polite">
      {#if busy}Searching{:else}{formatCount(total)} {total === 1 ? 'event' : 'events'}{#if detected}, {formatCount(detected)} with detections{/if}{/if}
    </output>
    <button type="button" class="toggle" aria-pressed={view.d} onclick={() => (view.d = !view.d)}>Detections only</button>
    <span class="grow"></span>
    {#if exporting}
      <span class="progress" aria-live="polite">Exporting {formatCount(exporting.done)} of {formatCount(exporting.total)}</span>
      <button type="button" onclick={() => (cancel = true)}>Cancel export</button>
    {:else}
      <button type="button" disabled={busy || total === 0} onclick={() => runExport('csv')}
        title="The shown columns, one row per event. A cell starting with = + - or @ gets a leading ' so spreadsheets read it as text.">Export CSV</button>
      <button type="button" disabled={busy || total === 0} onclick={() => runExport('json')}
        title="Every field of every event, one JSON object per line.">Export JSON</button>
    {/if}
  </div>
  {#if exportNote}<p class="note" role="status">{exportNote}</p>{/if}
  {#if failure}<p class="note failure" role="alert">The results could not be read: {failure}</p>{/if}

  <div
    id="result-grid"
    class="scroller"
    bind:this={scroller}
    bind:clientHeight={height}
    onscroll={() => (scrollTop = scroller?.scrollTop ?? 0)}
    role="grid"
    tabindex="0"
    aria-label="Events"
    aria-rowcount={total + 1}
    aria-colcount={columns.length + 2}
    aria-busy={busy}
    aria-activedescendant={total > 0 && active >= slice.first && active < slice.first + slice.count ? `row-${active}` : undefined}
    onkeydown={ongridkey}
  >
    <div class="row head" role="row" aria-rowindex={1} style:grid-template-columns={template} style:min-width={`${minWidth}px`}>
      <div role="columnheader" aria-sort={view.desc ? 'descending' : 'ascending'}>
        <button type="button" class="sort" onclick={() => (view.desc = !view.desc)}>Time (UTC) {view.desc ? '↓' : '↑'}</button>
      </div>
      <div role="columnheader">Level</div>
      {#each columns as field (field.key)}<div role="columnheader" class:num={field.type !== 'VARCHAR'} title={field.name}>{field.name}</div>{/each}
    </div>
    <div class="rows-space" style:height={`${slice.height}px`} style:min-width={`${minWidth}px`}>
      <div class="rows" style:transform={`translateY(${slice.top}px)`}>
        {#each positions as position (position)}
          {@const row = rowAt(position)}
          <!-- Rows are reached from the keyboard through the grid: arrow keys, j and k, then Enter. -->
          <!-- svelte-ignore a11y_click_events_have_key_events -->
          <div
            id={`row-${position}`}
            class="row"
            class:active={position === active}
            class:selected={row !== undefined && row._zl_uid === view.uid}
            role="row"
            aria-rowindex={position + 2}
            aria-selected={row !== undefined && row._zl_uid === view.uid}
            style:grid-template-columns={template}
            onclick={() => open(position)}
          >
            {#if row}
              <div role="gridcell" class="time">{isoTime(row._zl_t) || 'no time'}</div>
              <div role="gridcell" class="level">
                {#if row._zl_lvl !== null}<i style:background={`var(--sev-${row._zl_lvl})`}></i>{levelName(row._zl_lvl)}{/if}
              </div>
              {#each columns as field, i (field.key)}
                <div role="gridcell" class:num={field.type !== 'VARCHAR'} title={row[`_zl_v${i}`] ?? ''}>{row[`_zl_v${i}`] ?? ''}</div>
              {/each}
            {:else}
              <div role="gridcell" class="loading">Loading</div>
            {/if}
          </div>
        {/each}
      </div>
    </div>
    {#if !busy && total === 0 && !failure}
      <p class="empty">No events match. Remove a filter or change the search.</p>
    {/if}
  </div>
</div>

<style>
  .table { display: flex; flex-direction: column; min-height: 0; height: 100%; }
  .bar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 12px; padding: 8px 16px; border-bottom: 1px solid var(--rule); }
  .bar button { background: none; border: 1px solid var(--rule); border-radius: var(--radius); padding: 3px 10px; min-height: 24px; cursor: pointer; }
  .bar button:disabled { opacity: 0.5; cursor: default; }
  .toggle[aria-pressed='true'] { border-color: var(--signal); color: var(--signal); }
  .fields-toggle { display: none; }
  output { font-weight: 600; }
  .grow { flex: 1; }
  .progress { font-size: var(--t-13); color: var(--ink-2); }
  .note { margin: 6px 16px; font-size: var(--t-13); color: var(--ink-2); }
  .failure { color: var(--danger); }
  .scroller { position: relative; flex: 1; min-height: 0; overflow: auto; outline-offset: -2px; }
  .row { display: grid; height: 28px; align-items: center; border-bottom: 1px solid color-mix(in srgb, var(--rule) 55%, transparent); cursor: pointer; }
  .row > div { padding: 0 10px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font: 400 var(--t-13) / 28px var(--mono); }
  .row .num { text-align: right; }
  .row:hover { background: color-mix(in srgb, var(--signal) 6%, transparent); }
  .row.selected { background: color-mix(in srgb, var(--signal) 15%, transparent); }
  .scroller:focus-visible .row.active { box-shadow: inset 2px 0 0 var(--signal); }
  .head { position: sticky; top: 0; z-index: 2; height: 32px; background: var(--panel); cursor: default; border-bottom: 1px solid var(--rule); }
  .head > div { font: 600 var(--t-12) / 32px var(--sans); color: var(--ink-2); }
  .sort { background: none; border: 0; padding: 0; font: inherit; color: inherit; cursor: pointer; }
  .rows-space { position: relative; }
  .rows { position: absolute; inset: 0 0 auto 0; }
  .time { color: var(--ink-2); }
  .row > .level { display: flex; align-items: center; gap: 6px; font-family: var(--sans); }
  .level i { display: inline-block; width: 8px; height: 8px; border-radius: 1px; }
  .loading { color: var(--ink-2); }
  .empty { position: absolute; top: 56px; left: 16px; margin: 0; color: var(--ink-2); }
  @media (max-width: 720px) {
    .fields-toggle { display: inline-block; }
  }
</style>
