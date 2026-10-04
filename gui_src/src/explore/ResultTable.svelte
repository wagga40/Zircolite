<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import { isSuperseded } from '../engine/queries';
  import type { Field, Schema } from '../engine/schema';
  import { run, runAgain, stopAll } from '../state/run.svelte';
  import { view } from '../state/view.svelte';
  import { download } from '../ui/download';
  import { formatCount, isoTime, levelName } from '../ui/format';
  import { typing } from '../ui/keys';
  import { tick } from 'svelte';
  import { pageTopLayer } from '../ui/layers';
  import { ui } from '../ui/ui.svelte';
  import { csvExport, ExportTooLarge, jsonExport, limitNote, prepareExport } from './export';
  import { COUNT_SQL, ensureVisible, geometry, HEAD, HEIGHT_CAP, idsSql, nextPage, PAGE, pageSql, type PageRow, ROW, wheelDelta, wheelPosition } from './table';

  let { db, schema, manifest, where, columns, slow }: {
    db: Db;
    schema: Schema;
    manifest: Manifest;
    where: string;
    columns: Field[];
    /** Said in place of "Searching" when the search is known to take long. */
    slow: string | null;
  } = $props();

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
  let menuOpen = $state(false);
  let menu = $state<HTMLDetailsElement>();
  let cancelButton = $state<HTMLButtonElement>();
  let csvButton = $state<HTMLButtonElement>();
  let jsonButton = $state<HTMLButtonElement>();

  // The menu is a light dismiss: it never stays open beside the sheet or the drawer.
  function closeMenu(): void {
    if (menu) menu.open = false;
    menuOpen = false;
  }

  $effect(() => {
    if (menuOpen && (view.uid !== null || ui.fieldsOpen)) closeMenu();
  });

  $effect(() => {
    if (!menuOpen) return;
    // An outside touch lands wherever the person tapped, so focus is not pulled back to the summary.
    const outside = (event: PointerEvent) => {
      if (!menu?.contains(event.target as Node)) closeMenu();
    };
    window.addEventListener('pointerdown', outside, true);
    return () => window.removeEventListener('pointerdown', outside, true);
  });
  // The key of the one page request in flight; its end lets the next page go.
  let inflight = $state<string | null>(null);
  // Plain counters: tickets for the newest request, never read by the template.
  let build = 0;
  let cancel = false;
  // Pages that errored: cleared when the set of visible pages changes (one retry each) and on every rebuild.
  const failed = new Set<string>();
  // Pages a Stop cancelled: cleared only by a rebuild, which Run again triggers, so nothing re-requests after a stop.
  const stoppedPages = new Set<string>();
  // Whether the error on screen came from a page rather than a rebuild; a loaded page clears only its own kind.
  let pageFailure = false;
  // Unrounded wheel position, kept so 1 px trackpad deltas past the height cap are not rounded away.
  let wheelAt: number | null = null;

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
    void run.generation;
    // A new list is a new question; a stop belongs to the list it cancelled.
    run.stopped = false;
    const sql = idsSql(where, view.desc);
    const mine = ++build;
    busy = true;
    failure = null;
    pageFailure = false;
    void (async () => {
      try {
        await db.exec(sql, { lane: 'results' });
        const [counts] = await db.rows<{ n: number; d: number }>(COUNT_SQL, { cache: false, lane: 'results' });
        if (mine !== build) return;
        failed.clear();
        stoppedPages.clear();
        pages = new Map();
        total = counts.n;
        detected = counts.d;
        active = 0;
        follow = false;
        scrollTop = 0;
        if (scroller) scroller.scrollTop = 0;
        current = mine;
        busy = false;
      } catch (error) {
        if (mine !== build) return;
        // Rows and counts of the previous filter must not stay on screen under the new one.
        failed.clear();
        stoppedPages.clear();
        pages = new Map();
        total = 0;
        detected = 0;
        active = 0;
        follow = false;
        current = mine;
        failure = isSuperseded(error) ? null : message(error);
        pageFailure = false;
        busy = false;
      }
    })();
  });

  // A failed page is asked for again when the visible pages change, once per change; scrolling within them does not retry.
  const visiblePages = $derived(slice.count === 0 ? '' : `${Math.floor(slice.first / PAGE)}-${Math.floor((slice.first + slice.count - 1) / PAGE)}`);
  $effect(() => {
    void visiblePages;
    failed.clear();
  });

  // Load the pages the visible rows fall in, one request at a time: the
  // scheduler runs queries in order, so a fast scroll that asked for every
  // page it passed would keep the rows it stops on waiting behind them all.
  // A page requested while a newer list is being built would read that list,
  // so none is requested until it is ready.
  $effect(() => {
    if (inflight !== null || current === 0 || current !== build || total === 0) return;
    const page = nextPage(slice, (p) => pages.has(pageKey(p)) || failed.has(pageKey(p)) || stoppedPages.has(pageKey(p)));
    if (page === null) return;
    const fields = columns;
    const mine = current;
    const key = pageKey(page);
    inflight = key;
    const done = () => {
      if (inflight === key) inflight = null;
    };
    db.rows<PageRow>(pageSql(fields, page * PAGE, (page + 1) * PAGE), { cache: false, lane: 'page' }).then(
      (rows) => {
        if (mine === build && mine === current) {
          const next = new Map(pages);
          next.set(key, rows);
          for (const old of next.keys()) {
            if (next.size <= CACHED_PAGES) break;
            next.delete(old);
          }
          pages = next;
          if (pageFailure) {
            failure = null;
            pageFailure = false;
          }
        }
        done();
      },
      (error: unknown) => {
        if (mine === build) {
          // A step waiting for that page cannot land.
          follow = false;
          if (isSuperseded(error)) {
            stoppedPages.add(key);
          } else {
            failed.add(key);
            failure = message(error);
            pageFailure = true;
          }
        }
        done();
      },
    );
  });

  // Past the height cap one wheel notch would jump thousands of rows, so the scroll is stepped by rows.
  $effect(() => {
    const target = scroller;
    if (!target) return;
    const onwheel = (event: WheelEvent) => {
      if (event.ctrlKey || total * ROW <= HEIGHT_CAP) return;
      event.preventDefault();
      target.scrollLeft += event.deltaX;
      wheelAt = wheelPosition(wheelAt, target.scrollTop, wheelDelta(event, viewport), total, viewport);
      target.scrollTop = Math.round(wheelAt);
    };
    target.addEventListener('wheel', onwheel, { passive: false });
    return () => target.removeEventListener('wheel', onwheel);
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
    active = position;
    const row = rowAt(position);
    if (row) view.uid = row._zl_uid;
    // A row whose page is still loading opens as soon as it arrives, instead of the key press vanishing.
    else follow = true;
  }

  // The menu is a layer of its own: Escape closes it and nothing beneath it.
  function onmenukey(event: KeyboardEvent): void {
    if (event.key !== 'Escape' || event.defaultPrevented || pageTopLayer() !== 'menu') return;
    // The toggle event that feeds menuOpen is asynchronous, so a quick Escape would find it still false.
    closeMenu();
    menu?.querySelector('summary')?.focus();
    event.preventDefault();
  }

  function onwindowkey(event: KeyboardEvent): void {
    if (event.metaKey || event.ctrlKey || event.altKey || typing(event)) return;
    if ((event.target as Element | null)?.closest?.('dialog')) return;
    if (event.key === 'j') moveTo(active + 1);
    else if (event.key === 'k') moveTo(active - 1);
    else return;
    event.preventDefault();
  }

  function ongridkey(event: KeyboardEvent): void {
    // Keys from the header's sort button keep their own meaning.
    if (event.target !== scroller) return;
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
    if (exporting) return;
    // Set before the first await, so a second click cannot start another export.
    exporting = { done: 0, total: 0 };
    exportNote = null;
    cancel = false;
    // The button or menu item just used is replaced by "Cancel export"; keep the keyboard on the page.
    await tick();
    cancelButton?.focus();
    try {
      const count = await prepareExport(db);
      const refused = limitNote(kind, count);
      if (refused) {
        exportNote = refused;
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
      if (isSuperseded(error)) exportNote = 'Export stopped.';
      else exportNote = error instanceof ExportTooLarge ? error.message : `The export failed: ${message(error)}`;
    } finally {
      exporting = null;
      await tick();
      const active = document.activeElement;
      // Only restore focus that the export itself dropped; the person may have moved on.
      if (!active || active === document.body) {
        const narrowScreen = window.matchMedia('(max-width: 720px)').matches;
        const target = narrowScreen ? menu?.querySelector('summary') : kind === 'csv' ? csvButton : jsonButton;
        (target as HTMLElement | null | undefined)?.focus();
      }
    }
  }
</script>

<svelte:window onkeydown={(event) => { onmenukey(event); onwindowkey(event); }} />

<div class="table">
  <div class="bar">
    <button type="button" id="fields-toggle" class="fields-toggle" aria-expanded={ui.fieldsOpen} aria-controls="field-sidebar" onclick={() => (ui.fieldsOpen = !ui.fieldsOpen)}>Fields</button>
    {#if run.stopped && !busy}
      <p class="note stopped" role="status">The search was stopped. <button type="button" onclick={runAgain}>Run again</button></p>
    {:else}
      <output id="result-count" data-count={busy ? '' : total} data-detected={busy ? '' : detected} data-build={current} data-busy={busy} aria-live="polite">
        {#if busy && slow}<span class="slow">{slow}</span>{:else if busy}Searching{:else}{formatCount(total)} {total === 1 ? 'event' : 'events'}{#if detected}, {formatCount(detected)} with detections{/if}{/if}
      </output>
    {/if}
    {#if busy}<button type="button" onclick={() => stopAll(db)}>Stop</button>{/if}
    <button type="button" class="toggle" aria-pressed={view.d} onclick={() => (view.d = !view.d)}>Detections only</button>
    <span class="grow"></span>
    {#if exporting}
      <span class="progress" aria-live="polite">Exporting {formatCount(exporting.done)} of {formatCount(exporting.total)}</span>
      <button type="button" bind:this={cancelButton} onclick={() => (cancel = true)}>Cancel export</button>
    {:else}
      <span class="exports">
        <button type="button" bind:this={csvButton} disabled={busy || total === 0} onclick={() => runExport('csv')}
          title="The shown columns, one row per event. A cell starting with = + - or @ gets a leading ' so spreadsheets read it as text.">Export CSV</button>
        <button type="button" bind:this={jsonButton} disabled={busy || total === 0} onclick={() => runExport('json')}
          title="Every field of every event, one JSON object per line, for up to 100,000 events.">Export JSON</button>
      </span>
      <details class="export-menu" bind:open={menuOpen} bind:this={menu} onfocusout={(event) => { if (event.relatedTarget && !menu?.contains(event.relatedTarget as Node)) closeMenu(); }}>
        <summary>Export</summary>
        <div class="menu">
          <button type="button" disabled={busy || total === 0} onclick={() => { menuOpen = false; runExport('csv'); }}>CSV, the shown columns</button>
          <button type="button" disabled={busy || total === 0} onclick={() => { menuOpen = false; runExport('json'); }}>JSON, every field</button>
        </div>
      </details>
    {/if}
  </div>
  {#if exportNote}<p class="note" role="status">{exportNote}</p>{/if}
  {#if failure}<p class="note failure" role="alert">The results could not be read: {failure}. Change the search, or reload the page if this repeats.</p>{/if}

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
  .slow { font-weight: 400; color: var(--ink-2); }
  .grow { flex: 1; }
  .progress { font-size: var(--t-13); color: var(--ink-2); }
  .stopped { margin: 0; }
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
  .rows { position: absolute; inset: 0 0 auto 0; transition: opacity var(--motion); }
  /* Rows of the previous filter stay until the new list is ready. */
  .scroller[aria-busy='true'] .rows { opacity: 0.5; }
  .time { color: var(--ink-2); }
  .row > .level { display: flex; align-items: center; gap: 6px; font-family: var(--sans); }
  .level i { display: inline-block; width: 8px; height: 8px; border-radius: 1px; }
  .loading { color: var(--ink-2); }
  .empty { position: absolute; top: 56px; left: 16px; margin: 0; color: var(--ink-2); }
  .exports { display: inline-flex; gap: 8px; }
  .export-menu { display: none; position: relative; }
  .export-menu summary { min-height: 28px; padding: 3px 10px; border: 1px solid var(--rule); border-radius: var(--radius); cursor: pointer; list-style: none; }
  .export-menu .menu { position: absolute; right: 0; top: 100%; z-index: 10; display: grid; gap: 4px; margin-top: 4px; padding: 6px; background: var(--panel); border: 1px solid var(--rule); border-radius: var(--radius); white-space: nowrap; }
  @media (max-width: 720px) {
    .exports { display: none; }
    .export-menu { display: inline-block; }
    .fields-toggle { display: inline-block; }
  }
</style>
