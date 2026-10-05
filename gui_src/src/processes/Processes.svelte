<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Schema } from '../engine/schema';
  import { levelLabel } from '../detections/rules';
  import { fieldTerm } from '../search/edit';
  import type { QueryState } from '../state/query.svelte';
  import { run, runAgain } from '../state/run.svelte';
  import { view } from '../state/view.svelte';
  import { formatCount, isoTime } from '../ui/format';
  import { Panel } from '../ui/panel.svelte';
  import { ownScope } from '../ui/scope';
  import { windowOf } from '../ui/virtual';
  import { ancestorsSql, creationPredicate, PROCESS_LIMIT, processCountSql, processRowsSql } from './processes';
  import { basename, buildForest, type Process, type RawProcess, type Row, toProcess, visibleRows, withChildren } from './tree';

  let { db: page, schema, manifest, query }: { db: Db; schema: Schema; manifest: Manifest; query: QueryState } = $props();
  // svelte-ignore state_referenced_locally
  const db = ownScope(page, 'processes');
  const ROW = 28;

  interface Tree { roots: Process[]; starts: number; shown: number; context: number; nodes: number }
  const tree = new Panel<Tree>();
  const findable = $derived(creationPredicate(schema) !== null);
  const guidField = $derived(schema.find('ProcessGuid'));
  let expanded = $state.raw<Set<number>>(new Set());
  let active = $state<number | null>(null);
  let scrollTop = $state(0);
  let height = $state(0);
  let list = $state<HTMLElement>();
  let seen: Tree | null = null;

  $effect(() => {
    void run.generation;
    const where = query.where;
    if (!findable) return;
    tree.load(async () => {
      const [count] = await db.rows<{ n: number }>(processCountSql(schema, where) as string, { lane: 'tree' });
      const rows = await db.rows<RawProcess>(processRowsSql(schema, where) as string, { lane: 'tree' });
      const ancestors = ancestorsSql(schema, where);
      const context = ancestors ? await db.rows<RawProcess>(ancestors, { lane: 'tree' }) : [];
      const roots = buildForest([...rows, ...context].map(toProcess));
      return { roots, starts: count?.n ?? 0, shown: rows.length, context: context.length, nodes: rows.length + context.length };
    });
  });

  // A new answer opens small trees whole and large ones at their roots.
  $effect(() => {
    const data = tree.slot.data;
    if (!data || data === seen) return;
    seen = data;
    expanded = new Set(data.nodes <= 300 ? withChildren(data.roots) : data.roots.filter((r) => r.children.length).map((r) => r.uid));
    active = null;
  });

  const rows = $derived(tree.slot.data ? visibleRows(tree.slot.data.roots, expanded) : []);
  const win = $derived(windowOf(scrollTop, height, rows.length, ROW));
  const index = $derived(active === null ? -1 : rows.findIndex((r) => r.process.uid === active));
  const current = $derived(index >= 0 ? rows[index].process : null);
  const filtered = $derived(query.where !== 'TRUE');

  function setExpanded(uid: number, open: boolean): void {
    const next = new Set(expanded);
    if (open) next.add(uid);
    else next.delete(uid);
    expanded = next;
  }

  function focusRow(i: number): void {
    if (i < 0 || i >= rows.length) return;
    active = rows[i].process.uid;
    if (!list) return;
    const top = i * ROW;
    if (top < list.scrollTop) list.scrollTop = top;
    else if (top + ROW > list.scrollTop + list.clientHeight) list.scrollTop = top + ROW - list.clientHeight;
  }

  function choose(row: Row): void {
    active = row.process.uid;
    // Rows take focus on click; the tree owns the keyboard, so give it back.
    list?.focus();
    view.uid = row.process.uid;
  }

  function onkeydown(event: KeyboardEvent): void {
    const i = index < 0 ? 0 : index;
    const row = rows[i];
    if (!row) return;
    if (event.key === 'ArrowDown') focusRow(i + 1);
    else if (event.key === 'ArrowUp') focusRow(i - 1);
    else if (event.key === 'Home') focusRow(0);
    else if (event.key === 'End') focusRow(rows.length - 1);
    else if (event.key === 'ArrowRight') {
      if (row.expandable && !row.expanded) setExpanded(row.process.uid, true);
      else if (row.expanded) focusRow(i + 1);
    } else if (event.key === 'ArrowLeft') {
      if (row.expanded) setExpanded(row.process.uid, false);
      else if (row.process.parent) focusRow(rows.findIndex((r) => r.process === row.process.parent));
    } else if (event.key === 'Enter') choose(row);
    else return;
    event.preventDefault();
  }

  function eventsOf(process: Process): void {
    if (!guidField || !process.guid) return;
    view.q = fieldTerm(guidField.name, process.guid);
    view.t = null;
    view.d = false;
    view.route = 'explore';
  }

  const ink = (lvl: number) => `var(--sev-${Math.max(0, lvl)})`;
</script>

<main class="processes">
  <header>
    <h1 tabindex="-1">Processes</h1>
    {#if tree.slot.data && !tree.slot.pending}
      <output>{formatCount(tree.slot.data.starts)} process {tree.slot.data.starts === 1 ? 'start' : 'starts'}{filtered ? ' under the current filters' : ''}</output>
    {/if}
    <span class="actions">
      <button type="button" disabled={!tree.slot.data} onclick={() => (expanded = new Set(withChildren(tree.slot.data?.roots ?? [])))}>Expand all</button>
      <button type="button" disabled={!tree.slot.data} onclick={() => (expanded = new Set())}>Collapse all</button>
      {#if current?.guid && guidField}<button type="button" onclick={() => current && eventsOf(current)}>Events of this process</button>{/if}
      {#if tree.slot.stopped}<button type="button" onclick={runAgain}>Run again</button>{/if}
    </span>
  </header>

  {#if !findable}
    <p class="note">This package has no Channel and EventID fields, so process starts cannot be told apart.</p>
  {:else if tree.slot.failure}
    <p class="note failure" role="alert">The processes could not be read: {tree.slot.failure}. Change the search, or reload the page if this repeats.</p>
  {:else if tree.slot.stopped}
    <p class="note" role="status">Stopped.</p>
  {:else}
    {#if tree.slot.data && tree.slot.data.starts > tree.slot.data.shown}
      <p class="note">The filters keep {formatCount(tree.slot.data.starts)} process starts; the tree shows the first {formatCount(PROCESS_LIMIT)} by start time. Narrow the search or the time range to see the rest.</p>
    {/if}
    {#if tree.slot.data?.context}<p class="note">Grey rows are ancestors outside the filters, found by ProcessGuid.</p>{/if}
    {#if !guidField}<p class="note">This package has no ProcessGuid field, so processes link by host, parent PID and start time.</p>{/if}
    <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
    <div id="process-tree" class="tree" role="tree" aria-label="Process starts" tabindex="0"
      aria-activedescendant={active === null ? undefined : `proc-${active}`}
      data-starts={tree.slot.pending || !tree.slot.data ? '' : tree.slot.data.starts}
      data-shown={tree.slot.pending || !tree.slot.data ? '' : tree.slot.data.shown}
      class:stale={tree.slot.pending && tree.slot.data !== null} aria-busy={tree.slot.pending}
      bind:this={list} bind:clientHeight={height} onscroll={(e) => (scrollTop = e.currentTarget.scrollTop)} {onkeydown}>
      <div class="spacer" style:height={`${rows.length * ROW}px`}>
        {#each rows.slice(win.first, win.first + win.count) as row, i (row.process.uid)}
          <!-- svelte-ignore a11y_click_events_have_key_events -->
          <div id={`proc-${row.process.uid}`} data-uid={row.process.uid} role="treeitem" aria-level={row.depth + 1}
            aria-setsize={row.setsize} aria-posinset={row.posinset} aria-expanded={row.expandable ? row.expanded : undefined}
            aria-selected={row.process.uid === active} tabindex="-1" class="row" class:context={row.process.context} class:active={row.process.uid === active}
            style:top={`${(win.first + i) * ROW}px`} onclick={() => choose(row)}>
            <span class="name" style:padding-left={`${row.depth * 16}px`}>
              <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
              <span class="chev" aria-hidden="true" onclick={(e) => { e.stopPropagation(); if (row.expandable) setExpanded(row.process.uid, !row.expanded); }}>{row.expandable ? (row.expanded ? '▾' : '▸') : ''}</span>
              <span class="image">{basename(row.process.image) || 'unknown image'}</span>
              {#if row.process.commandLine}<span class="cmd">{row.process.commandLine}</span>{/if}
            </span>
            <span class="pid">{row.process.pid ?? ''}</span>
            <span class="user">{row.process.user ?? ''}</span>
            <span class="host">{row.process.host ?? ''}</span>
            <span class="time">{row.process.t === null ? 'No time' : isoTime(row.process.t, false)}</span>
            <span class="badge">
              {#if row.process.lvl !== null}<i style:background={ink(row.process.lvl)}></i>{levelLabel(row.process.lvl)}, {formatCount(row.process.hits)}{/if}
            </span>
          </div>
        {/each}
      </div>
      {#if tree.slot.data && rows.length === 0}<p class="note empty">No process starts (Sysmon event 1 or Security event 4688) match the filters.</p>{/if}
    </div>
  {/if}
</main>

<style>
  .processes { display: grid; grid-template-rows: auto auto minmax(0, 1fr); min-height: 0; padding: 16px 24px 0; background: var(--paper); min-width: 0; }
  header { display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px 16px; }
  h1 { margin: 0; font-size: var(--t-18); }
  output { font-weight: 600; }
  .actions { display: inline-flex; flex-wrap: wrap; gap: 6px; }
  .actions button { min-height: 28px; padding: 3px 10px; background: none; border: 1px solid var(--rule); border-radius: var(--radius); cursor: pointer; }
  .note { margin: 6px 0; color: var(--ink-2); font-size: var(--t-13); }
  .failure { color: var(--danger); }
  .tree { position: relative; overflow: auto; min-height: 240px; border-top: 1px solid var(--rule); margin-top: 8px; }
  .tree:focus-visible { outline: 2px solid var(--signal); outline-offset: -2px; }
  .spacer { position: relative; min-width: 900px; }
  .row { position: absolute; left: 0; right: 0; height: 28px; display: grid; grid-template-columns: minmax(0, 1fr) 64px 160px 160px 190px 120px; gap: 8px; align-items: center; padding: 0 8px; border-bottom: 1px solid color-mix(in srgb, var(--rule) 50%, transparent); cursor: pointer; font-size: var(--t-13); }
  .row.active { background: color-mix(in srgb, var(--signal) 14%, transparent); }
  .row.context { opacity: 0.55; }
  .name { display: flex; align-items: center; gap: 6px; min-width: 0; white-space: nowrap; overflow: hidden; }
  .chev { flex: none; width: 16px; text-align: center; color: var(--ink-2); }
  .image { font-family: var(--mono); }
  .cmd { font: 400 var(--t-12) / 1 var(--mono); color: var(--ink-2); overflow: hidden; text-overflow: ellipsis; }
  .pid { font-variant-numeric: tabular-nums; text-align: right; }
  .user, .host { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .time { font-family: var(--mono); white-space: nowrap; }
  .badge { display: inline-flex; align-items: center; gap: 4px; white-space: nowrap; }
  .badge i { width: 8px; height: 8px; border-radius: 1px; display: inline-block; }
  .empty { padding: 12px; }
  .stale { opacity: 0.5; }
  @media (max-width: 720px) {
    .processes { padding: 12px 12px 0; }
    .spacer { min-width: 0; }
    .row { grid-template-columns: minmax(0, 1fr) 56px 96px; }
    .user, .host, .time { display: none; }
  }
</style>
