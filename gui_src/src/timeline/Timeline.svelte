<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import { LEVELS } from '../engine/levels';
  import { isSuperseded } from '../engine/queries';
  import type { Schema } from '../engine/schema';
  import { appendRaw } from '../search/edit';
  import { TIME_LIMIT } from '../state/hash';
  import type { QueryState } from '../state/query.svelte';
  import { run, runAgain } from '../state/run.svelte';
  import { view } from '../state/view.svelte';
  import { drag } from '../ui/drag';
  import { formatCount, isoTime, levelName } from '../ui/format';
  import { pageTopLayer } from '../ui/layers';
  import {
    bucketMs, EXTENT_SQL, formatTick, height, hit, LANE_GAP, LANE_H, laneLabel, lanes, type Mark, marksSql, padLeft,
    PAD_R, PAD_T, pan, type Placed, place, showFilter, type Span, ticks, zoomAt,
  } from './timeline';

  let { db, schema, manifest, query }: { db: Db; schema: Schema; manifest: Manifest; query: QueryState } = $props();

  const laneList = $derived(lanes(manifest.tactics));
  const canvasHeight = $derived(height(laneList.length));
  let canvas = $state<HTMLCanvasElement>();
  let width = $state(0);
  let extent = $state<Span | null | undefined>(undefined);
  let span = $state<Span | null>(null);
  let request = $state<{ span: Span; bucket: number } | null>(null);
  let marks = $state.raw<{ rows: Mark[]; from: number; bucket: number } | null>(null);
  let pinned = $state<Mark | null>(null);
  let pending = $state(true);
  let failure = $state<string | null>(null);
  let stopped = $state(false);
  let extentTicket = 0;
  let paint = $state(0);
  let ticket = 0;
  let settle: ReturnType<typeof setTimeout> | undefined;
  let sync: ReturnType<typeof setTimeout> | undefined;
  // The range this view last wrote, so its own write does not move the window back.
  let written: string | null = null;

  let listing = $state(false);
  const LIST_CAP = 500;
  // The marks in view by lane, for the list that stands in for the canvas on a keyboard or a screen reader.
  const listed = $derived.by(() => {
    const groups = laneList.flatMap((lane) => {
      const inLane = placed.filter((mark) => mark.lane === lane).sort((a, b) => a.first - b.first);
      return inLane.length ? [{ lane, marks: inLane, total: inLane.reduce((sum, mark) => sum + mark.n, 0) }] : [];
    });
    let room = LIST_CAP;
    const shown = groups.map((group) => {
      const marks = group.marks.slice(0, room);
      room -= marks.length;
      return { ...group, marks };
    });
    return { shown, count: placed.length };
  });
  const filtered = $derived(query.whereWithoutTime !== 'TRUE');
  const placed = $derived<Placed[]>(marks && span && width > 0 ? place(marks.rows, marks, span, laneList, width) : []);

  function message(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
  }

  function padded(e: Span): Span {
    const pad = (e.to - e.from) * 0.02;
    return { from: e.from - pad, to: e.to + pad };
  }

  // Read again on Run again, so a stop during the first read does not leave the view without a time range.
  $effect(() => {
    void run.generation;
    const mine = ++extentTicket;
    stopped = false;
    db.rows<{ lo: number | null; hi: number | null }>(EXTENT_SQL, { lane: 'timeline-extent' }).then(
      (rows) => {
        if (mine !== extentTicket) return;
        const row = rows[0];
        if (!row || row.lo === null || row.hi === null) {
          extent = null;
          return;
        }
        // A single instant still needs a window to draw.
        extent = row.hi > row.lo ? { from: row.lo, to: row.hi } : { from: row.lo - 1_800_000, to: row.hi + 1_800_000 };
      },
      (error: unknown) => {
        if (mine !== extentTicket) return;
        if (!isSuperseded(error)) failure = message(error);
        else if (run.stopped) stopped = true;
      },
    );
  });

  onMount(() => {
    const repaint = () => paint++;
    const observer = new MutationObserver(repaint);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    const scheme = matchMedia('(prefers-color-scheme: dark)');
    scheme.addEventListener('change', repaint);
    return () => {
      observer.disconnect();
      scheme.removeEventListener('change', repaint);
      clearTimeout(settle);
      clearTimeout(sync);
    };
  });

  // Ctrl or ⌘ with the wheel zooms; a bare wheel scrolls the page, so the timeline never traps it.
  $effect(() => {
    const target = canvas;
    if (!target) return;
    const onwheel = (event: WheelEvent) => {
      if (!span || !extent || !(event.ctrlKey || event.metaKey)) return;
      event.preventDefault();
      const rect = target.getBoundingClientRect();
      const step = Math.min(0.25, 0.05 + Math.abs(event.deltaY) / 600);
      commit(zoomAt(span, timeAt(event.clientX - rect.left), event.deltaY > 0 ? 1 + step : 1 / (1 + step), extent));
    };
    target.addEventListener('wheel', onwheel, { passive: false });
    return () => target.removeEventListener('wheel', onwheel);
  });

  // The window follows the page's time range when it changes elsewhere: a chip removed, Back, the strip.
  $effect(() => {
    if (!extent) return;
    const key = view.t ? `${view.t[0]}~${view.t[1]}` : null;
    if (key !== null && key === written) return;
    written = null;
    span = view.t ? { from: view.t[0], to: view.t[1] } : padded(extent);
  });

  // The marks are asked for once the window settles; meanwhile the marks already drawn move with it.
  $effect(() => {
    if (!span || width <= 0) return;
    const next = { span: { ...span }, bucket: bucketMs(span, width - padLeft(width) - PAD_R) };
    clearTimeout(settle);
    settle = setTimeout(() => (request = next), untrack(() => marks) ? 250 : 0);
  });

  $effect(() => {
    void run.generation;
    if (!request) return;
    const where = query.whereWithoutTime;
    const { span: frame, bucket } = request;
    const mine = ++ticket;
    pending = true;
    failure = null;
    stopped = false;
    let sql: string;
    try {
      sql = marksSql(frame, bucket, where);
    } catch (error) {
      pending = false;
      marks = null;
      failure = message(error);
      return;
    }
    db.rows<Mark>(sql, { lane: 'timeline' }).then(
      (rows) => {
        if (mine !== ticket) return;
        marks = { rows, from: Math.floor(frame.from), bucket };
        // A pinned count belongs to the marks it was read from.
        const kept = untrack(() => pinned);
        if (kept && !rows.some((m) => m.lane === kept.lane && m.uid === kept.uid && m.n === kept.n && m.first === kept.first && m.last === kept.last)) pinned = null;
        pending = false;
      },
      (error: unknown) => {
        if (mine !== ticket) return;
        pending = false;
        // Whatever is drawn belongs to an earlier filter, so it goes.
        marks = null;
        pinned = null;
        if (!isSuperseded(error)) failure = message(error);
        else if (run.stopped) stopped = true;
        else failure = 'the query was interrupted';
      },
    );
  });

  $effect(() => {
    void paint;
    draw(canvas, width, canvasHeight, span, placed, pinned, laneList);
  });

  function plotWidth(): number {
    return Math.max(1, width - padLeft(width) - PAD_R);
  }

  function timeAt(x: number): number {
    const s = span as Span;
    return s.from + ((x - padLeft(width)) / plotWidth()) * (s.to - s.from);
  }

  /** Move the window now, and make it the page's time range once the person stops. */
  function commit(next: Span): void {
    span = next;
    clearTimeout(sync);
    sync = setTimeout(() => {
      const t: [number, number] = [Math.floor(next.from), Math.ceil(next.to)];
      if (Math.abs(t[0]) > TIME_LIMIT || Math.abs(t[1]) > TIME_LIMIT) return;
      written = `${t[0]}~${t[1]}`;
      view.replaceNext = true;
      view.t = t;
    }, 400);
  }

  function everything(): void {
    if (!extent) return;
    clearTimeout(sync);
    written = null;
    span = padded(extent);
    view.t = null;
  }

  function zoomBy(factor: number): void {
    if (span && extent) commit(zoomAt(span, (span.from + span.to) / 2, factor, extent));
  }

  function onpointerdown(event: PointerEvent): void {
    if (!span || !extent || !canvas) return;
    const start = span;
    const bounds = extent;
    const scale = (start.to - start.from) / plotWidth();
    const target = canvas;
    drag(event, target, {
      move: (dx) => {
        span = pan(start, -dx * scale, bounds);
      },
      end: (dx) => commit(pan(start, -dx * scale, bounds)),
      click: (e) => {
        const rect = target.getBoundingClientRect();
        const mark = hit(placed, e.clientX - rect.left, e.clientY - rect.top);
        if (mark) pin(mark);
      },
      cancel: () => {
        span = start;
      },
    });
  }

  function onkeydown(event: KeyboardEvent): void {
    if (!span || !extent) return;
    const step = (span.to - span.from) / 10;
    if (event.key === 'ArrowLeft') commit(pan(span, -step, extent));
    else if (event.key === 'ArrowRight') commit(pan(span, step, extent));
    else if (event.key === '+' || event.key === '=') zoomBy(1 / 1.5);
    else if (event.key === '-') zoomBy(1.5);
    else if (event.key === '0') everything();
    else if (event.key === 'Escape' && pinned && !event.defaultPrevented && pageTopLayer() === null) pinned = null;
    else return;
    event.preventDefault();
    event.stopPropagation();
  }

  function pin(mark: Mark): void {
    pinned = mark;
    view.uid = mark.uid;
  }

  function showAll(mark: Mark): void {
    const filter = showFilter(mark);
    if (!filter) return;
    view.t = filter.t;
    view.q = appendRaw(view.q, filter.term);
    view.route = 'explore';
  }

  function trim(ctx: CanvasRenderingContext2D, text: string, max: number): string {
    if (ctx.measureText(text).width <= max) return text;
    let s = text;
    while (s.length > 1 && ctx.measureText(`${s}…`).width > max) s = s.slice(0, -1);
    return `${s}…`;
  }

  function draw(
    target: HTMLCanvasElement | undefined,
    w: number,
    h: number,
    s: Span | null,
    shown: Placed[],
    pin: Mark | null,
    names: string[],
  ): void {
    if (!target || w <= 0 || !s) return;
    const ratio = window.devicePixelRatio || 1;
    target.width = Math.round(w * ratio);
    target.height = Math.round(h * ratio);
    const ctx = target.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    ctx.clearRect(0, 0, w, h);
    const style = getComputedStyle(target);
    const ink = (name: string) => style.getPropertyValue(name).trim();
    const pad = padLeft(w);
    const plot = Math.max(1, w - pad - PAD_R);
    const bottom = PAD_T + names.length * (LANE_H + LANE_GAP);
    ctx.font = `12px ${ink('--sans') || 'sans-serif'}`;
    ctx.textBaseline = 'middle';
    names.forEach((lane, i) => {
      const y = PAD_T + i * (LANE_H + LANE_GAP);
      if (i % 2 === 0) {
        ctx.fillStyle = ink('--rule');
        ctx.globalAlpha = 0.35;
        ctx.fillRect(pad, y, plot, LANE_H);
        ctx.globalAlpha = 1;
      }
      ctx.fillStyle = ink('--ink-2');
      ctx.textAlign = 'right';
      ctx.fillText(trim(ctx, laneLabel(lane), pad - 16), pad - 10, y + LANE_H / 2);
    });
    const width = s.to - s.from;
    ctx.textAlign = 'center';
    ctx.strokeStyle = ink('--rule');
    ctx.lineWidth = 1;
    let labelEnd = -Infinity;
    for (const t of ticks(s)) {
      const x = Math.round(pad + ((t - s.from) / width) * plot) + 0.5;
      ctx.beginPath();
      ctx.moveTo(x, PAD_T);
      ctx.lineTo(x, bottom);
      ctx.stroke();
      // On a narrow canvas the gridlines stay but a label that would touch its neighbour is left out.
      const label = formatTick(t, width, s);
      const half = ctx.measureText(label).width / 2;
      if (x - half < labelEnd + 8 || x + half > w) continue;
      labelEnd = x + half;
      ctx.fillStyle = ink('--ink-2');
      ctx.fillText(label, x, bottom + 13);
    }
    // Overplotted on purpose: in a busy lane the pile of marks is the signal.
    for (const mark of shown) {
      ctx.fillStyle = ink(`--sev-${Math.max(0, mark.lvl)}`);
      ctx.globalAlpha = 0.85;
      ctx.beginPath();
      ctx.arc(mark.x, mark.y, mark.r, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.globalAlpha = 1;
    const ringed = pin ? shown.find((mark) => mark.lane === pin.lane && mark.uid === pin.uid) : undefined;
    if (ringed) {
      ctx.strokeStyle = ink('--signal');
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(ringed.x, ringed.y, ringed.r + 3, 0, Math.PI * 2);
      ctx.stroke();
    }
  }
</script>

<main class="timeline" aria-busy={pending}>
  <header class="bar">
    <h1 tabindex="-1">Timeline</h1>
    <div class="controls">
      <button type="button" onclick={() => zoomBy(1 / 1.5)}>Zoom in</button>
      <button type="button" onclick={() => zoomBy(1.5)}>Zoom out</button>
      <button type="button" onclick={everything}>Show everything</button>
    </div>
    <p class="note">Ctrl or ⌘ with the wheel zooms; drag to move. A mark holds the detections of one tactic within a few pixels of time{filtered ? ', under the current filters' : ''}.</p>
  </header>
  <output id="timeline-marks" hidden data-count={pending ? '' : placed.length}></output>
  {#if failure}
    <p class="note failure" role="alert">The timeline could not be drawn: {failure}. Change the search, or reload the page if this repeats.</p>
  {:else if stopped}
    <p class="note pad" role="status">Stopped. <button type="button" class="again" onclick={runAgain}>Run again</button></p>
  {:else if extent === null}
    <p class="note pad">No detection in this package has a time, so there is nothing to place on a timeline. Detections lists them all.</p>
  {:else}
    <div class="plot" class:stale={pending && marks !== null} aria-busy={pending} bind:clientWidth={width}>
      <!-- svelte-ignore a11y_no_interactive_element_to_noninteractive_role -->
      <!-- A canvas has no native role for this; the key handler and the note below make it operable. -->
      <canvas
        id="timeline-canvas"
        bind:this={canvas}
        role="application"
        aria-roledescription="timeline"
        tabindex="0"
        style:height={`${canvasHeight}px`}
        aria-label="Detections over time, one lane per ATT&CK tactic. Left and right arrows move, plus and minus zoom, 0 shows everything. Click a mark to open its earliest event."
        {onpointerdown}
        {onkeydown}
      ></canvas>
    </div>
    <p class="key dims" aria-busy={pending}>
      Mark colour is the highest detection level:
      {#each LEVELS as level, rank (level)}<span class="swatch"><i style:background={`var(--sev-${rank})`}></i>{level}</span>{/each}
    </p>
    <div class="list" class:stale={pending && marks !== null} aria-busy={pending}>
      <button type="button" class="toggle" aria-expanded={listing} aria-controls="timeline-list" onclick={() => (listing = !listing)}>List the marks</button>
      {#if listing}
        <div id="timeline-list">
          {#if listed.count === 0}
            <p class="note">No marks in this window.</p>
          {:else}
            {#each listed.shown as group (group.lane)}
              {#if group.marks.length}
                <h2>{laneLabel(group.lane)}, {formatCount(group.total)} {group.total === 1 ? 'detection' : 'detections'}</h2>
                <ul>
                  {#each group.marks as mark (`${mark.lane}:${mark.b}`)}
                    <li>
                      <button type="button" class="mark" onclick={() => pin(mark)}>
                        {isoTime(mark.first)} to {isoTime(mark.last)} UTC, {formatCount(mark.n)} {mark.n === 1 ? 'event' : 'events'}, highest level {levelName(mark.lvl) ?? 'unknown'}
                      </button>
                    </li>
                  {/each}
                </ul>
              {/if}
            {/each}
            {#if listed.count > LIST_CAP}<p class="note">First {LIST_CAP} of {formatCount(listed.count)} marks. Zoom in to list the rest.</p>{/if}
          {/if}
        </div>
      {/if}
    </div>
    {#if pinned}
      <p class="pinned" role="status">
        {formatCount(pinned.n)} {pinned.n === 1 ? 'event' : 'events'} under {laneLabel(pinned.lane)}, highest level {levelName(pinned.lvl) ?? 'unknown'},
        from {isoTime(pinned.first)} to {isoTime(pinned.last)} UTC. The drawer shows the earliest.
        {#if pinned.n > 1 && pinned.lane}<button type="button" onclick={() => pinned && showAll(pinned)}>Show these {formatCount(pinned.n)} in Explore</button>
        {:else if pinned.n > 1}Rules without a tactic have no search term, so Explore cannot list exactly these.{/if}
      </p>
    {/if}
  {/if}
</main>

<style>
  .timeline { min-height: 0; overflow: auto; background: var(--paper); }
  .bar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 16px; padding: 12px 16px; background: var(--panel); border-bottom: 1px solid var(--rule); }
  h1 { margin: 0; font-size: var(--t-18); }
  .controls { display: flex; gap: 6px; }
  .controls button, .pinned button, .again { min-height: 28px; background: none; border: 1px solid var(--rule); border-radius: var(--radius); padding: 3px 10px; cursor: pointer; }
  .plot { padding: 12px 16px; }
  canvas { display: block; width: 100%; cursor: grab; touch-action: pan-y; }
  .stale { opacity: 0.5; transition: opacity var(--motion); }
  .note { margin: 0; color: var(--ink-2); font-size: var(--t-13); }
  .pad { margin: 12px 16px; }
  .pinned button { display: block; margin-top: 8px; }
  /* The open drawer covers the right 560px, and the pinned mark's note must stay clear of it. */
  @media (min-width: 1000px) { .pinned { max-width: calc(100% - 592px); } }
  .pinned { margin: 0 16px 16px; padding: 8px 12px; border-left: 3px solid var(--signal); background: var(--panel); font-size: var(--t-13); }
  .key { display: flex; flex-wrap: wrap; align-items: center; gap: 4px 10px; margin: 0 16px 8px; font-size: var(--t-12); color: var(--ink-2); }
  .swatch { display: inline-flex; align-items: center; gap: 4px; }
  .swatch i { display: inline-block; width: 8px; height: 8px; border-radius: 50%; }
  .list { margin: 0 16px 12px; font-size: var(--t-13); }
  .toggle { min-height: 28px; background: none; border: 1px solid var(--rule); border-radius: var(--radius); padding: 3px 10px; cursor: pointer; }
  .list h2 { margin: 12px 0 4px; font-size: var(--t-13); font-weight: 600; }
  .list ul { margin: 0; padding: 0; list-style: none; }
  .mark { display: block; width: 100%; min-height: 28px; text-align: left; background: none; border: 0; border-bottom: 1px solid var(--rule); padding: 3px 4px; cursor: pointer; font-variant-numeric: tabular-nums; }
  .failure { color: var(--danger); margin: 12px 16px; }
</style>
