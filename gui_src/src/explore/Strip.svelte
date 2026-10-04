<script lang="ts">
  import { onMount } from 'svelte';
  import type { Db } from '../engine/db';
  import { LEVELS } from '../engine/levels';
  import type { Manifest } from '../engine/manifest';
  import { isSuperseded } from '../engine/queries';
  import { run } from '../state/run.svelte';
  import { view } from '../state/view.svelte';
  import { pageTopLayer } from '../ui/layers';
  import { formatCount, isoTime } from '../ui/format';
  import {
    barHeight, binAt, type BinRow, type Bins, binSummary, DOMAIN_SQL, domainOf, formatRange, formatWidth, layout, rangeOf,
    type Series, stripRequest, stripSeries, timelessCount,
  } from './histogram';

  // The page's filters minus the time range: the strip draws time itself.
  let { db, manifest, where }: { db: Db; manifest: Manifest; where: string } = $props();

  const HEIGHT = 120;
  // Events rise above the line, detections hang below it on their own scale.
  const MID = 72;
  const UP = 64;
  const DOWN = 40;

  let canvas = $state<HTMLCanvasElement>();
  let width = $state(0);
  let domain = $state<[number, number] | null | undefined>(undefined);
  let series = $state.raw<Series | null>(null);
  let failure = $state<string | null>(null);
  let drag = $state<{ from: number; to: number } | null>(null);
  let hover = $state<number | null>(null);
  let cursor = $state<{ at: number; anchor: number } | null>(null);
  let paint = $state(0);
  let pending = $state(true);
  let ticket = 0;

  // A selected range zooms the strip into it, so a busy week can be narrowed to minutes; its end is exclusive.
  const span = $derived<[number, number] | null>(domain ? (view.t ? [view.t[0], view.t[1] - 1] : domain) : null);
  // Compared as text, so a resize that keeps the layout does not query again.
  const binsKey = $derived(span && width > 0 ? JSON.stringify(layout(span, Math.max(12, Math.floor(width / 4)))) : null);
  const bins = $derived<Bins | null>(binsKey ? JSON.parse(binsKey) : null);
  const timeless = $derived(timelessCount(manifest));
  const tip = $derived(series && hover !== null && hover < series.bins.count && !drag ? binSummary(series, hover, hover) : null);
  const announcement = $derived(series && cursor ? describe(binSummary(series, cursor.anchor, cursor.at)) : '');

  function describe(summary: ReturnType<typeof binSummary>): string {
    const found = LEVELS.flatMap((level, rank) => (summary.levels[rank] ? [`${formatCount(summary.levels[rank])} ${level}`] : []));
    const detections = found.length ? `; detections: ${found.reverse().join(', ')}` : '';
    return `${formatRange(summary.range)} UTC: ${formatCount(summary.events)} events${detections}`;
  }

  onMount(() => {
    let live = true;
    db.rows<{ lo: number | null; hi: number | null }>(DOMAIN_SQL).then(
      (rows) => {
        if (live) domain = domainOf(rows[0]);
      },
      (error: unknown) => {
        if (!isSuperseded(error)) failure = error instanceof Error ? error.message : String(error);
      },
    );
    const repaint = () => paint++;
    const observer = new MutationObserver(repaint);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    const scheme = matchMedia('(prefers-color-scheme: dark)');
    scheme.addEventListener('change', repaint);
    return () => {
      live = false;
      observer.disconnect();
      scheme.removeEventListener('change', repaint);
    };
  });

  // Each answer is drawn on the layout its own request was built for; an answer overtaken by a newer request is dropped.
  $effect(() => {
    void run.generation;
    if (!bins) return;
    const request = stripRequest(bins, where);
    const mine = ++ticket;
    pending = true;
    db.rows<BinRow>(request.sql, { lane: 'strip' }).then(
      (rows) => {
        if (mine !== ticket) return;
        pending = false;
        try {
          const next = stripSeries(request, rows);
          // Bin positions from the previous layout point at other times in this one.
          if (series?.bins !== next.bins) {
            cursor = null;
            hover = null;
          }
          series = next;
          failure = null;
        } catch (error) {
          failure = error instanceof Error ? error.message : String(error);
        }
      },
      (error: unknown) => {
        if (mine !== ticket) return;
        pending = false;
        failure = isSuperseded(error) ? null : error instanceof Error ? error.message : String(error);
      },
    );
  });

  $effect(() => {
    void paint;
    draw(canvas, width, series, drag, hover, cursor);
  });

  function draw(
    target: HTMLCanvasElement | undefined,
    w: number,
    s: Series | null,
    dragging: { from: number; to: number } | null,
    hovered: number | null,
    keyed: { at: number; anchor: number } | null,
  ): void {
    if (!target || w <= 0) return;
    const ratio = window.devicePixelRatio || 1;
    target.width = Math.round(w * ratio);
    target.height = HEIGHT * ratio;
    const ctx = target.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    ctx.clearRect(0, 0, w, HEIGHT);
    const style = getComputedStyle(target);
    const ink = (name: string) => style.getPropertyValue(name).trim();
    ctx.fillStyle = ink('--rule');
    ctx.fillRect(0, MID, w, 1);
    if (!s) return;
    const { bins: b, n, levels } = s;
    const step = w / b.count;
    const bar = Math.max(1, step - (step >= 3 ? 1 : 0));
    const totals = Array.from(n, (_, i) => levels.reduce((sum, counts) => sum + counts[i], 0));
    const maxN = n.reduce((m, v) => Math.max(m, v), 0);
    const maxD = totals.reduce((m, v) => Math.max(m, v), 0);
    ctx.fillStyle = ink('--strip');
    for (let i = 0; i < b.count; i++) {
      const h = barHeight(n[i], maxN, UP, 1);
      if (h) ctx.fillRect(i * step, MID - h, bar, h);
    }
    for (let i = 0; i < b.count; i++) {
      const total = totals[i];
      if (!total) continue;
      const h = barHeight(total, maxD, DOWN, 2);
      let y = MID + 2;
      // The most severe level sits nearest the line, where the eye lands first.
      for (let rank = levels.length - 1; rank >= 0; rank--) {
        const count = levels[rank][i];
        if (!count) continue;
        const segment = Math.max(2, (h * count) / total);
        ctx.fillStyle = ink(`--sev-${rank}`);
        ctx.fillRect(i * step, y, bar, segment);
        y += segment;
      }
    }
    const span = b.width * b.count;
    const xOf = (t: number) => Math.min(w, Math.max(0, ((t - b.start) / span) * w));
    // A committed range is not drawn: the strip is zoomed to it.
    const selected = dragging ? rangeOf(b, dragging.from, dragging.to) : keyed ? rangeOf(b, keyed.anchor, keyed.at) : null;
    if (selected) {
      const x0 = xOf(selected[0]);
      const x1 = xOf(selected[1]);
      ctx.fillStyle = ink('--signal');
      ctx.globalAlpha = 0.14;
      ctx.fillRect(x0, 0, Math.max(1, x1 - x0), HEIGHT);
      ctx.globalAlpha = 1;
      ctx.fillRect(x0, 0, 1, HEIGHT);
      ctx.fillRect(Math.max(x0, x1 - 1), 0, 1, HEIGHT);
    }
    if (hovered !== null && !dragging) {
      ctx.strokeStyle = ink('--ink-2');
      ctx.strokeRect(hovered * step + 0.5, 0.5, Math.max(1, bar - 1), HEIGHT - 1);
    }
  }

  function binOf(event: PointerEvent): number | null {
    if (!series || !canvas) return null;
    const rect = canvas.getBoundingClientRect();
    return binAt(event.clientX - rect.left, rect.width, series.bins.count);
  }

  function onpointerdown(event: PointerEvent): void {
    const bin = binOf(event);
    if (bin === null || !canvas) return;
    canvas.setPointerCapture(event.pointerId);
    cursor = null;
    drag = { from: bin, to: bin };
  }

  function onpointermove(event: PointerEvent): void {
    const bin = binOf(event);
    hover = bin;
    if (drag && bin !== null) drag = { ...drag, to: bin };
  }

  function onpointerup(): void {
    if (drag && series) view.t = rangeOf(series.bins, drag.from, drag.to);
    drag = null;
  }

  function onkeydown(event: KeyboardEvent): void {
    if (!series) return;
    const last = series.bins.count - 1;
    const start = cursor ?? { at: 0, anchor: 0 };
    const moveTo = (at: number) => {
      const next = Math.min(last, Math.max(0, at));
      cursor = { at: next, anchor: event.shiftKey ? start.anchor : next };
    };
    if (event.key === 'ArrowRight') moveTo(cursor ? start.at + 1 : 0);
    else if (event.key === 'ArrowLeft') moveTo(cursor ? start.at - 1 : last);
    else if (event.key === 'Home') moveTo(0);
    else if (event.key === 'End') moveTo(last);
    else if (event.key === 'Enter' && cursor) {
      view.t = rangeOf(series.bins, cursor.anchor, cursor.at);
      cursor = null;
    } else if (event.key === 'Escape' && !event.defaultPrevented && (cursor || view.t) && pageTopLayer() === null) {
      // The strip's selection is the lowest layer: an open panel above it takes the Escape.
      if (cursor) cursor = null;
      else view.t = null;
    } else return;
    event.preventDefault();
    event.stopPropagation();
  }
</script>

<section class="strip" aria-label="Events over time">
  {#if failure}
    <p class="note failure" role="alert">The histogram could not be drawn: {failure}</p>
  {:else if domain === null}
    <p class="note">No event in this package has a time, so there is nothing to draw here. Every event is still listed below.</p>
  {:else}
    <div class="plot dims" aria-busy={pending} bind:clientWidth={width}>
      <!-- svelte-ignore a11y_no_interactive_element_to_noninteractive_role -->
      <!-- A canvas has no native brush role; the key handler and live region make it operable. -->
      <canvas
        id="seismic-strip"
        bind:this={canvas}
        role="application"
        aria-roledescription="time brush"
        style:height={`${HEIGHT}px`}
        tabindex="0"
        aria-label="Event histogram. Drag, or use the arrow keys with Shift and press Enter, to select a time range and zoom into it. Escape clears it."
        aria-describedby="strip-legend"
        {onpointerdown}
        {onpointermove}
        {onpointerup}
        onpointercancel={() => (drag = null)}
        onpointerleave={() => (hover = null)}
        {onkeydown}
      ></canvas>
      {#if tip && hover !== null && series}
        <div class="tip" style:left={`${Math.min(85, (hover / series.bins.count) * 100)}%`}>{describe(tip)}</div>
      {/if}
    </div>
    <p class="visually-hidden" aria-live="polite">{announcement}</p>
    <div id="strip-legend" class="legend dims" aria-busy={pending}>
      <span>{series ? `${isoTime(series.bins.start, false)} UTC` : 'Reading event times'}</span>
      <span class="key">
        Events above the line, detections below it:
        {#each LEVELS as level, rank (level)}<span class="swatch"><i style:background={`var(--sev-${rank})`}></i>{level}</span>{/each}
      </span>
      {#if series}<span>Each bar is {formatWidth(series.bins.width)}</span>{/if}
      {#if timeless}<span>{formatCount(timeless)} events have no time and are not drawn</span>{/if}
      {#if view.t}<span class="zoomed">Zoomed to the selected range. Remove its chip to see the whole package.</span>{/if}
      <span class="end">{series ? `${isoTime(series.bins.start + series.bins.width * series.bins.count, false)} UTC` : ''}</span>
    </div>
  {/if}
</section>

<style>
  .strip { padding: 10px 16px 6px; background: var(--panel); border-bottom: 1px solid var(--rule); }
  .plot { position: relative; }
  canvas { display: block; width: 100%; cursor: crosshair; touch-action: none; }
  .tip { position: absolute; top: 4px; transform: translateX(8px); max-width: 26rem; padding: 4px 8px; font-size: var(--t-12); background: var(--paper); border: 1px solid var(--rule); border-radius: var(--radius); pointer-events: none; white-space: nowrap; }
  .legend { display: flex; flex-wrap: wrap; gap: 4px 16px; font-size: var(--t-12); color: var(--ink-2); margin-top: 4px; }
  .legend .end { margin-left: auto; }
  .zoomed { color: var(--signal); }
  .key { display: inline-flex; flex-wrap: wrap; gap: 4px 10px; align-items: center; }
  .swatch { display: inline-flex; align-items: center; gap: 4px; }
  .swatch i { display: inline-block; width: 8px; height: 8px; border-radius: 1px; }
  .note { margin: 4px 0; color: var(--ink-2); font-size: var(--t-13); }
  .failure { color: var(--danger); }
  .visually-hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
</style>
