<script lang="ts">
  import { onDestroy } from 'svelte';
  import type { Db } from '../engine/db';
  import { textIndex } from '../engine/textIndex.svelte';
  import { run, stopAll } from '../state/run.svelte';
  import { activity, activityText, BusyClock } from './busy.svelte';
  import { formatElapsed, formatPercent } from './format';

  let { db }: { db: Db } = $props();

  const clock = new BusyClock();
  onDestroy(() => clock.dispose());
  $effect(() => clock.set(activity.queries > 0));

  let now = $state(Date.now());
  $effect(() => {
    if (!clock.shown) return;
    now = Date.now();
    const timer = setInterval(() => (now = Date.now()), 1000);
    return () => clearInterval(timer);
  });

  const text = $derived(activityText(activity, textIndex));
  const elapsed = $derived(clock.since === null ? 0 : now - clock.since);
  const stoppable = $derived(run.ownStops === 0);
</script>

{#if clock.shown}
  <div id="page-busy" class="busy">
    <div class="track" aria-hidden="true">
      {#if text.fraction === null}<span class="sweep"></span>{:else}<span class="fill" style:width={`${text.fraction * 100}%`}></span>{/if}
    </div>
    <div class="pill">
      <span role="status">{text.label}</span>
      {#if text.fraction !== null}<span class="figure" aria-hidden="true">{formatPercent(text.fraction)}</span>{/if}
      {#if elapsed >= 1000}<span class="figure time" aria-hidden="true">{formatElapsed(elapsed)}</span>{/if}
      {#if stoppable}<button type="button" onclick={() => stopAll(db)} title="Stop every query of the page">Stop</button>{/if}
    </div>
  </div>
{/if}

<style>
  /*
   * Over the view rather than in its flow, so the page does not move when it shows: the bar along its top, the
   * words at the foot, clear of the headers where the views keep their buttons.
   */
  .busy { position: absolute; inset: 0; z-index: 12; pointer-events: none; }
  .track { position: absolute; top: 0; left: 0; right: 0; height: 3px; overflow: hidden; background: color-mix(in srgb, var(--signal) 18%, transparent); }
  .fill, .sweep { position: absolute; top: 0; bottom: 0; left: 0; background: var(--signal); }
  .fill { transition: width 200ms ease-out; }
  .sweep { width: 30%; animation: sweep 1.2s ease-in-out infinite; }
  @keyframes sweep { from { transform: translateX(-100%); } to { transform: translateX(340%); } }
  .pill {
    position: absolute; bottom: 16px; left: 50%; transform: translateX(-50%); pointer-events: auto; width: max-content; max-width: calc(100% - 32px);
    display: flex; align-items: center; gap: 10px;
    padding: 4px 6px 4px 12px; background: var(--panel); color: var(--ink); border: 1px solid var(--rule); border-radius: 999px;
    box-shadow: 0 2px 12px rgb(0 0 0 / 0.16); font-size: var(--t-13);
  }
  .figure { color: var(--ink-2); font-variant-numeric: tabular-nums; }
  .pill:not(:has(button)) { padding-right: 12px; }
  button { min-height: 24px; padding: 1px 10px; background: none; border: 1px solid var(--rule); border-radius: 999px; cursor: pointer; color: var(--ink); font: inherit; }
  /* Still there, still filling, without the movement. */
  @media (prefers-reduced-motion: reduce) {
    .sweep { animation: none; width: 100%; opacity: 0.5; }
    .fill { transition: none; }
  }
</style>
