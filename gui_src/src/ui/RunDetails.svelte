<script lang="ts">
  import type { Manifest } from '../engine/manifest';
  import { formatCount, inputCount, isoTime, timeRange } from './format';

  let { manifest, detected }: { manifest: Manifest; detected: number | null } = $props();
  let dialog: HTMLDialogElement;

  export function open(): void {
    dialog.showModal();
  }

  const range = $derived(timeRange(manifest.parts));
  const made = $derived(Date.parse(manifest.created));
  const partial = $derived(manifest.parts.filter((p) => p.status === 'partial'));
</script>

<dialog bind:this={dialog} aria-labelledby="run-title">
  <form method="dialog" class="head">
    <h2 id="run-title">Run details</h2>
    <button type="submit" aria-label="Close run details">Close</button>
  </form>
  <dl>
    <dt>Events</dt><dd>{formatCount(manifest.totals.events)}</dd>
    <dt>Inputs</dt><dd>{formatCount(inputCount(manifest))}</dd>
    <dt>Time range</dt><dd>{range}</dd>
    <dt>Rules that matched</dt><dd>{formatCount(manifest.totals.rules_matched)} of {formatCount(manifest.run.rules_loaded)} loaded</dd>
    <dt>Rule matches</dt><dd>{formatCount(manifest.totals.hits)}</dd>
    <dt>Events with detections</dt><dd>{detected === null ? 'Counting' : formatCount(detected)}</dd>
    <dt>Correlation alerts</dt><dd>{formatCount(manifest.totals.alerts)}</dd>
    <dt>Processing</dt><dd>{manifest.run.mode}, {manifest.run.executor}</dd>
    <dt>Time field</dt><dd>{manifest.run.time_field || 'none'}</dd>
    <dt>Event filtering</dt><dd>{manifest.run.event_filter}</dd>
    <dt>Made by</dt><dd>Zircolite {manifest.zircolite}{Number.isNaN(made) ? '' : ` on ${isoTime(made, false)} UTC`}</dd>
  </dl>
  {#if manifest.warnings.length}
    <h3>Warnings</h3>
    <ul>{#each manifest.warnings as warning}<li>{warning}</li>{/each}</ul>
  {/if}
  {#if manifest.failed_sources.length}
    <h3>Inputs that failed</h3>
    <ul class="mono">{#each manifest.failed_sources as source}<li>{source}</li>{/each}</ul>
  {/if}
  {#if partial.length}
    <h3>Inputs read only in part</h3>
    <ul class="mono">{#each partial.flatMap((p) => p.unreadable) as source}<li>{source}</li>{/each}</ul>
  {/if}
</dialog>

<style>
  dialog { width: min(40rem, calc(100vw - 32px)); border: 1px solid var(--rule); border-radius: var(--radius); background: var(--panel); color: var(--ink); padding: 20px 24px; }
  dialog::backdrop { background: rgb(0 0 0 / 0.35); }
  .head { display: flex; justify-content: space-between; align-items: baseline; margin: 0 0 12px; }
  h2 { font-size: var(--t-18); margin: 0; }
  h3 { font-size: var(--t-15); margin: 18px 0 6px; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 0; }
  dt { color: var(--ink-2); }
  dd { margin: 0; }
  ul { margin: 0; padding-left: 18px; }
  .mono { font-family: var(--mono); font-size: var(--t-13); }
  button { background: none; border: 1px solid var(--rule); border-radius: var(--radius); padding: 2px 10px; cursor: pointer; }
</style>
