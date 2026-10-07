<script lang="ts">
  import type { Manifest } from '../engine/manifest';
  import { formatCount, inputCount } from './format';

  let { phase, loaded, total, failure, manifest }: {
    phase: string;
    loaded: number;
    total: number;
    failure: string | null;
    manifest: Manifest | null;
  } = $props();
</script>

<main class="loading">
  <h1>Zircolite</h1>
  {#if failure}
    <p class="failure" role="alert">{failure}</p>
  {:else}
    <p class="phase" aria-live="polite">{phase}</p>
    {#if total > 0}
      <progress max={total} value={loaded} aria-label="Package files loaded"></progress>
    {/if}
  {/if}
  {#if manifest}
    <p class="meta">{formatCount(manifest.totals.events)} events from {formatCount(inputCount(manifest))} inputs</p>
  {/if}
</main>

<style>
  .loading { max-width: 36rem; margin: 18vh auto 0; padding: 0 16px; }
  h1 { font-size: var(--t-22); font-weight: 600; margin: 0 0 12px; }
  .phase, .meta { color: var(--ink-2); margin: 6px 0; }
  progress { width: 100%; height: 6px; accent-color: var(--signal); }
  .failure { color: var(--danger); border-left: 3px solid var(--danger); padding: 6px 12px; background: var(--panel); }
</style>
