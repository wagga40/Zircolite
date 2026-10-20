<script lang="ts">
  import type { Manifest } from '../engine/manifest';
  import { formatBytes, formatCount, formatElapsed, formatPercent, inputCount } from './format';
  import { BOOT_STEPS, type BootStep } from './loading';

  let { phase, loaded, total, failure, manifest }: {
    phase: BootStep;
    /** Bytes of the package's data loaded, of total. */
    loaded: number;
    total: number;
    failure: string | null;
    manifest: Manifest | null;
  } = $props();

  const current = $derived(BOOT_STEPS.indexOf(phase));

  // A step that takes its time says how long, so a large package does not look stuck.
  let started = $state(Date.now());
  let now = $state(Date.now());
  $effect(() => {
    void phase;
    started = Date.now();
    now = started;
  });
  $effect(() => {
    if (failure) return;
    const timer = setInterval(() => (now = Date.now()), 1000);
    return () => clearInterval(timer);
  });
</script>

<main class="loading">
  <h1>Zircolite</h1>
  {#if failure}
    <p class="failure" role="alert">{failure}</p>
  {:else}
    <p class="visually-hidden" aria-live="polite">{phase}</p>
    <ol class="steps" aria-label="Opening the package">
      {#each BOOT_STEPS as step, i (step)}
        <li class:done={i < current} class:current={i === current} aria-current={i === current ? 'step' : undefined}>
          <span class="mark" aria-hidden="true">{i < current ? '✓' : ''}</span>
          <span class="name">{step}</span>
          {#if i === current}
            {#if step === 'Loading the data' && total > 0}
              <span class="figure">{formatBytes(loaded)} of {formatBytes(total)}, {formatPercent(loaded / total)}</span>
            {:else if now - started >= 2000}
              <span class="figure">{formatElapsed(now - started)}</span>
            {/if}
          {/if}
        </li>
      {/each}
    </ol>
    {#if phase === 'Loading the data' && total > 0}
      <progress max={total} value={loaded} aria-label="Package data loaded"></progress>
    {:else}
      <div class="track" aria-hidden="true"><span class="sweep"></span></div>
    {/if}
  {/if}
  {#if manifest}
    <p class="meta">{formatCount(manifest.totals.events)} events from {formatCount(inputCount(manifest))} inputs</p>
  {/if}
</main>

<style>
  .loading { max-width: 36rem; margin: 18vh auto 0; padding: 0 16px; }
  h1 { font-size: var(--t-22); font-weight: 600; margin: 0 0 12px; }
  .meta { color: var(--ink-2); margin: 10px 0 6px; }
  .steps { list-style: none; margin: 0 0 12px; padding: 0; display: grid; gap: 4px; }
  .steps li { display: flex; align-items: baseline; gap: 8px; color: var(--ink-2); }
  .steps li.current { color: var(--ink); font-weight: 600; }
  .steps li.done { color: var(--ink-2); }
  .mark { width: 1.2em; flex: none; color: var(--signal); font-weight: 600; }
  .current .mark::before { content: '›'; color: var(--signal); }
  .figure { margin-left: auto; font-weight: 400; color: var(--ink-2); font-variant-numeric: tabular-nums; }
  progress { width: 100%; height: 6px; accent-color: var(--signal); }
  .track { position: relative; height: 6px; overflow: hidden; border-radius: 3px; background: color-mix(in srgb, var(--signal) 18%, transparent); }
  .sweep { position: absolute; top: 0; bottom: 0; left: 0; width: 30%; border-radius: 3px; background: var(--signal); animation: sweep 1.2s ease-in-out infinite; }
  @keyframes sweep { from { transform: translateX(-100%); } to { transform: translateX(340%); } }
  @media (prefers-reduced-motion: reduce) { .sweep { animation: none; width: 100%; opacity: 0.5; } }
  .visually-hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
  .failure { color: var(--danger); border-left: 3px solid var(--danger); padding: 6px 12px; background: var(--panel); }
</style>
