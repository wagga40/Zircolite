<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Schema } from '../engine/schema';
  import type { QueryState } from '../state/query.svelte';
  import RunDetails from './RunDetails.svelte';
  import SearchBar from './SearchBar.svelte';
  import { applyTheme, loadTheme, nextTheme, type Theme } from './theme';

  let { db, schema, manifest, detected, query }: { db: Db; schema: Schema; manifest: Manifest; detected: number | null; query: QueryState } = $props();
  let theme = $state<Theme>(loadTheme());
  let details: RunDetails;
  const warnings = $derived(manifest.warnings.length);
  const LABEL: Record<Theme, string> = { system: 'Auto', light: 'Light', dark: 'Dark' };

  $effect(() => applyTheme(theme));
</script>

<header class="top">
  <span class="brand">Zircolite</span>
  <div class="slot"><SearchBar {db} {schema} {query} /></div>
  <button type="button" onclick={() => details.open()}>
    Run details{#if warnings}<span class="badge"><span class="swatch" aria-hidden="true"></span>{warnings} {warnings === 1 ? 'warning' : 'warnings'}</span>{/if}
  </button>
  <button type="button" aria-label={`Theme: ${LABEL[theme]}. Change theme`} onclick={() => (theme = nextTheme(theme))}>{LABEL[theme]}</button>
</header>
<RunDetails bind:this={details} {manifest} {detected} />

<style>
  .top { display: flex; align-items: flex-start; gap: 12px; padding: 10px 16px; background: var(--panel); border-bottom: 1px solid var(--rule); }
  .brand { font-weight: 600; font-size: var(--t-18); padding-top: 4px; letter-spacing: 0.01em; }
  button { background: none; border: 1px solid var(--rule); border-radius: var(--radius); padding: 6px 10px; cursor: pointer; white-space: nowrap; }
  .badge { margin-left: 8px; display: inline-flex; align-items: center; gap: 6px; }
  .swatch { width: 8px; height: 8px; border-radius: 50%; background: var(--sev-3); }
  .slot { flex: 1; min-width: 0; display: flex; }
  @media (max-width: 720px) {
    .top { flex-wrap: wrap; align-items: center; }
    .brand { flex: 1; padding-top: 0; }
    .slot { order: 3; flex: 1 1 100%; }
  }
</style>
