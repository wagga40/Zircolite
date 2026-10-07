<script lang="ts">
  import { ROUTES, type Route } from '../state/hash';
  import { view } from '../state/view.svelte';

  const LABELS: Record<Route, string> = {
    overview: 'Overview', detections: 'Detections', explore: 'Explore', timeline: 'Timeline',
    attack: 'ATT&CK', entities: 'Entities', processes: 'Processes', sql: 'SQL',
  };
  let rail = $state<HTMLElement>();

  // On a phone the rail is a sideways row, and the current view could sit off screen.
  $effect(() => {
    void view.route;
    rail?.querySelector('[aria-current="page"]')?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  });
</script>

<nav class="rail" aria-label="Views" bind:this={rail}>
  {#each ROUTES as route (route)}
    <button type="button" aria-current={view.route === route ? 'page' : undefined} onclick={() => (view.route = route)}>{LABELS[route]}</button>
  {/each}
</nav>

<style>
  .rail { display: flex; flex-direction: column; padding: 8px 0; background: var(--panel); border-right: 1px solid var(--rule); }
  button { position: relative; height: 40px; padding: 0 12px; text-align: left; background: none; border: 0; cursor: pointer; color: var(--ink-2); font-size: var(--t-15); }
  button:hover { color: var(--ink); }
  button[aria-current='page'] { color: var(--ink); font-weight: 600; }
  button[aria-current='page']::before { content: ''; position: absolute; left: 0; top: 8px; bottom: 8px; width: 3px; background: var(--signal); }
  @media (max-width: 720px) {
    .rail { flex-direction: row; overflow-x: auto; padding: 0 8px; border-right: 0; border-bottom: 1px solid var(--rule); }
    button { flex: none; }
    button:focus-visible { outline-offset: -2px; }
    button[aria-current='page']::before { left: 12px; right: 12px; top: auto; bottom: 0; width: auto; height: 3px; }
  }
</style>
