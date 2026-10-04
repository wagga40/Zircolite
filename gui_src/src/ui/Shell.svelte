<script lang="ts">
  import Detections from '../detections/Detections.svelte';
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Schema } from '../engine/schema';
  import DetailDrawer from '../explore/DetailDrawer.svelte';
  import Explore from '../explore/Explore.svelte';
  import Overview from '../overview/Overview.svelte';
  import { QueryState } from '../state/query.svelte';
  import { run } from '../state/run.svelte';
  import { view } from '../state/view.svelte';
  import Timeline from '../timeline/Timeline.svelte';
  import { typing } from './keys';
  import { pageTopLayer } from './layers';
  import NavRail from './NavRail.svelte';
  import TopBar from './TopBar.svelte';
  import { closeFields, ui } from './ui.svelte';

  let { db, schema, manifest, detected }: { db: Db; schema: Schema; manifest: Manifest; detected: number | null } = $props();

  const query = $derived(new QueryState(schema, manifest.totals.events));

  // A new question is not a stopped one.
  $effect(() => {
    void query.where;
    run.stopped = false;
  });

  function onkeydown(event: KeyboardEvent): void {
    if (event.metaKey || event.ctrlKey || event.altKey || typing(event)) return;
    if (event.key === '/') {
      event.preventDefault();
      document.getElementById('search-input')?.focus();
    } else if (event.key === '?') {
      ui.help = !ui.help;
    } else if (event.key === 'Escape' && !event.defaultPrevented) {
      const layer = pageTopLayer();
      if (layer === 'help') {
        ui.help = false;
      } else if (layer === 'fields') {
        void closeFields();
      } else {
        return;
      }
      event.preventDefault();
    }
  }
</script>

<svelte:window {onkeydown} />
<div class="shell">
  <TopBar {db} {schema} {manifest} {detected} />
  <div class="frame">
    <NavRail />
    <div class="main">
      {#if view.route === 'overview'}
        <Overview {db} {schema} {manifest} {query} />
      {:else if view.route === 'detections'}
        <Detections {db} {schema} {manifest} {query} />
      {:else if view.route === 'timeline'}
        <Timeline {db} {schema} {manifest} {query} />
      {:else}
        <Explore {db} {schema} {manifest} {query} />
      {/if}
      <DetailDrawer {db} {schema} {manifest} />
    </div>
  </div>
</div>

<style>
  .shell { display: grid; grid-template-rows: auto minmax(0, 1fr); height: 100vh; }
  .frame { display: grid; grid-template-columns: 96px minmax(0, 1fr); min-height: 0; }
  .main { position: relative; display: grid; min-height: 0; min-width: 0; }
  @media (max-width: 720px) {
    .frame { grid-template-columns: minmax(0, 1fr); grid-template-rows: auto minmax(0, 1fr); }
  }
</style>
