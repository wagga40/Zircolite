<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Schema } from '../engine/schema';
  import Explore from '../explore/Explore.svelte';
  import { typing } from './keys';
  import { pageTopLayer } from './layers';
  import TopBar from './TopBar.svelte';
  import { ui } from './ui.svelte';

  let { db, schema, manifest, detected }: { db: Db; schema: Schema; manifest: Manifest; detected: number | null } = $props();

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
        ui.fieldsOpen = false;
        document.getElementById('fields-toggle')?.focus();
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
  <Explore {db} {schema} {manifest} />
</div>

<style>
  .shell { display: grid; grid-template-rows: auto minmax(0, 1fr); height: 100vh; }
</style>
