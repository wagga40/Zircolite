<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Schema } from '../engine/schema';
  import Explore from '../explore/Explore.svelte';
  import { typing } from './keys';
  import TopBar from './TopBar.svelte';
  import { ui } from './ui.svelte';

  let { db, schema, manifest }: { db: Db; schema: Schema; manifest: Manifest } = $props();

  function onkeydown(event: KeyboardEvent): void {
    if (event.metaKey || event.ctrlKey || event.altKey || typing(event)) return;
    if (event.key === '/') {
      event.preventDefault();
      document.getElementById('search-input')?.focus();
    } else if (event.key === '?') {
      ui.help = !ui.help;
    } else if (event.key === 'Escape' && ui.help) {
      ui.help = false;
    }
  }
</script>

<svelte:window {onkeydown} />
<div class="shell">
  <TopBar {db} {schema} {manifest} />
  <Explore {db} {schema} {manifest} />
</div>

<style>
  .shell { display: grid; grid-template-rows: auto minmax(0, 1fr); height: 100vh; }
</style>
