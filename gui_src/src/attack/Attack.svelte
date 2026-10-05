<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Schema } from '../engine/schema';
  import type { QueryState } from '../state/query.svelte';

  let props: { db: Db; schema: Schema; manifest: Manifest; query: QueryState } = $props();
</script>

<main class="stub" data-events={props.manifest.totals.events}>
  <h1 tabindex="-1">ATT&amp;CK</h1>
  <p>This view is not built yet. Explore lists every event.</p>
</main>

<style>
  .stub { padding: 24px; }
  h1 { margin: 0 0 8px; font-size: var(--t-18); }
  p { color: var(--ink-2); }
</style>
