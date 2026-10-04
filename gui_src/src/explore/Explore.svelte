<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Schema } from '../engine/schema';
  import { compile } from '../search/compile';
  import { parse } from '../search/parse';
  import { setDetections, setSearch, setTime } from '../state/filters';
  import { view } from '../state/view.svelte';
  import { timePredicate } from '../state/where';

  let { db, schema, manifest }: { db: Db; schema: Schema; manifest: Manifest } = $props();

  // A query from a bookmark has not been validated: an invalid one shows its
  // error in the search bar and matches nothing, never everything.
  $effect(() => {
    let predicate: string | null;
    try {
      predicate = view.q ? compile(parse(view.q), schema) : null;
    } catch {
      predicate = 'FALSE';
    }
    setSearch(predicate);
  });
  $effect(() => setTime(timePredicate(view.t)));
  $effect(() => setDetections(view.d));
</script>

<main class="explore" data-db={db ? 'ready' : ''} data-events={manifest.totals.events}></main>

<style>
  .explore { min-height: 0; }
</style>
