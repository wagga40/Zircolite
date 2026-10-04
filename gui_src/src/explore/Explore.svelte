<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Schema } from '../engine/schema';
  import { compile } from '../search/compile';
  import { parse } from '../search/parse';
  import { SearchError } from '../search/tokens';
  import { setDetections, setSearch, setTime } from '../state/filters';
  import { view } from '../state/view.svelte';
  import { timePredicate } from '../state/where';
  import Strip from './Strip.svelte';

  let { db, schema, manifest }: { db: Db; schema: Schema; manifest: Manifest } = $props();

  // A query from a bookmark has not been validated: an invalid one shows its
  // error in the search bar and matches nothing, never everything.
  const search = $derived.by(() => {
    try {
      return view.q ? compile(parse(view.q), schema) : null;
    } catch (problem) {
      if (problem instanceof SearchError) return 'FALSE';
      throw problem;
    }
  });
  const time = $derived(timePredicate(view.t));

  $effect(() => setSearch(search));
  $effect(() => setTime(time));
  $effect(() => setDetections(view.d));
</script>

<main class="explore">
  <Strip {db} {manifest} />
  <div class="body"></div>
</main>

<style>
  .explore { display: grid; grid-template-rows: auto minmax(0, 1fr); min-height: 0; }
  .body { min-height: 0; }
</style>
