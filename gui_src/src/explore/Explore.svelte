<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Schema } from '../engine/schema';
  import { compile } from '../search/compile';
  import { parse } from '../search/parse';
  import { SearchError } from '../search/tokens';
  import { setDetections, setSearch, setTime } from '../state/filters';
  import { view } from '../state/view.svelte';
  import { combineWhere, DETECTIONS_PREDICATE, timePredicate } from '../state/where';
  import { shownColumns } from './columns';
  import DetailDrawer from './DetailDrawer.svelte';
  import FieldSidebar from './FieldSidebar.svelte';
  import ResultTable from './ResultTable.svelte';
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
  // The same three predicates go to Mosaic, so its charts and these queries agree.
  const where = $derived(combineWhere([search, time, view.d ? DETECTIONS_PREDICATE : null]));
  const columns = $derived(shownColumns(view.cols, schema));

  $effect(() => setSearch(search));
  $effect(() => setTime(time));
  $effect(() => setDetections(view.d));
</script>

<main class="explore">
  <Strip {db} {manifest} />
  <div class="body">
    <FieldSidebar {db} {schema} {manifest} {where} {columns} />
    <section class="results" aria-label="Events">
      <ResultTable {db} {schema} {manifest} {where} {columns} />
    </section>
    <DetailDrawer {db} {schema} {manifest} />
  </div>
</main>

<style>
  .explore { display: grid; grid-template-rows: auto minmax(0, 1fr); min-height: 0; }
  .body { position: relative; display: grid; grid-template-columns: 280px minmax(0, 1fr); min-height: 0; }
  .results { position: relative; min-height: 0; min-width: 0; }
  @media (max-width: 720px) {
    .body { grid-template-columns: minmax(0, 1fr); }
  }
</style>
