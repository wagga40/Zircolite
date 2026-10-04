<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Schema } from '../engine/schema';
  import { compile } from '../search/compile';
  import { type Node, parse } from '../search/parse';
  import { SearchError } from '../search/tokens';
  import { view } from '../state/view.svelte';
  import { combineWhere, DETECTIONS_PREDICATE, timePredicate } from '../state/where';
  import { textIndex } from '../engine/textIndex.svelte';
  import { slowSearchNote } from '../ui/format';
  import { shownColumns } from './columns';
  import DetailDrawer from './DetailDrawer.svelte';
  import FieldSidebar from './FieldSidebar.svelte';
  import ResultTable from './ResultTable.svelte';
  import Strip from './Strip.svelte';

  let { db, schema, manifest }: { db: Db; schema: Schema; manifest: Manifest } = $props();

  // A query from a bookmark has not been validated: an invalid one shows its
  // error in the search bar and matches nothing, never everything.
  const compiled = $derived.by((): { tree: Node | null; sql: string | null } => {
    if (!view.q) return { tree: null, sql: null };
    try {
      const tree = parse(view.q);
      return { tree, sql: compile(tree, schema, { textIndex: textIndex.status === 'ready' }) };
    } catch (problem) {
      if (problem instanceof SearchError) return { tree: null, sql: 'FALSE' };
      throw problem;
    }
  });
  const search = $derived(compiled.sql);
  const slow = $derived(slowSearchNote(compiled.tree, manifest.totals.events, textIndex.status === 'ready'));
  const time = $derived(timePredicate(view.t));
  // The table, facets and drawer read every filter; the strip draws time itself.
  const where = $derived(combineWhere([search, time, view.d ? DETECTIONS_PREDICATE : null]));
  const stripWhere = $derived(combineWhere([search, view.d ? DETECTIONS_PREDICATE : null]));
  const columns = $derived(shownColumns(view.cols, schema));

</script>

<main class="explore">
  <Strip {db} {manifest} where={stripWhere} />
  <div class="body">
    <FieldSidebar {db} {schema} {manifest} {where} {columns} />
    <section class="results" aria-label="Events">
      <ResultTable {db} {schema} {manifest} {where} {columns} {slow} />
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
