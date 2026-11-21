<script lang="ts">
  import type { Db } from '../engine/db';
  import { hasExploreTable, type Manifest } from '../engine/manifest';
  import type { Schema } from '../engine/schema';
  import type { QueryState } from '../state/query.svelte';
  import { view } from '../state/view.svelte';
  import { ownScope } from '../ui/scope';
  import { shownColumns } from './columns';
  import { timelessCount } from './histogram';
  import { indexCovers } from './table';
  import FieldSidebar from './FieldSidebar.svelte';
  import ResultTable from './ResultTable.svelte';
  import Strip from './Strip.svelte';

  let { db: page, schema, manifest, query }: { db: Db; schema: Schema; manifest: Manifest; query: QueryState } = $props();
  // The view's scope lives as long as the view, on the page's one Db.
  // svelte-ignore state_referenced_locally
  const db = ownScope(page, 'explore');

  const columns = $derived(shownColumns(view.cols, schema));
  const index = $derived.by(() => {
    if (!hasExploreTable(manifest)) return undefined;
    const events = manifest.totals.events;
    const dated = events - timelessCount(manifest);
    return Number.isSafeInteger(dated) && dated >= 0 && dated <= events ? { events, dated } : undefined;
  });
</script>

<main class="explore">
  <Strip {db} {manifest} where={query.whereWithoutTime} />
  <div class="body">
    <FieldSidebar {db} {schema} {manifest} where={query.where} {columns} />
    <section class="results" aria-label="Events">
      <ResultTable {db} exportDb={page} {schema} {manifest} index={index && indexCovers(query.compiled.tree) ? index : undefined}
        where={query.where} whereFor={(q) => query.whereFor(q)} {columns} slow={query.slow} />
    </section>
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
