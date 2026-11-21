<script lang="ts">
  import { onMount } from 'svelte';
  import { bootEngine } from './engine/boot';
  import { ChunkStore, loadScript, loadScripts } from './engine/chunks';
  import { type Db, openDb } from './engine/db';
  import { hasExploreTable, type Manifest, PACKAGE_FORMAT } from './engine/manifest';
  import { Schema } from './engine/schema';
  import { configureTextIndex, textIndex } from './engine/textIndex.svelte';
  import { bindHash, view } from './state/view.svelte';
  import { activity } from './ui/busy.svelte';
  import Loading from './ui/Loading.svelte';
  import { type BootStep, chunkWeights } from './ui/loading';
  import Shell from './ui/Shell.svelte';

  let manifest = $state<Manifest | null>(null);
  let db = $state<Db | null>(null);
  let schema = $state<Schema | null>(null);
  let phase = $state<BootStep>('Reading the package');
  let loaded = $state(0);
  let total = $state(0);
  let failure = $state<string | null>(null);
  let engineEvents = $state<number | null>(null);
  let detected = $state<number | null>(null);

  async function start(): Promise<void> {
    const store = new ChunkStore();
    let received: Manifest | null = null;
    window.__zircolite = {
      manifest: (m) => {
        received = m;
      },
      chunk: (name, sequence, text) => store.add(name, sequence, text),
    };
    await loadScript('data/manifest.js');
    const m = received as Manifest | null;
    if (m === null) throw new Error('data/manifest.js did not describe a package');
    if (m.format !== PACKAGE_FORMAT) {
      throw new Error(`This viewer reads package format ${PACKAGE_FORMAT}; this package is format ${m.format}. Open it with the viewer of the Zircolite version that made it, or re-create the package with this version.`);
    }
    manifest = m;
    const weights = chunkWeights(m.files);
    total = [...weights.values()].reduce((sum, bytes) => sum + bytes, 0);
    phase = 'Loading the engine';
    const chunkLoaded = (source: string) => {
      loaded += weights.get(source) ?? 0;
    };
    await loadScripts(m.files.filter((file) => file.kind === 'engine').flatMap((file) => file.chunks), chunkLoaded);
    phase = 'Starting the query engine';
    const engine = await bootEngine(m, store, (label) => {
      phase = label;
    }, chunkLoaded);
    phase = 'Linking detections to their events';
    const opened = await openDb(engine, { onActivity: (next) => Object.assign(activity, next) });
    phase = 'Checking the package';
    const exploreCount = hasExploreTable(m) ? ', (SELECT count(*) FROM explore)::DOUBLE AS explore' : '';
    const [counts] = await opened.rows<{ events: number; hits: number; explore?: number }>(
      `SELECT (SELECT count(*) FROM events)::DOUBLE AS events, (SELECT count(*) FROM hits)::DOUBLE AS hits${exploreCount}`,
      { cache: false },
    );
    engineEvents = counts.events;
    if (counts.events !== m.totals.events || counts.hits !== m.totals.hits) {
      throw new Error(
        `The engine holds ${counts.events} events and ${counts.hits} hits; the package lists ${m.totals.events} and ${m.totals.hits}. The package is damaged or incomplete: extract the whole archive again, or re-create the package.`,
      );
    }
    if (counts.explore !== undefined && counts.explore !== counts.events) {
      throw new Error(`The Explore index holds ${counts.explore} rows for ${counts.events} events. Extract the whole archive again, or re-create the package.`);
    }
    const [withHits] = await opened.rows<{ n: number }>('SELECT count(*)::DOUBLE AS n FROM event_levels', { cache: false });
    detected = withHits.n;
    schema = Schema.fromManifest(m);
    bindHash(view);
    configureTextIndex(m, opened, (file, progress) => store.readBytes(file, progress));
    db = opened;
    document.title = 'Zircolite — ready';
  }

  onMount(() => {
    start().catch((error: unknown) => {
      failure = error instanceof Error ? error.message : String(error);
      document.title = 'Zircolite — error';
    });
  });
</script>

{#if db && schema && manifest}
  <Shell {db} {schema} {manifest} {detected} />
{:else}
  <Loading {phase} {loaded} {total} {failure} {manifest} />
{/if}
<output id="engine-check" hidden data-events={engineEvents ?? ''} data-expected={manifest?.totals.events ?? ''} data-text-index={textIndex.status}></output>
