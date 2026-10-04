<script lang="ts">
  import { onMount } from 'svelte';
  import { bootEngine } from './engine/boot';
  import { ChunkStore, loadScript, loadScripts } from './engine/chunks';
  import { type Db, openDb } from './engine/db';
  import { type Manifest, PACKAGE_FORMAT } from './engine/manifest';
  import { Schema } from './engine/schema';
  import { bindHash, view } from './state/view.svelte';
  import Loading from './ui/Loading.svelte';
  import Shell from './ui/Shell.svelte';

  let manifest = $state<Manifest | null>(null);
  let db = $state<Db | null>(null);
  let schema = $state<Schema | null>(null);
  let phase = $state('Reading the package');
  let loaded = $state(0);
  let total = $state(0);
  let failure = $state<string | null>(null);
  let engineEvents = $state<number | null>(null);

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
      throw new Error(`This viewer reads package format ${PACKAGE_FORMAT}; this package is format ${m.format}.`);
    }
    manifest = m;
    const scripts = m.files.flatMap((file) => file.chunks);
    total = scripts.length;
    phase = 'Loading the data';
    await loadScripts(scripts, () => {
      loaded += 1;
    });
    phase = 'Starting the query engine';
    const engine = await bootEngine(m, store, (label) => {
      phase = label;
    });
    const opened = await openDb(engine);
    const [counts] = await opened.rows<{ events: number; hits: number }>(
      'SELECT (SELECT count(*) FROM events)::DOUBLE AS events, (SELECT count(*) FROM hits)::DOUBLE AS hits',
      { cache: false },
    );
    engineEvents = counts.events;
    if (counts.events !== m.totals.events || counts.hits !== m.totals.hits) {
      throw new Error(
        `The engine holds ${counts.events} events and ${counts.hits} hits; the package lists ${m.totals.events} and ${m.totals.hits}.`,
      );
    }
    schema = Schema.fromManifest(m);
    bindHash(view);
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
  <Shell {db} {schema} {manifest} />
{:else}
  <Loading {phase} {loaded} {total} {failure} {manifest} />
{/if}
<output id="engine-check" hidden data-events={engineEvents ?? ''} data-expected={manifest?.totals.events ?? ''}></output>
