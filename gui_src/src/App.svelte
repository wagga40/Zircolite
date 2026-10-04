<script lang="ts">
  import { onMount } from 'svelte';
  import { bootEngine } from './engine/boot';
  import { ChunkStore, loadScript, loadScripts } from './engine/chunks';
  import { type Manifest, PACKAGE_FORMAT } from './engine/manifest';

  interface Counts {
    events: number;
    rules: number;
    hits: number;
  }

  let manifest = $state<Manifest | null>(null);
  let phase = $state('Reading the package');
  let loaded = $state(0);
  let total = $state(0);
  let counts = $state<Counts | null>(null);
  let failure = $state<string | null>(null);

  const timeRange = $derived(manifest === null ? null : range(manifest));

  function range(m: Manifest): string | null {
    const starts = m.parts.map((p) => p.time.min).filter((v): v is number => v !== null);
    const ends = m.parts.map((p) => p.time.max).filter((v): v is number => v !== null);
    if (starts.length === 0 || ends.length === 0) return null;
    const iso = (microseconds: number) => new Date(microseconds / 1000).toISOString();
    return `${iso(Math.min(...starts))} → ${iso(Math.max(...ends))}`;
  }

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
    const result = await engine.conn.query(
      'SELECT (SELECT count(*) FROM events)::DOUBLE AS events, (SELECT count(*) FROM rules)::DOUBLE AS rules, ' +
        '(SELECT count(*) FROM hits)::DOUBLE AS hits',
    );
    const row = result.get(0);
    if (row === null) throw new Error('the query engine returned nothing');
    counts = { events: Number(row.events), rules: Number(row.rules), hits: Number(row.hits) };
    if (counts.events !== m.totals.events) {
      throw new Error(`The engine holds ${counts.events} events; the package lists ${m.totals.events}.`);
    }
    phase = 'Ready';
    document.title = 'Zircolite — ready';
  }

  onMount(() => {
    start().catch((error: unknown) => {
      failure = error instanceof Error ? error.message : String(error);
      phase = 'Failed';
      document.title = 'Zircolite — error';
    });
  });
</script>

<main>
  <header>
    <h1>Zircolite</h1>
    <p class="phase" aria-live="polite">
      {phase}{#if phase === 'Loading the data' && total > 0}: {loaded} / {total}{/if}
    </p>
  </header>

  {#if failure !== null}
    <p class="failure" role="alert">{failure}</p>
  {/if}

  {#if manifest !== null}
    <section class="summary">
      <dl>
        <div><dt>Events</dt><dd>{manifest.totals.events.toLocaleString()}</dd></div>
        <div><dt>Rules matched</dt><dd>{manifest.totals.rules_matched.toLocaleString()}</dd></div>
        <div><dt>Hits</dt><dd>{manifest.totals.hits.toLocaleString()}</dd></div>
        <div><dt>Correlation alerts</dt><dd>{manifest.totals.alerts.toLocaleString()}</dd></div>
        <div><dt>Inputs</dt><dd>{manifest.parts.length.toLocaleString()}</dd></div>
        {#if timeRange !== null}<div class="wide"><dt>Time range (UTC)</dt><dd>{timeRange}</dd></div>{/if}
      </dl>
      <p class="meta">Zircolite {manifest.zircolite} · {manifest.run.mode} · created {manifest.created}</p>
      {#if counts !== null}
        <p class="meta">Query engine ready: {counts.events.toLocaleString()} events, {counts.rules.toLocaleString()} rules, {counts.hits.toLocaleString()} hits.</p>
      {/if}
    </section>
    {#if manifest.warnings.length > 0}
      <section class="warnings">
        <h2>Warnings</h2>
        <ul>
          {#each manifest.warnings as warning}<li>{warning}</li>{/each}
        </ul>
      </section>
    {/if}
  {/if}

  <output id="engine-check" hidden data-events={counts?.events ?? ''} data-expected={manifest?.totals.events ?? ''}></output>
</main>

<style>
  main { max-width: 960px; margin: 0 auto; padding: 24px 16px; }
  header { display: flex; align-items: baseline; gap: 16px; flex-wrap: wrap; }
  h1 { font-size: 20px; margin: 0; }
  h2 { font-size: 15px; margin: 0 0 8px; }
  .phase, .meta { color: var(--muted); margin: 4px 0; }
  .failure { color: var(--danger); border: 1px solid var(--danger); border-radius: 6px; padding: 8px 12px; }
  .summary, .warnings { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; margin-top: 16px; }
  dl { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin: 0 0 8px; }
  dt { color: var(--muted); font-size: 12px; }
  dd { margin: 0; font: 600 18px/1.3 var(--mono); }
  .wide { grid-column: 1 / -1; }
  .wide dd { font-size: 14px; }
  ul { margin: 0; padding-left: 20px; }
</style>
