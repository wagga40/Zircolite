<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import { isSuperseded } from '../engine/queries';
  import type { Schema } from '../engine/schema';
  import type { QueryState } from '../state/query.svelte';
  import { run, runAgain } from '../state/run.svelte';
  import { formatCount } from '../ui/format';
  import RuleItem from './RuleItem.svelte';
  import {
    groupRules, type KeyRow, keyRowsSql, levelLabel, type RuleGroup, type RuleRow, ruleRowsSql, type SectionRow,
    sectionRowsSql, sections, totalSql,
  } from './rules';

  let { db, schema, manifest, query }: { db: Db; schema: Schema; manifest: Manifest; query: QueryState } = $props();

  interface Loaded {
    groups: RuleGroup[];
    sectionRows: SectionRow[];
    events: number;
  }

  let loaded = $state.raw<Loaded | null>(null);
  let pending = $state(true);
  let failure = $state<string | null>(null);
  // A stop leaves no answer: the counts on screen would belong to an earlier filter.
  let stopped = $state(false);
  let showEmpty = $state(false);
  let expanded = $state<string[]>([]);
  let ticket = 0;

  $effect(() => {
    void run.generation;
    const where = query.where;
    const mine = ++ticket;
    pending = true;
    failure = null;
    stopped = false;
    void (async () => {
      try {
        const rows = await db.rows<RuleRow>(ruleRowsSql(where), { lane: 'detections' });
        const keys = await db.rows<KeyRow>(keyRowsSql(where), { lane: 'detections' });
        const sectionRows = await db.rows<SectionRow>(sectionRowsSql(where), { lane: 'detections' });
        const [total] = await db.rows<{ events: number }>(totalSql(where), { lane: 'detections' });
        if (mine !== ticket) return;
        loaded = { groups: groupRules(rows, keys), sectionRows, events: total?.events ?? 0 };
        pending = false;
      } catch (error) {
        if (mine !== ticket) return;
        pending = false;
        if (!isSuperseded(error)) failure = error instanceof Error ? error.message : String(error);
        else if (run.stopped) {
          loaded = null;
          stopped = true;
        }
      }
    })();
  });

  const shown = $derived(loaded ? sections(loaded.groups, loaded.sectionRows, showEmpty) : []);
  const matchedRules = $derived(loaded ? loaded.groups.filter((g) => g.events > 0).length : 0);
  const hidden = $derived(loaded ? loaded.groups.length - matchedRules : 0);
  const filtered = $derived(query.where !== 'TRUE');

  function toggle(key: string): void {
    expanded = expanded.includes(key) ? expanded.filter((k) => k !== key) : [...expanded, key];
  }
</script>

<main class="detections" aria-busy={pending}>
  <header class="bar">
    <h1 tabindex="-1">Detections</h1>
    <output id="detections-summary" data-rules={pending ? '' : matchedRules} data-events={pending ? '' : (loaded?.events ?? '')}>
      {#if stopped}Stopped{:else if loaded}{formatCount(matchedRules)} {matchedRules === 1 ? 'rule' : 'rules'} matched {formatCount(loaded.events)} {loaded.events === 1 ? 'event' : 'events'}{filtered ? ' under the current filters' : ''}{:else}Counting detections{/if}
    </output>
    {#if hidden}
      <button type="button" aria-pressed={showEmpty} onclick={() => (showEmpty = !showEmpty)}>{showEmpty ? 'Hide' : 'Show'} {formatCount(hidden)} {hidden === 1 ? 'rule' : 'rules'} without events here</button>
    {/if}
  </header>
  {#if failure}
    <p class="note failure" role="alert">The detections could not be counted: {failure}. Change the search, or reload the page if this repeats.</p>
  {:else if stopped}
    <p class="note" role="status">Stopped. <button type="button" class="again" onclick={runAgain}>Run again</button></p>
  {:else if loaded && shown.length === 0}
    <p class="note">{manifest.totals.rules_matched === 0 ? 'No rule matched any event in this run.' : 'No detection matches the current filters. Remove a filter to see them.'}</p>
  {/if}
  <div class="list" class:stale={pending && loaded !== null}>
    {#each shown as section (section.rank)}
      <section aria-label={levelLabel(section.rank)}>
        <h2><i style:background={`var(--sev-${Math.max(0, section.rank)})`}></i>{levelLabel(section.rank)}: {formatCount(section.rules.length)} {section.rules.length === 1 ? 'rule' : 'rules'}, {formatCount(section.events)} {section.events === 1 ? 'event' : 'events'}</h2>
        <ul>
          {#each section.rules as group (group.key)}
            <RuleItem {db} {schema} {group} expanded={expanded.includes(group.key)} ontoggle={() => toggle(group.key)} />
          {/each}
        </ul>
      </section>
    {/each}
  </div>
</main>

<style>
  .detections { min-height: 0; overflow: auto; background: var(--paper); }
  .bar { position: sticky; top: 0; z-index: 2; display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px 16px; padding: 12px 16px; background: var(--panel); border-bottom: 1px solid var(--rule); }
  h1 { margin: 0; font-size: var(--t-18); }
  output { font-weight: 600; }
  .bar button, .again { min-height: 28px; background: none; border: 1px solid var(--rule); border-radius: var(--radius); padding: 3px 10px; cursor: pointer; }
  h2 { display: flex; align-items: center; gap: 8px; margin: 0; padding: 16px 16px 6px; font-size: var(--t-15); }
  h2 i { width: 10px; height: 10px; border-radius: 1px; }
  ul { list-style: none; margin: 0; padding: 0; border-top: 1px solid var(--rule); }
  .note { margin: 12px 16px; color: var(--ink-2); }
  .failure { color: var(--danger); }
  .stale { opacity: 0.5; transition: opacity var(--motion); }
</style>
