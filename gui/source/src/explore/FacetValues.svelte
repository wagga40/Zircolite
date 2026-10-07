<script lang="ts">
  import type { Db } from '../engine/db';
  import { isSuperseded } from '../engine/queries';
  import type { Field } from '../engine/schema';
  import { appendTerm } from '../search/edit';
  import { run, runAgain } from '../state/run.svelte';
  import { view } from '../state/view.svelte';
  import { formatCount } from '../ui/format';
  import { ownScope } from '../ui/scope';
  import { topValuesSql, valueLabel } from './sidebar';

  let { db: parent, field, where, shown, ontoggle }: { db: Db; field: Field; where: string; shown: boolean; ontoggle: () => void } = $props();
  // Collapsing the field stops its count. Each field has its own component, so its first field is its only one.
  // svelte-ignore state_referenced_locally
  const db = ownScope(parent, `facet-${field.key}`);

  interface Value {
    v: string;
    n: number;
    spellings: number;
    total: number;
  }

  let rows = $state.raw<Value[] | null>(null);
  let failure = $state<string | null>(null);
  let pending = $state(true);
  // A stop leaves no answer: the rows on screen would belong to an earlier filter.
  let stopped = $state(false);
  let ticket = 0;

  $effect(() => {
    void run.generation;
    const sql = topValuesSql(field, where);
    const mine = ++ticket;
    failure = null;
    stopped = false;
    pending = true;
    db.rows<Value>(sql, { lane: 'values' }).then(
      (result) => {
        if (mine !== ticket) return;
        rows = result;
        pending = false;
      },
      (error: unknown) => {
        if (mine !== ticket) return;
        failure = isSuperseded(error) ? null : error instanceof Error ? error.message : String(error);
        if (isSuperseded(error) && run.stopped) {
          rows = null;
          stopped = true;
        }
        pending = false;
      },
    );
  });

  const total = $derived(rows?.[0]?.total ?? 0);
</script>

<div class="facet">
  <button type="button" class="column" aria-pressed={shown} onclick={ontoggle}>{shown ? 'Hide column' : 'Show as column'}</button>
  {#if failure}
    <p class="note failure" role="alert">The top values could not be counted: {failure}. Change the search, or reload the page if this repeats.</p>
  {:else if stopped}
    <p class="note" role="status">Stopped. <button type="button" class="again" onclick={runAgain}>Run again</button></p>
  {:else if rows === null}
    <p class="note">Counting values</p>
  {:else if rows.length === 0}
    <p class="note dims" aria-busy={pending}>No event in the results has this field.</p>
  {:else}
    <div class="dims" aria-busy={pending}>
      <p class="note">Top {rows.length} of {formatCount(total)} results with this field</p>
      <ul>
        {#each rows as row (row.v)}
          <li data-value={row.v} data-count={row.n}>
            <span class="value" class:empty={row.v === ''} title={row.v}>
              {valueLabel(row.v)}{#if row.spellings > 1}<span
                  class="cases"
                  title={`Also written in ${row.spellings - 1} other letter case${row.spellings > 2 ? 's' : ''}; the count and the filter include them.`}
                > any case<span class="visually-hidden"> (the count includes other letter cases)</span></span>{/if}
            </span>
            <span class="n">{formatCount(row.n)}</span>
            <button type="button" aria-label={`Filter for ${field.name} ${valueLabel(row.v)}`} onclick={() => (view.q = appendTerm(view.q, field.name, row.v, false))}>+</button>
            <button type="button" aria-label={`Filter out ${field.name} ${valueLabel(row.v)}`} onclick={() => (view.q = appendTerm(view.q, field.name, row.v, true))}>−</button>
            <span class="bar" style:inline-size={`${(row.n / total) * 100}%`}></span>
          </li>
        {/each}
      </ul>
    </div>
  {/if}
</div>

<style>
  .facet { padding: 4px 0 10px 12px; }
  .column { background: none; border: 1px solid var(--rule); border-radius: var(--radius); padding: 1px 8px; min-height: 24px; font-size: var(--t-12); cursor: pointer; margin-bottom: 6px; }
  .column[aria-pressed='true'] { border-color: var(--signal); color: var(--signal); }
  .note { margin: 2px 0 6px; font-size: var(--t-12); color: var(--ink-2); }
  .failure { color: var(--danger); }
  .again { background: none; border: 1px solid var(--rule); border-radius: var(--radius); padding: 1px 8px; min-height: 24px; font-size: var(--t-12); cursor: pointer; }
  ul { list-style: none; margin: 0; padding: 0; }
  li { position: relative; display: grid; grid-template-columns: minmax(0, 1fr) auto auto auto; gap: 4px; align-items: center; padding: 2px 0 4px; }
  .value { font: 400 var(--t-13) / 1.4 var(--mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .value.empty { color: var(--ink-2); font-style: italic; }
  .cases { font: 400 var(--t-12) / 1 var(--sans); color: var(--ink-2); }
  .visually-hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
  .n { font-size: var(--t-12); color: var(--ink-2); text-align: right; }
  li button { background: none; border: 1px solid transparent; border-radius: var(--radius); width: 24px; height: 24px; padding: 0; cursor: pointer; color: var(--ink-2); }
  li button:hover { border-color: var(--rule); color: var(--ink); }
  .bar { position: absolute; left: 0; bottom: 0; height: 2px; background: var(--strip); opacity: 0.6; }
</style>
