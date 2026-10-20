<script lang="ts">
  import { onDestroy } from 'svelte';
  import type { Db } from '../engine/db';
  import { isSuperseded } from '../engine/queries';
  import type { Field } from '../engine/schema';
  import { asciiLower } from '../engine/sql';
  import type { ColumnFilter, ColumnState } from '../search/filters';
  import { run } from '../state/run.svelte';
  import { formatCount } from '../ui/format';
  import Placeholder from '../ui/Placeholder.svelte';
  import { ownScope } from '../ui/scope';
  import { columnValuesSql, valueLabel } from './sidebar';

  let { db: parent, field, where, current, onapply }: {
    db: Db;
    field: Field;
    /** Every filter but this column's own, so the counts say what each choice would list. */
    where: string;
    current: ColumnState;
    onapply: (filter: ColumnFilter | null) => void;
  } = $props();

  // Closing the menu stops its count.
  // svelte-ignore state_referenced_locally
  const db = ownScope(parent, 'column-values');
  const LIMIT = 100;

  interface Value {
    v: string;
    n: number;
    spellings: number;
    distinct: number;
    total: number;
  }

  const chosen = (() => {
    if (current.kind !== 'filter') return [];
    const filter = current.filter;
    if (filter.op === 'oneOf') return filter.values;
    return filter.op === 'equals' && !filter.negate ? [filter.value] : [];
  })();

  let order = $state<'common' | 'rare'>('common');
  let search = $state('');
  let query = $state('');
  let rows = $state.raw<Value[] | null>(null);
  let failure = $state<string | null>(null);
  let pending = $state(true);
  // Picked values by their lowercase, as the search matches them; each keeps the spelling it was picked in.
  let picked = $state.raw(new Map(chosen.map((value) => [asciiLower(value), value])));
  let timer: ReturnType<typeof setTimeout> | undefined;
  let ticket = 0;

  $effect(() => {
    const text = search;
    clearTimeout(timer);
    timer = setTimeout(() => (query = text), 250);
  });

  onDestroy(() => clearTimeout(timer));

  $effect(() => {
    void run.generation;
    const sql = columnValuesSql(field, where, { order, search: query, limit: LIMIT });
    const mine = ++ticket;
    pending = true;
    failure = null;
    db.rows<Value>(sql, { lane: 'values' }).then(
      (result) => {
        if (mine !== ticket) return;
        rows = result;
        pending = false;
      },
      (error: unknown) => {
        if (mine !== ticket) return;
        if (!isSuperseded(error)) failure = error instanceof Error ? error.message : String(error);
        pending = false;
      },
    );
  });

  // Picked values stay on top, listed even when the counted page no longer holds them.
  const listed = $derived.by(() => {
    const counted = rows ?? [];
    const keys = new Set(counted.map((row) => asciiLower(row.v)));
    const extra = [...picked.entries()].filter(([key]) => !keys.has(key)).map(([, v]) => ({ v, n: null as number | null, spellings: 1 }));
    const pickedRows = counted.filter((row) => picked.has(asciiLower(row.v)));
    const rest = counted.filter((row) => !picked.has(asciiLower(row.v)));
    return [...extra, ...pickedRows, ...rest];
  });

  const distinct = $derived(rows?.[0]?.distinct ?? 0);

  function toggle(value: string): void {
    const key = asciiLower(value);
    const next = new Map(picked);
    if (next.has(key)) next.delete(key);
    else next.set(key, value);
    picked = next;
  }
</script>

<section class="values" aria-label={`Values of ${field.name}`} aria-busy={pending}>
  <div class="line">
    <input type="search" aria-label={`Find values of ${field.name}`} placeholder="Find values" bind:value={search} spellcheck="false" autocomplete="off" />
    <button type="button" aria-pressed={order === 'rare'} onclick={() => (order = order === 'rare' ? 'common' : 'rare')}
      title="Rarest first: the least frequent values are where unusual activity hides">Rarest first</button>
  </div>
  {#if failure}
    <p class="note failure" role="alert">The values could not be counted: {failure}</p>
  {:else if rows === null}
    <Placeholder label="Counting values" lines={4} />
  {:else if listed.length === 0}
    <p class="note">{query ? 'No value contains this text.' : 'No event in the results has this field.'}</p>
  {:else}
    <ul class:stale={pending}>
      {#each listed as row (asciiLower(row.v))}
        <li data-value={row.v} data-count={row.n ?? ''}>
          <label>
            <input type="checkbox" checked={picked.has(asciiLower(row.v))} onchange={() => toggle(row.v)} />
            <span class="value" class:empty={row.v === ''} title={row.v}>{valueLabel(row.v)}{#if row.spellings > 1}<span class="cases"> any case</span>{/if}</span>
          </label>
          <span class="n">{row.n === null ? '' : formatCount(row.n)}</span>
        </li>
      {/each}
    </ul>
    {#if distinct > (rows?.length ?? 0)}
      <p class="note">Showing {formatCount(rows?.length ?? 0)} of {formatCount(distinct)} values; find a value to see others.</p>
    {/if}
  {/if}
  <div class="line">
    <button type="button" disabled={picked.size === 0} onclick={() => onapply({ op: 'oneOf', values: [...picked.values()], negate: false })}>Show only these</button>
    <button type="button" disabled={picked.size === 0} onclick={() => onapply({ op: 'oneOf', values: [...picked.values()], negate: true })}>Leave these out</button>
  </div>
</section>

<style>
  .values { display: grid; gap: 6px; border-top: 1px solid var(--rule); padding-top: 8px; }
  .line { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
  input[type='search'] { flex: 1; min-width: 0; height: 28px; box-sizing: border-box; padding: 0 6px; font: 400 var(--t-13) / 1 var(--mono); color: var(--ink);
    background: var(--paper); border: 1px solid var(--rule); border-radius: var(--radius); }
  button { background: none; border: 1px solid var(--rule); border-radius: var(--radius); padding: 3px 10px; min-height: 28px; cursor: pointer; color: var(--ink); font: inherit; }
  button:disabled { opacity: 0.5; cursor: default; }
  button[aria-pressed='true'] { border-color: var(--signal); color: var(--signal); }
  ul { list-style: none; margin: 0; padding: 0; max-height: 240px; overflow: auto; }
  ul.stale { opacity: 0.6; }
  li { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 6px; min-height: 26px; }
  label { display: flex; align-items: center; gap: 6px; min-width: 0; cursor: pointer; }
  .value { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font: 400 var(--t-13) / 1.4 var(--mono); }
  .value.empty { color: var(--ink-2); font-style: italic; }
  .cases { font: 400 var(--t-12) / 1 var(--sans); color: var(--ink-2); }
  .n { font-size: var(--t-12); color: var(--ink-2); text-align: right; }
  .note { margin: 0; font-size: var(--t-12); color: var(--ink-2); }
  .failure { color: var(--danger); }
</style>
