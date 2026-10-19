<script lang="ts">
  import type { Field, Schema } from '../engine/schema';
  import { cellText, type ColumnState, columnState } from '../search/filters';
  import { view } from '../state/view.svelte';
  import FilterCell from '../ui/FilterCell.svelte';
  import { isoTime } from '../ui/format';
  import { applyCell, applyFilter, LEVEL_CHOICES, levelChoice, levelFilter, nextSort } from './header';
  import { SORT_PREFIX, type SortKey } from './table';

  let { columns, schema, sortKey, template, minWidth, menuFor, onmenu, onproblem }: {
    columns: Field[];
    schema: Schema;
    sortKey: SortKey | null;
    template: string;
    minWidth: number;
    /** The key of the column whose menu is open. */
    menuFor: string | null;
    onmenu: (field: Field, anchor: HTMLElement) => void;
    onproblem: (problem: string | null) => void;
  } = $props();

  const level = $derived(levelChoice(view.q));

  function sortBy(target: SortKey | null): void {
    const next = nextSort(sortKey, view.desc, target);
    view.sort = next.sort;
    view.desc = next.desc;
  }

  function ariaSort(target: SortKey | null): 'ascending' | 'descending' | undefined {
    if (target !== sortKey) return undefined;
    return view.desc ? 'descending' : 'ascending';
  }

  function arrow(target: SortKey | null): string {
    return target === sortKey ? (view.desc ? ' ↓' : ' ↑') : '';
  }

  function apply(field: Field, text: string): string | null {
    const result = applyCell(view.q, field, text, schema);
    if ('problem' in result) return result.problem;
    view.q = result.query;
    return null;
  }

  function clear(field: Field): void {
    const result = applyFilter(view.q, field.name, null, schema);
    if ('query' in result) view.q = result.query;
  }

  function setLevel(choice: string): void {
    const result = applyFilter(view.q, 'level', levelFilter(choice), schema, { shortcut: true });
    if ('query' in result) view.q = result.query;
    onproblem('problem' in result ? result.problem : null);
  }

  function locked(state: ColumnState): string | null {
    if (state.kind === 'invalid') return 'The search does not parse; fix it in the search bar first';
    if (state.kind === 'custom') return 'Several terms filter this column; edit them in the search bar, or clear them here';
    if (state.kind === 'filter' && state.filter.op === 'oneOf') return 'Values picked in the column menu; open it to change them, or clear them here';
    return null;
  }

  function filtered(state: ColumnState): boolean {
    return state.kind === 'filter' || state.kind === 'custom';
  }
</script>

<div class="row head" role="row" aria-rowindex={1} style:grid-template-columns={template} style:min-width={`${minWidth}px`}>
  <div role="columnheader" aria-sort={ariaSort(null)}>
    <div class="name"><button type="button" class="sort" onclick={() => sortBy(null)}>Time (UTC){arrow(null)}</button></div>
    <div class="filter">
      {#if view.t}
        <span class="range" title={`${isoTime(view.t[0])} to ${isoTime(view.t[1])}, end excluded`}>{isoTime(view.t[0])} →</span>
        <button type="button" class="clear" aria-label="Clear the time range" onclick={() => (view.t = null)}>×</button>
      {:else}
        <span class="hint">Drag on the strip</span>
      {/if}
    </div>
  </div>
  <div role="columnheader" aria-sort={ariaSort('level')}>
    <div class="name"><button type="button" class="sort" onclick={() => sortBy('level')}>Level{arrow('level')}</button></div>
    <div class="filter">
      <select aria-label="Filter Level" class:active={level !== ''} value={level} onchange={(event) => setLevel(event.currentTarget.value)}>
        {#each LEVEL_CHOICES as choice (choice.value)}<option value={choice.value}>{choice.label}</option>{/each}
        {#if level === 'custom'}<option value="custom" disabled>Custom</option>{/if}
      </select>
    </div>
  </div>
  {#each columns as field (field.key)}
    {@const current = columnState(view.q, field.name)}
    {@const numeric = field.type !== 'VARCHAR'}
    <div role="columnheader" aria-sort={ariaSort(field)} class:num={numeric}>
      <div class="name">
        <button type="button" class="sort" title={numeric ? `Sort by ${field.name}` : `Sort by ${field.name}: text sorts by its first ${SORT_PREFIX} characters, ignoring case`}
          onclick={() => sortBy(field)}>{field.name}{arrow(field)}</button>
        <button type="button" class="funnel" class:on={filtered(current)} aria-haspopup="dialog" aria-expanded={menuFor === field.key}
          aria-label={`Filter and sort ${field.name}${filtered(current) ? ', filtered' : ''}`} data-column-funnel={field.key}
          onclick={(event) => onmenu(field, event.currentTarget)}>
          <svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true"><path d="M2 3h12l-4.5 5.5V13l-3 1.5V8.5z" /></svg>
        </button>
      </div>
      <div class="filter">
        <FilterCell label={field.name} text={cellText(current, numeric)} locked={locked(current)} apply={(text) => apply(field, text)}
          onclear={current.kind === 'invalid' ? undefined : () => clear(field)} {onproblem} />
      </div>
    </div>
  {/each}
</div>

<style>
  .head { position: sticky; top: 0; z-index: 2; display: grid; height: 62px; background: var(--panel); border-bottom: 1px solid var(--rule); }
  .head > div { display: grid; grid-template-rows: 30px 32px; min-width: 0; padding: 0 6px 0 10px; font: 600 var(--t-12) / 30px var(--sans); color: var(--ink-2); }
  .name { display: flex; align-items: center; gap: 4px; min-width: 0; }
  .num .name { justify-content: flex-end; }
  .sort { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; background: none; border: 0; padding: 0; font: inherit; color: inherit; cursor: pointer; text-align: inherit; }
  [aria-sort] .sort { color: var(--ink); }
  .funnel { flex: none; display: inline-grid; place-items: center; width: 22px; height: 22px; padding: 0; background: none; border: 1px solid transparent; border-radius: var(--radius); color: var(--ink-2); cursor: pointer; }
  .funnel:hover, .funnel[aria-expanded='true'] { border-color: var(--rule); color: var(--ink); }
  .funnel path { fill: none; stroke: currentColor; stroke-width: 1.4; stroke-linejoin: round; }
  .funnel.on { color: var(--signal); }
  .funnel.on path { fill: currentColor; }
  .filter { display: flex; align-items: center; gap: 2px; min-width: 0; font: 400 var(--t-12) / 1 var(--sans); }
  .filter > :global(.cell) { flex: 1; }
  select { width: 100%; min-width: 0; height: 24px; font: 400 var(--t-12) / 1 var(--sans); color: var(--ink); background: var(--paper); border: 1px solid var(--rule); border-radius: var(--radius); }
  select.active { border-color: var(--signal); }
  .range { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: var(--mono); color: var(--ink); }
  .hint { color: var(--ink-2); opacity: 0.8; }
  .clear { background: none; border: 0; cursor: pointer; color: var(--ink-2); min-width: 20px; min-height: 24px; padding: 0; }
</style>
