<script lang="ts">
  import type { Snippet } from 'svelte';
  import { onMount } from 'svelte';
  import type { ColumnFilter, ColumnState } from '../search/filters';
  import { filterFrom, formFrom, type MenuForm, menuOps } from './columnMenu';
  import { pageTopLayer } from './layers';

  let { title, numeric, anchor, current, sort, onsort, onapply, onclose, values, column }: {
    title: string;
    numeric: boolean;
    /** The button that opened the menu: the menu sits under it, and an outside press ignores it. */
    anchor: HTMLElement;
    /** What the search says about the column now. */
    current: ColumnState;
    /** The column's place in the order, or null when the list is ordered by something else. */
    sort: 'ascending' | 'descending' | null;
    onsort: (desc: boolean) => void;
    /** Puts a filter in force, or removes it with null: null once done, or why it cannot be. */
    onapply: (filter: ColumnFilter | null) => string | null;
    onclose: () => void;
    /** The column's values, where the table can count them; given the menu's apply, so a refusal shows here. */
    values?: Snippet<[(filter: ColumnFilter | null) => void]>;
    /** Moving, hiding and resizing, where the table lets columns change. */
    column?: Snippet;
  } = $props();

  const WIDTH = 320;
  const GAP = 8;

  let menu = $state<HTMLElement>();
  // The form starts from the filter in force when the menu opens; the menu closes once one is applied.
  // svelte-ignore state_referenced_locally
  let form = $state<MenuForm>(formFrom(current, numeric));
  let problem = $state<string | null>(null);
  const ops = $derived(menuOps(numeric));
  const needsValue = $derived(form.op !== 'present' && form.op !== 'missing');
  const place = (() => {
    const rect = anchor.getBoundingClientRect();
    const left = Math.max(GAP, Math.min(rect.right - WIDTH, window.innerWidth - WIDTH - GAP));
    return { left, top: rect.bottom + 4 };
  })();

  onMount(() => {
    menu?.querySelector<HTMLElement>('button, select, input')?.focus();
    const outside = (event: PointerEvent) => {
      const target = event.target as Node;
      if (!menu?.contains(target) && !anchor.contains(target)) onclose();
    };
    // The menu is placed against the button; once the page moves under it, it would point at nothing.
    const away = () => onclose();
    window.addEventListener('pointerdown', outside, true);
    window.addEventListener('resize', away);
    return () => {
      window.removeEventListener('pointerdown', outside, true);
      window.removeEventListener('resize', away);
    };
  });

  function onwindowkey(event: KeyboardEvent): void {
    if (event.key !== 'Escape' || event.defaultPrevented || pageTopLayer() !== 'column') return;
    event.preventDefault();
    onclose();
  }

  function apply(filter: ColumnFilter | null): void {
    problem = onapply(filter);
    if (problem === null) onclose();
  }

  function submit(event: SubmitEvent): void {
    event.preventDefault();
    const filter = filterFrom(form);
    if ('problem' in filter) problem = filter.problem;
    else apply(filter);
  }
</script>

<svelte:window onkeydown={onwindowkey} />

<div class="menu" role="dialog" aria-label={`Filter and sort ${title}`} data-column-menu bind:this={menu}
  style:left={`${place.left}px`} style:top={`${place.top}px`} style:width={`${WIDTH}px`} style:max-height={`calc(100vh - ${place.top + GAP}px)`}>
  <p class="title">{title}</p>
  <div class="sort" role="group" aria-label="Sort">
    <button type="button" aria-pressed={sort === 'ascending'} onclick={() => onsort(false)}>Sort ascending ↑</button>
    <button type="button" aria-pressed={sort === 'descending'} onclick={() => onsort(true)}>Sort descending ↓</button>
  </div>
  <form onsubmit={submit}>
    {#if current.kind === 'custom'}
      <p class="note">Filtered by <code>{current.text}</code>. Apply replaces it.</p>
    {:else if current.kind === 'filter' && current.filter.op === 'oneOf'}
      <p class="note">{current.filter.negate ? 'Leaving out' : 'Showing only'} {current.filter.values.length} values. Apply replaces them.</p>
    {/if}
    <div class="line">
      <label class="not" class:hidden={!needsValue}><input type="checkbox" bind:checked={form.not} disabled={!needsValue} /> Not</label>
      <select aria-label={`How ${title} matches`} bind:value={form.op}>
        {#each ops as op (op.value)}<option value={op.value}>{op.label}</option>{/each}
      </select>
    </div>
    {#if needsValue}
      <div class="line">
        <input type="text" aria-label={form.op === 'between' ? 'From' : 'Value'} bind:value={form.value} spellcheck="false" autocomplete="off" />
        {#if form.op === 'between'}<span>and</span><input type="text" aria-label="To" bind:value={form.value2} spellcheck="false" autocomplete="off" />{/if}
      </div>
    {/if}
    {#if problem}<p class="note failure" role="alert">{problem}</p>{/if}
    <div class="line actions">
      <button type="submit" class="primary">Apply</button>
      <button type="button" disabled={current.kind === 'none'} onclick={() => apply(null)}>Clear</button>
    </div>
  </form>
  {#if values}{@render values(apply)}{/if}
  {#if column}<div class="column" role="group" aria-label="Column">{@render column()}</div>{/if}
</div>

<style>
  .menu { position: fixed; z-index: 30; box-sizing: border-box; overflow: auto; padding: 10px 12px; display: grid; gap: 10px; background: var(--panel);
    border: 1px solid var(--rule); border-radius: var(--radius); box-shadow: 0 6px 24px rgb(0 0 0 / 0.18); font: 400 var(--t-13) / 1.4 var(--sans); color: var(--ink); }
  .title { margin: 0; font-weight: 600; overflow-wrap: anywhere; }
  .sort, .column { display: flex; flex-wrap: wrap; gap: 6px; }
  form { display: grid; gap: 6px; }
  .line { display: flex; align-items: center; gap: 6px; }
  .line input[type='text'], select { flex: 1; min-width: 0; height: 28px; box-sizing: border-box; padding: 0 6px; font: 400 var(--t-13) / 1 var(--mono);
    color: var(--ink); background: var(--paper); border: 1px solid var(--rule); border-radius: var(--radius); }
  select { font-family: var(--sans); }
  .not { display: inline-flex; align-items: center; gap: 4px; white-space: nowrap; }
  .not.hidden { visibility: hidden; }
  /* The table's own controls arrive as a snippet, styled by the table's component unless styled here. */
  button, .column :global(button) { background: none; border: 1px solid var(--rule); border-radius: var(--radius); padding: 3px 10px; min-height: 28px;
    cursor: pointer; color: var(--ink); font: inherit; }
  button:disabled, .column :global(button:disabled) { opacity: 0.5; cursor: default; }
  button[aria-pressed='true'] { border-color: var(--signal); color: var(--signal); }
  .primary { border-color: var(--signal); color: var(--signal); font-weight: 600; }
  .note { margin: 0; font-size: var(--t-12); color: var(--ink-2); }
  .note code { font-family: var(--mono); overflow-wrap: anywhere; }
  .failure { color: var(--danger); }
  .column { border-top: 1px solid var(--rule); padding-top: 8px; }
</style>
