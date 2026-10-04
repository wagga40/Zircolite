<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Field, Schema } from '../engine/schema';
  import { view } from '../state/view.svelte';
  import { ui } from '../ui/ui.svelte';
  import { toggleColumn } from './columns';
  import FacetValues from './FacetValues.svelte';
  import { filterFields, percent } from './sidebar';

  let { db, schema, manifest, where, columns }: { db: Db; schema: Schema; manifest: Manifest; where: string; columns: Field[] } = $props();

  let text = $state('');
  let open = $state<string[]>([]);

  const shownKeys = $derived(new Set(columns.map((field) => field.key)));
  const list = $derived(filterFields(schema.fields, text, columns.map((field) => field.name)));

  function toggle(field: Field): void {
    open = open.includes(field.key) ? open.filter((key) => key !== field.key) : [...open, field.key];
  }
</script>

<aside id="field-sidebar" class="sidebar" class:open={ui.fieldsOpen} aria-label="Fields">
  <div class="head">
    <h2>Fields</h2>
    <label class="visually-hidden" for="field-filter">Filter fields</label>
    <input id="field-filter" type="search" placeholder="Filter fields" autocomplete="off" spellcheck="false" bind:value={text} />
  </div>
  {#if list.length === 0}
    <p class="empty">No field name contains “{text}”.</p>
  {/if}
  <ul>
    {#each list as field (field.key)}
      <li>
        <button type="button" class="field" aria-expanded={open.includes(field.key)} onclick={() => toggle(field)}>
          <span class="name">{field.name}</span>
          {#if shownKeys.has(field.key)}<span class="shown">column</span>{/if}
          <span class="count" title={`${field.count.toLocaleString('en-US')} of ${manifest.totals.events.toLocaleString('en-US')} events have this field`}>
            {percent(field.count, manifest.totals.events)}
          </span>
        </button>
        {#if open.includes(field.key)}
          <FacetValues
            {db}
            {field}
            {where}
            shown={shownKeys.has(field.key)}
            ontoggle={() => (view.cols = toggleColumn(columns.map((f) => f.name), field.name))}
          />
        {/if}
      </li>
    {/each}
  </ul>
</aside>

<style>
  .sidebar { min-height: 0; overflow: auto; background: var(--panel); border-right: 1px solid var(--rule); padding: 0 12px 16px; }
  .head { position: sticky; top: 0; background: var(--panel); padding: 12px 0 8px; z-index: 1; }
  h2 { font-size: var(--t-15); font-weight: 600; margin: 0 0 8px; }
  input { width: 100%; font: 400 var(--t-13) / 1.4 var(--sans); color: var(--ink); background: var(--paper); border: 1px solid var(--rule); border-radius: var(--radius); padding: 5px 8px; }
  ul { list-style: none; margin: 0; padding: 0; }
  .field { display: flex; width: 100%; gap: 6px; align-items: baseline; background: none; border: 0; padding: 4px 2px; cursor: pointer; text-align: left; border-radius: var(--radius); }
  .field:hover { background: color-mix(in srgb, var(--signal) 8%, transparent); }
  .name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: var(--t-13); }
  .field[aria-expanded='true'] .name { font-weight: 600; }
  .shown { font-size: var(--t-12); color: var(--signal); }
  .count { font-size: var(--t-12); color: var(--ink-2); }
  .empty { font-size: var(--t-13); color: var(--ink-2); }
  .visually-hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
  @media (max-width: 720px) {
    .sidebar { display: none; position: absolute; inset: 0 auto 0 0; width: min(320px, 85vw); z-index: 30; box-shadow: 4px 0 16px rgb(0 0 0 / 0.18); }
    .sidebar.open { display: block; }
  }
</style>
