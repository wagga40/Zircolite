<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Schema } from '../engine/schema';
  import { formatRange } from '../explore/histogram';
  import { suggestValuesSql } from '../explore/sidebar';
  import { compile } from '../search/compile';
  import { chips, type Completion, completionAt, fieldSuggestions, quoteValue, removeSpan } from '../search/edit';
  import { parse } from '../search/parse';
  import { SHORTCUTS, SYNTAX } from '../search/shortcuts';
  import { SearchError } from '../search/tokens';
  import { view } from '../state/view.svelte';
  import { ui } from './ui.svelte';

  let { db, schema }: { db: Db; schema: Schema } = $props();

  let input: HTMLInputElement;
  let draft = $state('');
  let error = $state<SearchError | null>(null);
  let options = $state<string[]>([]);
  let active = $state(-1);
  let context: Completion | null = null;
  let lookup = 0;
  let failure = $state<string | null>(null);

  const items = $derived(chips(view.q));

  function check(text: string): SearchError | null {
    try {
      compile(parse(text), schema);
      return null;
    } catch (problem) {
      if (problem instanceof SearchError) return problem;
      throw problem;
    }
  }

  // The committed query also changes from outside: the sidebar, the event view, Back.
  $effect(() => {
    draft = view.q;
    error = view.q ? check(view.q) : null;
  });

  // Bumping the ticket also drops a lookup still in flight, so it cannot reopen the list.
  function closeOptions(): void {
    lookup += 1;
    options = [];
    active = -1;
  }

  function submit(): void {
    closeOptions();
    failure = null;
    error = check(draft);
    if (!error) view.q = draft.trim();
  }

  async function suggest(): Promise<void> {
    const caret = input.selectionStart ?? draft.length;
    context = completionAt(draft, caret);
    closeOptions();
    const ticket = lookup;
    if (!context) return;
    if (context.kind === 'field') {
      options = fieldSuggestions(context.prefix, schema);
      return;
    }
    const field = schema.find(context.field);
    if (!field) return;
    try {
      const rows = await db.rows<{ v: string }>(suggestValuesSql(field, context.prefix));
      if (ticket === lookup) {
        options = rows.map((row) => row.v);
        failure = null;
      }
    } catch (problem) {
      if (ticket === lookup) {
        failure = `Could not look up values for ${field.name}: ${problem instanceof Error ? problem.message : String(problem)}`;
      }
    }
  }

  function accept(option: string): void {
    if (!context) return;
    const insert = context.kind === 'field' ? `${option}:` : /^[\w.@-]+$/.test(option) ? option : quoteValue(option);
    draft = draft.slice(0, context.start) + insert + draft.slice(context.end);
    const caret = context.start + insert.length;
    closeOptions();
    error = null;
    queueMicrotask(() => {
      input.focus();
      input.setSelectionRange(caret, caret);
    });
  }

  function onkeydown(event: KeyboardEvent): void {
    if (options.length && (event.key === 'ArrowDown' || event.key === 'ArrowUp')) {
      event.preventDefault();
      const step = event.key === 'ArrowDown' ? 1 : -1;
      active = (active + step + options.length) % options.length;
    } else if (options.length && active >= 0 && (event.key === 'Tab' || event.key === 'Enter')) {
      event.preventDefault();
      accept(options[active]);
    } else if (options.length && event.key === 'Tab') {
      closeOptions();
    } else if (event.key === 'Enter') {
      event.preventDefault();
      submit();
    } else if (event.key === 'Escape') {
      if (options.length) {
        closeOptions();
        event.stopPropagation();
      } else if (draft !== view.q) {
        draft = view.q;
        error = null;
        event.stopPropagation();
      } else if (ui.help) {
        ui.help = false;
      }
    }
  }

  // The caret has moved by key-up, so the completion context is current again.
  function onkeyup(event: KeyboardEvent): void {
    if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) void suggest();
  }
</script>

<div class="search" role="search">
  <div class="field">
    <label class="visually-hidden" for="search-input">Search events</label>
    <input
      id="search-input"
      bind:this={input}
      bind:value={draft}
      type="text"
      spellcheck="false"
      autocomplete="off"
      placeholder="Search events, for example host:DC01 -EventID:4634 powershell"
      role="combobox"
      aria-autocomplete="list"
      aria-expanded={options.length > 0}
      aria-controls={options.length ? 'search-options' : undefined}
      aria-activedescendant={active >= 0 ? `search-option-${active}` : undefined}
      aria-invalid={error ? 'true' : undefined}
      aria-describedby={error ? 'search-error' : undefined}
      oninput={suggest}
      onclick={suggest}
      {onkeydown}
      {onkeyup}
      onblur={closeOptions}
    />
    <button type="button" class="syntax" aria-expanded={ui.help} aria-controls="search-help" onclick={() => (ui.help = !ui.help)}>Syntax</button>
    {#if options.length}
      <ul id="search-options" role="listbox" aria-label="Suggestions">
        {#each options as option, i (option)}
          <li id={`search-option-${i}`} role="option" aria-selected={i === active} onmousedown={(event) => { event.preventDefault(); accept(option); }}>{option}</li>
        {/each}
      </ul>
    {/if}
  </div>
  {#if error}
    <p id="search-error" class="error" role="alert">{error.message} (at character {error.start + 1}).</p>
  {:else if failure}
    <p class="error" role="alert">{failure}</p>
  {/if}
  {#if items.length || view.t || view.d}
    <ul class="chips" aria-label="Active filters">
      {#each items as chip (chip.start)}
        <li>
          <span>{chip.negated ? 'not ' : ''}{chip.label}</span>
          <button type="button" aria-label={`Remove ${chip.negated ? 'not ' : ''}${chip.label}`} onclick={() => (view.q = removeSpan(view.q, chip.start, chip.end))}>×</button>
        </li>
      {/each}
      {#if view.t}
        <li>
          <span>{formatRange(view.t)} UTC</span>
          <button type="button" aria-label="Remove the time range" onclick={() => (view.t = null)}>×</button>
        </li>
      {/if}
      {#if view.d}
        <li>
          <span>Detections only</span>
          <button type="button" aria-label="Show events without detections too" onclick={() => (view.d = false)}>×</button>
        </li>
      {/if}
    </ul>
  {/if}
  {#if ui.help}
    <section id="search-help" class="help" aria-label="Search syntax">
      <table>
        <tbody>
          <tr><th colspan="2" scope="colgroup">Search syntax</th></tr>
          {#each SYNTAX as row}<tr><th scope="row"><code>{row.pattern}</code></th><td>{row.meaning}</td></tr>{/each}
        </tbody>
        <tbody>
          <tr><th colspan="2" scope="colgroup">Shortcuts</th></tr>
          {#each SHORTCUTS as row}<tr><th scope="row"><code>{row.example}</code></th><td>{`${row.description}${row.fields ? ` Fields: ${row.fields.join(', ')}.` : ''}`}</td></tr>{/each}
        </tbody>
      </table>
      <p>Keys: / searches, ? shows this help, Esc closes, j and k move through events, Enter opens one.</p>
    </section>
  {/if}
</div>

<style>
  .search { position: relative; flex: 1; min-width: 0; }
  .field { display: flex; gap: 6px; position: relative; }
  input { flex: 1; min-width: 0; font: 400 var(--t-15) / 1.4 var(--mono); color: var(--ink); background: var(--paper); border: 1px solid var(--rule); border-radius: var(--radius); padding: 7px 10px; }
  input[aria-invalid='true'] { border-color: var(--danger); }
  .syntax { background: none; border: 1px solid var(--rule); border-radius: var(--radius); padding: 0 10px; cursor: pointer; color: var(--ink-2); }
  [role='listbox'] { position: absolute; top: 100%; left: 0; right: 0; z-index: 20; list-style: none; margin: 4px 0 0; padding: 4px; background: var(--panel); border: 1px solid var(--rule); border-radius: var(--radius); max-height: 18rem; overflow: auto; }
  [role='option'] { padding: 4px 8px; font: 400 var(--t-13) / 1.4 var(--mono); cursor: pointer; overflow-wrap: anywhere; }
  [role='option'][aria-selected='true'] { background: color-mix(in srgb, var(--signal) 16%, transparent); }
  .error { color: var(--danger); margin: 6px 0 0; font-size: var(--t-13); }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; list-style: none; margin: 8px 0 0; padding: 0; }
  .chips li { max-width: 100%; display: inline-flex; align-items: center; gap: 4px; font: 400 var(--t-12) / 1.6 var(--mono); border: 1px solid var(--rule); border-radius: var(--radius); padding: 0 2px 0 8px; background: var(--paper); }
  .chips button { background: none; border: 0; cursor: pointer; padding: 0 6px; color: var(--ink-2); }
  .help { max-height: 70vh; overflow: auto; position: absolute; z-index: 15; top: 100%; right: 0; width: min(44rem, 100%); margin-top: 6px; padding: 12px 16px; background: var(--panel); border: 1px solid var(--rule); border-radius: var(--radius); font-size: var(--t-13); }
  .help table { border-collapse: collapse; width: 100%; margin-bottom: 10px; }
  .help th[scope='colgroup'] { text-align: left; font-weight: 600; padding: 8px 0 4px; }
  .help th { text-align: left; font-weight: 400; padding: 3px 12px 3px 0; white-space: nowrap; vertical-align: top; }
  .help td { padding: 3px 0; color: var(--ink-2); }
  .chips span { overflow-wrap: anywhere; }
  @media (max-width: 720px) {
    .help tr { display: block; padding: 4px 0; }
    .help th, .help td { display: block; padding: 0; white-space: normal; overflow-wrap: anywhere; }
  }
  code { font-family: var(--mono); }
  .visually-hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
</style>
