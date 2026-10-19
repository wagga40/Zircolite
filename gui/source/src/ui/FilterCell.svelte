<script lang="ts">
  import { untrack } from 'svelte';

  let { label, text, apply, locked = null, onclear, onproblem }: {
    /** The column's name, for the input's accessible name. */
    label: string;
    /** What the cell shows for the filter in force. */
    text: string;
    /** Applies typed text: null once it is in force, or why it cannot be. */
    apply: (text: string) => string | null;
    /** Why the cell cannot be typed in, such as a combined filter the cell cannot show. */
    locked?: string | null;
    onclear?: () => void;
    /** Hears why typed text was refused, and null once that no longer stands; the table says it where there is room. */
    onproblem?: (problem: string | null) => void;
  } = $props();

  let draft = $state('');
  let problem = $state<string | null>(null);

  function report(next: string | null): void {
    if (next === problem) return;
    problem = next;
    onproblem?.(next);
  }

  // The filter also changes from outside: the search bar, a chip, Back. Only that change resets the cell,
  // not the refusal it reports.
  $effect(() => {
    const shown = text;
    untrack(() => {
      draft = shown;
      report(null);
    });
  });

  function commit(): void {
    report(draft === text ? null : apply(draft));
  }

  function onkeydown(event: KeyboardEvent): void {
    if (event.key === 'Enter') {
      commit();
      event.preventDefault();
    } else if (event.key === 'Escape' && (draft !== text || problem)) {
      // Only an edit is undone here; with nothing to undo, Escape goes on to close what is open.
      draft = text;
      report(null);
      event.preventDefault();
      event.stopPropagation();
    }
  }

  function onblur(): void {
    // Leaving the window is not leaving the cell: switching apps must not apply half-typed text.
    if (document.hasFocus()) commit();
  }
</script>

<span class="cell" class:active={text !== ''}>
  {#if locked}
    <span class="locked" title={locked}>{text}</span>
    {#if onclear}<button type="button" class="clear" aria-label={`Clear the filter on ${label}`} onclick={onclear}>×</button>{/if}
  {:else}
    <input
      type="text"
      bind:value={draft}
      aria-label={`Filter ${label}`}
      aria-invalid={problem !== null}
      title={problem ?? 'Contains this text. =x is exact, * a wildcard, "…" literal, >5 compares, ! leaves out; Enter applies'}
      placeholder="Filter"
      spellcheck="false"
      autocomplete="off"
      {onkeydown}
      {onblur}
    />
  {/if}
</span>

<style>
  .cell { display: flex; align-items: center; gap: 2px; min-width: 0; }
  input { width: 100%; min-width: 0; height: 24px; box-sizing: border-box; padding: 0 6px; font: 400 var(--t-12) / 1 var(--mono); color: var(--ink);
    background: var(--paper); border: 1px solid var(--rule); border-radius: var(--radius); }
  input::placeholder { color: var(--ink-2); opacity: 0.7; }
  .active input, .active .locked { border-color: var(--signal); }
  input[aria-invalid='true'] { border-color: var(--danger); }
  .locked { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; height: 24px; box-sizing: border-box; padding: 0 6px;
    font: 400 var(--t-12) / 22px var(--mono); color: var(--ink-2); border: 1px dashed var(--rule); border-radius: var(--radius); }
  .clear { background: none; border: 0; cursor: pointer; color: var(--ink-2); min-width: 20px; min-height: 24px; padding: 0; }
</style>
