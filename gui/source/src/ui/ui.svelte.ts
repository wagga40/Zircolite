import { tick } from 'svelte';

/**
 * Page-level panels that several components open and close, and an event the
 * events table is asked to scroll to once its list is built.
 */
export const ui = $state<{ help: boolean; fieldsOpen: boolean; locate: number | null }>({ help: false, fieldsOpen: false, locate: null });

/** Closes the Fields panel and puts focus back on its button once the page behind the sheet is live again. */
export async function closeFields(): Promise<void> {
  ui.fieldsOpen = false;
  // The page behind a phone sheet is inert until the flush that follows; an inert button cannot take focus.
  await tick();
  document.getElementById('fields-toggle')?.focus();
}
