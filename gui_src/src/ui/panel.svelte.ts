import { untrack } from 'svelte';
import { isSuperseded } from '../engine/queries';
import { run } from '../state/run.svelte';

export interface Slot<T> {
  data: T | null;
  pending: boolean;
  failure: string | null;
  stopped: boolean;
}

/**
 * What a request that did not answer leaves on screen. Never the earlier
 * answer: it belongs to an earlier filter. A supersede that is not a Stop
 * means the request was replaced after its ticket was taken, and saying so
 * beats going blank.
 */
export function failedSlot<T>(error: unknown): Slot<T> {
  if (isSuperseded(error)) {
    return run.stopped
      ? { data: null, pending: false, failure: null, stopped: true }
      : { data: null, pending: false, failure: 'the query was interrupted', stopped: false };
  }
  return { data: null, pending: false, failure: error instanceof Error ? error.message : String(error), stopped: false };
}

/** One panel's answer to its latest request; an older answer arrives to nobody. */
export class Panel<T> {
  slot = $state.raw<Slot<T>>({ data: null, pending: true, failure: null, stopped: false });
  #ticket = 0;

  constructor(pending = true) {
    this.slot = { data: null, pending, failure: null, stopped: false };
  }

  /**
   * Ask again. The fetch runs on the next microtask, outside the effect that
   * calls this, so the effect must read its inputs before and close over them.
   */
  load(fetch: () => Promise<T>): void {
    const mine = ++this.#ticket;
    const shown = untrack(() => this.slot);
    this.slot = { data: shown.data, pending: true, failure: null, stopped: false };
    Promise.resolve()
      .then(fetch)
      .then(
        (data) => {
          if (mine === this.#ticket) this.slot = { data, pending: false, failure: null, stopped: false };
        },
        (error: unknown) => {
          if (mine === this.#ticket) this.slot = failedSlot<T>(error);
        },
      );
  }
}
