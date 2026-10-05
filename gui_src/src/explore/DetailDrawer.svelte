<script lang="ts">
  import { fly } from 'svelte/transition';
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import { levelInk } from '../engine/levels';
  import { nameResolver } from '../engine/names';
  import { isSuperseded } from '../engine/queries';
  import type { Schema } from '../engine/schema';
  import { appendRaw, appendTerm, quoteValue } from '../search/edit';
  import { run, runAgain } from '../state/run.svelte';
  import { view } from '../state/view.svelte';
  import { copyText } from '../ui/clipboard';
  import { isoTime } from '../ui/format';
  import { focusFallback } from '../ui/focus';
  import { pageTopLayer } from '../ui/layers';
  import {
    type Entry, familyFields, groupEntries, type Head, headSql, hostEntry, isCurrent, nearbyRange, type RuleRow, rulesSql, valuesSql,
  } from './detail';
  import { eventJson } from './export';

  let { db, schema, manifest }: { db: Db; schema: Schema; manifest: Manifest } = $props();

  interface Loaded {
    uid: number;
    head: Head;
    entries: Entry[];
    rules: RuleRow[];
  }

  let loaded = $state.raw<Loaded | null>(null);
  let failure = $state<string | null>(null);
  let stopped = $state(false);
  // Choosing the open event again changes nothing, so a failed read is retried from its own button.
  let attempt = $state(0);
  let raw = $state(false);
  let status = $state('');
  // Stepping with j and k leaves focus in the table, so the new event is announced instead.
  let spoken = $state('');
  let heading = $state<HTMLHeadingElement>();
  let element = $state<HTMLElement>();
  let opener: HTMLElement | null = null;
  let ticket = 0;
  let focused = false;
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

  // A drawer closing keeps its content for the slide; only a switch to another event makes it stale.
  // A failed load is not a pending one, so the header stays readable beside its error.
  const stale = $derived(view.uid !== null && failure === null && !stopped && !isCurrent(loaded, view.uid));
  const groups = $derived(loaded ? groupEntries(loaded.entries) : []);
  const host = $derived(loaded ? hostEntry(loaded.entries) : null);
  const title = $derived(loaded ? titleOf(loaded) : 'Event');

  function titleOf(l: Loaded): string {
    return [l.head._zl_channel ?? 'Event', l.head._zl_eventid ?? ''].join(' ').trim();
  }

  async function load(uid: number): Promise<Loaded> {
    const [head] = await db.rows<Head>(headSql(schema, uid), { lane: 'drawer' });
    if (!head) throw new Error('this package holds no event with that id; the link may come from another package');
    const fields = familyFields(manifest, schema, head._zl_channel, head._zl_eventid);
    const [values] = await db.rows<Record<string, string | null>>(valuesSql(fields, uid), { lane: 'drawer' });
    const rules = await db.rows<RuleRow>(rulesSql(uid), { lane: 'drawer' });
    const name = nameResolver(manifest, head._zl_part, head._zl_spelling);
    const entries = fields.flatMap((field, i) => {
      const value = values?.[`_zl_v${i}`];
      return value === null || value === undefined ? [] : [{ field, name: name(field), value }];
    });
    return { uid, head, entries, rules };
  }

  $effect(() => {
    const uid = view.uid;
    const mine = ++ticket;
    // The drawer is not tied to a view: it stays open across a route switch. A deep link or Back leaves focus on the body, which is no opener.
    if (uid !== null && opener === null && document.activeElement instanceof HTMLElement && document.activeElement !== document.body && !element?.contains(document.activeElement)) {
      opener = document.activeElement;
    }
    // Closing keeps what is shown until the outro ends, so the drawer does not flash empty while it slides away.
    if (uid === null) {
      // Back closes the drawer as well as Escape does; either way focus goes back where it came from.
      if (document.activeElement === document.body || element?.contains(document.activeElement)) focusFallback(opener)?.focus();
      opener = null;
      focused = false;
      spoken = '';
      return;
    }
    // Read only while open: Run again pressed elsewhere must not move focus out of a closed drawer.
    void run.generation;
    void attempt;
    failure = null;
    stopped = false;
    status = '';
    load(uid).then(
      (result) => {
        if (mine !== ticket) return;
        loaded = result;
        if (focused) spoken = `${titleOf(result)}, ${result.head._zl_t === null ? 'no time' : `${isoTime(result.head._zl_t)} UTC`}`;
      },
      (error: unknown) => {
        if (mine !== ticket) return;
        loaded = null;
        if (!isSuperseded(error)) failure = error instanceof Error ? error.message : String(error);
        else if (run.stopped) stopped = true;
        // A newer event would have moved the ticket on, so nothing else of the drawer's replaced this one.
        else failure = 'the query was interrupted';
      },
    );
  });

  // Move focus into the drawer when it opens, not on every event shown in it.
  $effect(() => {
    if ((loaded || failure || stopped) && heading && !focused) {
      focused = true;
      heading.focus();
    }
  });

  function settle(): void {
    if (view.uid === null) {
      loaded = null;
      failure = null;
      stopped = false;
    }
  }

  function close(): void {
    const back = focusFallback(opener);
    opener = null;
    view.uid = null;
    back?.focus();
  }

  function onkeydown(event: KeyboardEvent): void {
    if (event.key === 'Escape' && !event.defaultPrevented && pageTopLayer() === 'drawer') {
      event.preventDefault();
      close();
    }
  }

  function json(pretty: boolean): string {
    return eventJson((loaded?.entries ?? []).map((entry) => ({ name: entry.name, type: entry.field.type, text: entry.value })), pretty);
  }

  async function copy(text: string, what: string): Promise<void> {
    if (stale) return;
    status = (await copyText(text)) ? `Copied ${what}.` : `Copying ${what} failed; select it and copy it with the keyboard.`;
  }

  function nearby(): void {
    if (stale || !loaded || !host || loaded.head._zl_t === null) return;
    view.q = appendTerm('', host.field.name, host.value, false);
    view.t = nearbyRange(loaded.head._zl_t);
    view.d = false;
  }

  function filterRule(rule: RuleRow): void {
    if (stale) return;
    view.q = appendRaw(view.q, `rulekey:${quoteValue(rule.key)}`);
  }
</script>

<svelte:window {onkeydown} />

{#if view.uid !== null}
  <aside class="drawer" bind:this={element} aria-label="Event details" transition:fly={{ x: 48, duration: reduced ? 0 : 120 }} onoutroend={settle}>
    <p class="visually-hidden" aria-live="polite">{spoken}</p>
    <header>
      <div class="dims" aria-busy={stale}>
        <h2 tabindex="-1" bind:this={heading}>{title}</h2>
        <p class="sub">
          {#if loaded}{loaded.head._zl_t === null ? 'No time' : `${isoTime(loaded.head._zl_t)} UTC`}{/if}
        </p>
      </div>
      <button type="button" class="close" onclick={close}>Close</button>
    </header>

    {#if failure}
      <p class="note failure" role="alert">
        This event could not be read: {failure}. <button type="button" onclick={() => attempt++}>Read it again</button> If this repeats, reload the page.
      </p>
    {:else if stopped}
      <p class="note" role="status">Stopped. <button type="button" onclick={runAgain}>Run again</button></p>
    {:else if !loaded}
      <p class="note">Reading the event</p>
    {:else}
      <div class="dims" aria-busy={stale}>
        <div class="actions">
          <button type="button" disabled={stale} aria-pressed={raw} onclick={() => (raw = !raw)}>{raw ? 'Show fields' : 'Show JSON'}</button>
          <button type="button" disabled={stale} onclick={() => copy(json(true), 'the event as JSON')}>Copy JSON</button>
          {#if host && loaded.head._zl_t !== null}
            <button type="button" disabled={stale} onclick={nearby}>Events on {host.value} within 5 minutes</button>
          {/if}
        </div>
        <p class="status" role="status">{status}</p>

        {#if loaded.rules.length}
          <section class="rules" aria-label="Detections">
            <h3>Detections</h3>
            <ul>
              {#each loaded.rules as rule (rule.rule_idx)}
                <li>
                  <span class="sev"><i style:background={levelInk(rule.level_rank)}></i>{rule.level}</span>
                  <span class="rule-title">{rule.title}</span>
                  {#if rule.techniques?.length}<span class="techniques">{rule.techniques.join(', ')}</span>{/if}
                  <button type="button" disabled={stale} onclick={() => filterRule(rule)}>Filter by this rule</button>
                </li>
              {/each}
            </ul>
          </section>
        {/if}

        {#if raw}
          <pre class="json">{json(true)}</pre>
        {:else}
          {#each groups as group (group.name)}
            <section class="group" aria-label={group.name}>
              <h3>{group.name}</h3>
              <dl>
                {#each group.entries as entry (entry.field.key)}
                  <div class="entry">
                    <dt>{entry.name}</dt>
                    <dd>
                      <span class="value">{entry.value}</span>
                      <span class="tools">
                        <button type="button" disabled={stale} aria-label={`Filter for ${entry.name}`} onclick={() => (view.q = appendTerm(view.q, entry.field.name, entry.value, false))}>+</button>
                        <button type="button" disabled={stale} aria-label={`Filter out ${entry.name}`} onclick={() => (view.q = appendTerm(view.q, entry.field.name, entry.value, true))}>−</button>
                        <button type="button" disabled={stale} aria-label={`Copy ${entry.name}`} onclick={() => copy(entry.value, entry.name)}>Copy</button>
                      </span>
                    </dd>
                  </div>
                {/each}
              </dl>
            </section>
          {/each}
        {/if}
      </div>
    {/if}
  </aside>
{/if}

<style>
  .drawer { position: absolute; top: 0; right: 0; bottom: 0; z-index: 40; width: min(var(--drawer-w), 100%); overflow: auto; background: var(--panel); border-left: 1px solid var(--rule); box-shadow: -6px 0 18px rgb(0 0 0 / 0.14); padding: 0 18px 24px; }
  header { position: sticky; top: 0; z-index: 1; display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; padding: 14px 0 10px; background: var(--panel); border-bottom: 1px solid var(--rule); }
  h2 { margin: 0; width: fit-content; font-size: var(--t-18); font-weight: 600; }
  h2:focus { outline: none; }
  h2:focus-visible { outline: 2px solid var(--signal); outline-offset: 2px; }
  .sub { margin: 2px 0 0; font: 400 var(--t-13) / 1.4 var(--mono); color: var(--ink-2); }
  h3 { font-size: var(--t-13); font-weight: 600; color: var(--ink-2); margin: 18px 0 6px; }
  button { background: none; border: 1px solid var(--rule); border-radius: var(--radius); padding: 3px 10px; cursor: pointer; }
  button:disabled { cursor: default; }
  .actions { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 12px; }
  .status { min-height: 1.2em; margin: 6px 0 0; font-size: var(--t-12); color: var(--ink-2); }
  .note { margin: 14px 0; color: var(--ink-2); }
  .failure { color: var(--danger); }
  .rules ul { list-style: none; margin: 0; padding: 0; }
  .rules li { display: grid; grid-template-columns: 110px minmax(0, 1fr) auto; gap: 2px 10px; align-items: baseline; padding: 6px 0; border-bottom: 1px solid color-mix(in srgb, var(--rule) 60%, transparent); }
  .rules li button { grid-column: 3; grid-row: 1 / span 2; align-self: center; font-size: var(--t-12); }
  .sev { display: inline-flex; align-items: center; gap: 6px; font-size: var(--t-13); }
  .sev i { display: inline-block; width: 8px; height: 8px; border-radius: 1px; }
  .rule-title { font-weight: 600; }
  .techniques { grid-column: 2; font: 400 var(--t-12) / 1.4 var(--mono); color: var(--ink-2); }
  dl { margin: 0; }
  .entry { display: grid; grid-template-columns: minmax(110px, 34%) minmax(0, 1fr); gap: 10px; padding: 4px 0; border-bottom: 1px solid color-mix(in srgb, var(--rule) 45%, transparent); }
  dt { font-size: var(--t-13); color: var(--ink-2); overflow-wrap: anywhere; }
  dd { margin: 0; display: flex; gap: 6px; align-items: flex-start; }
  .value { flex: 1; min-width: 0; font: 400 var(--t-13) / 1.45 var(--mono); white-space: pre-wrap; overflow-wrap: anywhere; }
  .tools { display: inline-flex; gap: 2px; opacity: 0; }
  .entry:hover .tools, .entry:focus-within .tools { opacity: 1; }
  .tools button { min-width: 24px; min-height: 24px; padding: 0 6px; font-size: var(--t-12); border-color: transparent; }
  .tools button:hover { border-color: var(--rule); }
  .json { margin: 14px 0 0; padding: 12px; background: var(--paper); border: 1px solid var(--rule); border-radius: var(--radius); font: 400 var(--t-13) / 1.45 var(--mono); white-space: pre-wrap; overflow-wrap: anywhere; }
  .visually-hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
  @media (max-width: 720px) {
    .entry { grid-template-columns: minmax(0, 1fr); gap: 2px; }
    dt { font-size: var(--t-12); }
  }
  @media (hover: none) {
    .tools { opacity: 1; }
  }
</style>
