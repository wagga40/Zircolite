<script lang="ts">
  import { type Decoded, decodings } from './decode';
  import Self from './Decoded.svelte';

  let { value, name, oncopy, depth = 0 }: {
    value: string;
    /** The field the value belongs to, for the buttons' names. */
    name: string;
    oncopy: (text: string, what: string) => void;
    depth?: number;
  } = $props();

  /** Decodings nest this deep: Base64 inside Base64 inside a command line is common, a fourth layer is not. */
  const DEPTH = 3;

  let found = $state.raw<Decoded[]>([]);
  let open = $state(false);
  let ticket = 0;

  $effect(() => {
    const text = value;
    const mine = ++ticket;
    found = [];
    open = false;
    void decodings(text).then((result) => {
      if (mine === ticket) found = result;
    });
  });
</script>

{#if found.length > 0}
  <button type="button" class="toggle" aria-expanded={open} onclick={() => (open = !open)}
    aria-label={`${open ? 'Hide' : 'Show'} what ${name} decodes to`}>{open ? 'Hide decoded' : `Decode (${found.map((d) => d.label).join(', ')})`}</button>
  {#if open}
    <ul class="decoded">
      {#each found as decoded, i (i)}
        <li>
          <p class="label">{decoded.label}{decoded.truncated ? `, first ${Math.round(decoded.text.length / 1024)} KiB` : ''}
            <button type="button" aria-label={`Copy ${name} decoded from ${decoded.label}`} onclick={() => oncopy(decoded.text, `${name}, decoded`)}>Copy</button></p>
          <pre>{decoded.text}</pre>
          {#if depth + 1 < DEPTH}<Self value={decoded.text} {name} {oncopy} depth={depth + 1} />{/if}
        </li>
      {/each}
    </ul>
  {/if}
{/if}

<style>
  .toggle { margin-top: 4px; padding: 1px 8px; min-height: 24px; font-size: var(--t-12); background: none; border: 1px solid var(--signal); border-radius: var(--radius); color: var(--signal); cursor: pointer; }
  .decoded { list-style: none; margin: 6px 0 0; padding: 0 0 0 10px; border-left: 2px solid var(--signal); }
  .decoded li + li { margin-top: 8px; }
  .label { display: flex; align-items: center; gap: 8px; margin: 0 0 4px; font-size: var(--t-12); color: var(--ink-2); }
  .label button { padding: 0 6px; min-height: 22px; font-size: var(--t-12); background: none; border: 1px solid var(--rule); border-radius: var(--radius); cursor: pointer; }
  pre { margin: 0; max-height: 320px; overflow: auto; padding: 8px; font: 400 var(--t-13) / 1.45 var(--mono); white-space: pre-wrap; overflow-wrap: anywhere; background: var(--paper); border: 1px solid var(--rule); border-radius: var(--radius); }
</style>
