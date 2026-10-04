<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Schema } from '../engine/schema';
  import { appendRaw, quoteValue } from '../search/edit';
  import { view } from '../state/view.svelte';
  import { formatCount } from '../ui/format';
  import Alerts from './Alerts.svelte';
  import { levelLabel, type RuleGroup } from './rules';

  let { db, schema, group, expanded, ontoggle }: { db: Db; schema: Schema; group: RuleGroup; expanded: boolean; ontoggle: () => void } = $props();

  const first = $derived(group.variants[0]);
  const term = $derived(`rule:${quoteValue(group.key)}`);
</script>

<li class="rule">
  <button type="button" class="row" aria-expanded={expanded} data-key={group.key} data-events={group.events} onclick={ontoggle}>
    <span class="level"><i style:background={`var(--sev-${Math.max(0, group.rank)})`}></i>{levelLabel(group.rank)}</span>
    <span class="title">{group.title}</span>
    <span class="tactics">{group.tactics.join(', ')}</span>
    <span class="variants">{group.variants.length > 1 ? `${group.variants.length} variants` : ''}</span>
    <span class="n">{formatCount(group.events)}</span>
  </button>
  {#if expanded}
    <div class="details">
      <dl>
        {#if first.description}<dt>Description</dt><dd>{first.description}</dd>{/if}
        {#if first.falsepositives.length}<dt>False positives</dt><dd>{first.falsepositives.join('; ')}</dd>{/if}
        {#if group.techniques.length}<dt>Techniques</dt><dd class="mono">{group.techniques.join(', ')}</dd>{/if}
        {#if first.tags.length}<dt>Tags</dt><dd class="mono">{first.tags.join(', ')}</dd>{/if}
        <dt>Rule id</dt><dd class="mono">{first.id || 'none'}</dd>
      </dl>
      <table class="variants-table">
        <caption>Ruleset entries</caption>
        <thead><tr><th scope="col">Title</th><th scope="col">Level</th><th scope="col">Sigma file</th><th scope="col" class="num">Events</th></tr></thead>
        <tbody>
          {#each group.variants as variant (variant.rule_idx)}
            <tr><td>{variant.title}</td><td>{variant.level}</td><td class="mono">{variant.sigmafile || 'none'}</td><td class="num">{formatCount(variant.events)}</td></tr>
          {/each}
        </tbody>
      </table>
      <div class="actions">
        <button type="button" onclick={() => { view.q = appendRaw(view.q, term); view.route = 'explore'; }}>Show events</button>
        <button type="button" onclick={() => (view.q = appendRaw(view.q, term))}>Add to search</button>
      </div>
      {#if group.correlation}
        <Alerts {db} {schema} ruleIdx={group.variants.filter((v) => v.result_type === 'correlation').map((v) => v.rule_idx)} />
      {/if}
    </div>
  {/if}
</li>

<style>
  .rule { border-bottom: 1px solid var(--rule); }
  .row { display: grid; grid-template-columns: 112px minmax(0, 1fr) minmax(0, max-content) 72px 64px; gap: 12px; align-items: center; width: 100%; min-height: 36px; padding: 4px 16px; text-align: left; background: none; border: 0; cursor: pointer; }
  .row:hover { background: color-mix(in srgb, var(--signal) 6%, transparent); }
  .level { display: inline-flex; align-items: center; gap: 6px; font-size: var(--t-13); }
  .level i { width: 8px; height: 8px; border-radius: 1px; }
  .title { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .tactics, .variants { font-size: var(--t-12); color: var(--ink-2); white-space: nowrap; }
  .n { font: 400 var(--t-13) / 1 var(--mono); text-align: right; }
  .details { padding: 8px 16px 16px 140px; }
  dl { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 4px 16px; margin: 0 0 12px; }
  dt { color: var(--ink-2); font-size: var(--t-13); }
  dd { margin: 0; overflow-wrap: anywhere; }
  .mono { font: 400 var(--t-13) / 1.45 var(--mono); }
  table { border-collapse: collapse; width: 100%; font-size: var(--t-13); margin-bottom: 12px; }
  caption { text-align: left; color: var(--ink-2); padding-bottom: 4px; }
  th, td { text-align: left; padding: 2px 8px 2px 0; border-bottom: 1px solid color-mix(in srgb, var(--rule) 60%, transparent); }
  .num { text-align: right; }
  .actions { display: flex; gap: 8px; }
  .actions button { min-height: 28px; background: none; border: 1px solid var(--rule); border-radius: var(--radius); padding: 3px 10px; cursor: pointer; }
  @media (max-width: 720px) {
    .row { grid-template-columns: 96px minmax(0, 1fr) 64px; }
    .tactics, .variants { display: none; }
    .title { white-space: normal; overflow-wrap: anywhere; }
    .details { padding-left: 16px; }
  }
</style>
