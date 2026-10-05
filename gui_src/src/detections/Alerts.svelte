<script lang="ts">
  import type { Db } from '../engine/db';
  import { isSuperseded } from '../engine/queries';
  import type { Schema } from '../engine/schema';
  import { run, runAgain } from '../state/run.svelte';
  import { view } from '../state/view.svelte';
  import { formatCount, isoTime } from '../ui/format';
  import { ownScope } from '../ui/scope';
  import { type AlertRow, alertsSql, type EvidenceRow, evidenceSql, groupKeysText } from './rules';

  let { db: parent, schema, ruleIdx }: { db: Db; schema: Schema; ruleIdx: number[] } = $props();
  // Lanes of their own, so opening an alert of another rule does not supersede this one's evidence;
  // collapsing the rule stops them. A rule's correlation entries do not change while it is listed.
  // svelte-ignore state_referenced_locally
  const db = ownScope(parent, `alerts-${ruleIdx.join('-')}`);

  let alerts = $state.raw<AlertRow[] | null>(null);
  let failure = $state<string | null>(null);
  let stopped = $state(false);
  let open = $state<number | null>(null);
  let evidence = $state.raw<EvidenceRow[] | null>(null);
  let evidenceStopped = $state(false);
  let evidenceFailure = $state<string | null>(null);
  let ticket = 0;
  let evidenceTicket = 0;

  $effect(() => {
    void run.generation;
    const mine = ++ticket;
    failure = null;
    stopped = false;
    db.rows<AlertRow>(alertsSql(ruleIdx), { lane: 'list' }).then(
      (rows) => { if (mine === ticket) alerts = rows; },
      (error: unknown) => {
        if (mine !== ticket) return;
        if (!isSuperseded(error)) failure = error instanceof Error ? error.message : String(error);
        else if (run.stopped) {
          alerts = null;
          stopped = true;
        } else failure = 'the query was interrupted';
      },
    );
  });

  function load(alert: AlertRow): void {
    const mine = ++evidenceTicket;
    evidence = null;
    evidenceStopped = false;
    evidenceFailure = null;
    db.rows<EvidenceRow>(evidenceSql(alert.alert_idx, schema), { lane: 'evidence' }).then(
      (rows) => { if (mine === evidenceTicket) evidence = rows; },
      (error: unknown) => {
        if (mine !== evidenceTicket) return;
        if (!isSuperseded(error)) evidenceFailure = error instanceof Error ? error.message : String(error);
        else if (run.stopped) evidenceStopped = true;
        // No newer request of this panel replaced it, so no answer is coming: say so rather than read forever.
        else evidenceFailure = 'the query was interrupted';
      },
    );
  }

  function toggle(alert: AlertRow): void {
    if (open === alert.alert_idx) {
      open = null;
      evidenceTicket += 1;
      db.cancel('evidence');
      return;
    }
    open = alert.alert_idx;
    load(alert);
  }
</script>

<section class="alerts" aria-label="Correlation alerts">
  <h3>Alerts</h3>
  <p class="note">Alerts are listed for the whole package; the filters do not apply to them.</p>
  {#if failure}
    <p class="note failure" role="alert">The alerts could not be read: {failure}. Reload the page if this repeats.</p>
  {:else if stopped}
    <p class="note" role="status">Stopped. <button type="button" class="again" onclick={runAgain}>Run again</button></p>
  {:else if alerts === null}
    <p class="note">Reading the alerts</p>
  {:else if alerts.length === 0}
    <p class="note">This rule raised no alert.</p>
  {:else}
    {#if alerts[0].total > alerts.length}<p class="note">The first {formatCount(alerts.length)} of {formatCount(alerts[0].total)} alerts.</p>{/if}
    <ul>
      {#each alerts as alert (alert.alert_idx)}
        <li>
          <button type="button" class="alert" aria-expanded={open === alert.alert_idx} onclick={() => toggle(alert)}>
            <span class="when">{isoTime(alert.occurrence, false) || 'no time'}</span>
            <span class="keys">{groupKeysText(alert.group_keys) || 'No group keys'}</span>
            <span class="metric">{alert.metric_name ?? 'metric'} = {alert.metric_value ?? ''}</span>
            <span class="n">{formatCount(alert.event_count)} events</span>
          </button>
          {#if open === alert.alert_idx}
            <p class="note">Window {isoTime(alert.window_start, false)} to {isoTime(alert.window_end, false)} UTC</p>
            {#if evidenceFailure}
              <p class="note failure" role="alert">The evidence could not be read: {evidenceFailure}. Close the alert and open it again.</p>
            {:else if evidenceStopped}
              <p class="note" role="status">Stopped. <button type="button" class="again" onclick={() => { runAgain(); load(alert); }}>Run again</button></p>
            {:else if evidence === null}
              <p class="note">Reading the evidence</p>
            {:else}
              {#if alert.event_count > evidence.length}<p class="note">First {formatCount(evidence.length)} of {formatCount(alert.event_count)} events.</p>{/if}
              <ol class="evidence">
                {#each evidence as row (row.ord)}
                  <li><button type="button" onclick={() => (view.uid = row._zl_uid)}>{isoTime(row._zl_t) || 'no time'} {row.host ?? ''} {row.eventid ? `event ${row.eventid}` : ''}</button></li>
                {/each}
              </ol>
            {/if}
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</section>

<style>
  .alerts { margin-top: 12px; }
  h3 { margin: 0 0 4px; font-size: var(--t-13); color: var(--ink-2); }
  ul, ol { list-style: none; margin: 0; padding: 0; }
  .alert { display: grid; grid-template-columns: 160px minmax(0, 1fr) auto auto; gap: 12px; width: 100%; min-height: 32px; padding: 4px 8px; text-align: left; background: none; border: 0; border-bottom: 1px solid var(--rule); cursor: pointer; }
  .when, .metric, .n { font: 400 var(--t-13) / 1.4 var(--mono); }
  .keys { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .evidence button { width: 100%; min-height: 28px; text-align: left; background: none; border: 0; padding: 2px 8px 2px 24px; cursor: pointer; font: 400 var(--t-13) / 1.4 var(--mono); }
  .evidence button:hover { background: color-mix(in srgb, var(--signal) 8%, transparent); }
  .note { margin: 4px 0; font-size: var(--t-12); color: var(--ink-2); }
  .failure { color: var(--danger); }
  .again { min-height: 24px; background: none; border: 1px solid var(--rule); border-radius: var(--radius); padding: 1px 8px; cursor: pointer; }
  @media (max-width: 720px) {
    .alert { grid-template-columns: minmax(0, 1fr); gap: 2px; }
  }
</style>
