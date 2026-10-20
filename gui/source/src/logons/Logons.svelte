<script lang="ts">
  import type { Db } from '../engine/db';
  import type { Manifest } from '../engine/manifest';
  import type { Schema } from '../engine/schema';
  import { appendRaw } from '../search/edit';
  import type { QueryState } from '../state/query.svelte';
  import { run } from '../state/run.svelte';
  import { view } from '../state/view.svelte';
  import { formatCount, isoTime } from '../ui/format';
  import { localWhere, sortClause, type TableColumn } from '../ui/localFilters';
  import { ownScope } from '../ui/scope';
  import LateralGraph from './LateralGraph.svelte';
  import {
    EXPLICIT_COLUMNS, EXPLICIT_ORDER, type ExplicitRow, explicitSql, explicitTerms, LATERAL_COLUMNS, LATERAL_ORDER, type LateralRow, lateralSql,
    lateralTerms, LOGON_COLUMNS, LOGON_ORDER, type LogonRow, logonFields, logonsSql, logonTerms, RDP_COLUMNS, RDP_ORDER, type RdpRow, rdpSql,
    rdpTerms, SESSION_COLUMNS, SESSION_ORDER, sessionActivity, type SessionRow, sessionsSql,
  } from './logons';
  import Section from './Section.svelte';
  import { LogonTable } from './table.svelte';

  let { db: page, schema, manifest, query }: { db: Db; schema: Schema; manifest: Manifest; query: QueryState } = $props();
  // svelte-ignore state_referenced_locally
  const db = ownScope(page, 'logons');

  const fields = $derived(logonFields(schema));
  let remoteOnly = $state(false);
  let hideMachines = $state(false);

  const lateral = new LogonTable<LateralRow>(LATERAL_COLUMNS);
  const logons = new LogonTable<LogonRow>(LOGON_COLUMNS);
  const explicit = new LogonTable<ExplicitRow>(EXPLICIT_COLUMNS);
  const rdp = new LogonTable<RdpRow>(RDP_COLUMNS);
  const sessions = new LogonTable<SessionRow>(SESSION_COLUMNS);

  $effect(() => {
    void run.generation;
    lateral.load(db, 'lateral', lateralSql(fields, query.where, {
      hideMachines, filter: localWhere(lateral.filters, lateral.schema), order: sortClause(lateral.sort, LATERAL_ORDER),
    }));
  });
  $effect(() => {
    void run.generation;
    logons.load(db, 'logons', logonsSql(fields, query.where, {
      remoteOnly, hideMachines, filter: localWhere(logons.filters, logons.schema), order: sortClause(logons.sort, LOGON_ORDER),
    }));
  });
  $effect(() => {
    void run.generation;
    explicit.load(db, 'explicit', explicitSql(fields, query.where, { filter: localWhere(explicit.filters, explicit.schema), order: sortClause(explicit.sort, EXPLICIT_ORDER) }));
  });
  $effect(() => {
    void run.generation;
    rdp.load(db, 'rdp', rdpSql(fields, query.where, { filter: localWhere(rdp.filters, rdp.schema), order: sortClause(rdp.sort, RDP_ORDER) }));
  });

  $effect(() => {
    void run.generation;
    sessions.load(db, 'sessions', sessionsSql(fields, query.where, {
      remoteOnly, hideMachines, filter: localWhere(sessions.filters, sessions.schema), order: sortClause(sessions.sort, SESSION_ORDER),
    }));
  });

  const label = (names: Record<string, string>) => (column: TableColumn<never>['column']) => ({ column, label: names[column.name] });
  const LOGON_LABELS: Record<string, string> = {
    host: 'Host', account: 'Account', type_name: 'Logon type', ip: 'Source address', workstation: 'Source workstation', successes: 'Successes',
    failures: 'Failures', reasons: 'Failure reasons', sessions: 'Sessions', first: 'First (UTC)', last: 'Last (UTC)',
  };
  const EXPLICIT_LABELS: Record<string, string> = {
    host: 'Used on', subject: 'By account', account: 'For account', server: 'Target server', process: 'Process', events: 'Events', first: 'First (UTC)', last: 'Last (UTC)',
  };
  const RDP_LABELS: Record<string, string> = {
    kind: 'Event', host: 'Host', account: 'Account', source: 'Source address', client: 'Client name', events: 'Events', first: 'First (UTC)', last: 'Last (UTC)',
  };
  const LATERAL_LABELS: Record<string, string> = {
    source: 'From', target: 'To', kind: 'How', accounts: 'Accounts', account_list: 'Most used accounts', events: 'Events', first: 'First (UTC)',
    last: 'Last (UTC)',
  };
  const lateralColumns: TableColumn<LateralRow>[] = LATERAL_COLUMNS.map(label(LATERAL_LABELS));
  const logonColumns: TableColumn<LogonRow>[] = LOGON_COLUMNS.map(label(LOGON_LABELS));
  const explicitColumns: TableColumn<ExplicitRow>[] = EXPLICIT_COLUMNS.map(label(EXPLICIT_LABELS));
  const rdpColumns: TableColumn<RdpRow>[] = RDP_COLUMNS.map(label(RDP_LABELS));
  const SESSION_LABELS: Record<string, string> = {
    host: 'Host', account: 'Account', type_name: 'Logon type', ip: 'Source address', session: 'Logon ID', start: 'Logon (UTC)', end: 'Logoff (UTC)',
    minutes: 'Minutes', privileges: 'Special privileges',
  };
  // Without the fields of 4672 an empty column would read as no session being privileged.
  const privilegesKnown = $derived(!!fields.field.SubjectLogonId && !!fields.field.PrivilegeList);
  const sessionColumns: TableColumn<SessionRow>[] = $derived(SESSION_COLUMNS.filter((column) => column.name !== 'privileges' || privilegesKnown)
    .map(label(SESSION_LABELS)).map((column) =>
      column.column.name === 'end' ? { ...column, show: (row: SessionRow) => sessionEnd(row) }
      : column.column.name === 'minutes' ? { ...column, show: (row: SessionRow) => (row.minutes === null ? '' : formatCount(row.minutes)) } : column));

  function sessionEnd(row: SessionRow): string {
    if (row.end !== null) return isoTime(row.end, false);
    return row.next_logon === null ? 'still open' : `no logoff; id logged on again ${isoTime(row.next_logon, false)}`;
  }

  // The activity replaces the search: the filters that found the session, such as EventID:4624, would cut it down
  // to the logon itself.
  function activity(row: SessionRow): void {
    const { q, t } = sessionActivity(fields, row);
    view.q = q;
    view.t = t;
    view.d = false;
    view.route = 'explore';
  }

  function explore(terms: string): void {
    view.q = appendRaw(view.q, terms);
    view.route = 'explore';
  }
</script>

<main class="logons">
  <header>
    <h1 tabindex="-1">Logons</h1>
  </header>
  {#if fields.missing.length > 0}
    <p class="note">This package has no {fields.missing.join(' or ')} field, so it holds no Windows logon to list.</p>
  {:else}
    <p class="note">
      Windows logons under the current filters: who reached which host, from where and how, and how often it failed.
      {#if !fields.field.Channel}This package has no Channel field, so events are told apart by their event ID alone.{/if}
    </p>
    <div class="toggles" role="group" aria-label="Lateral movement, logons and sessions">
      <span class="scope">Lateral movement, logons and sessions:</span>
      <button type="button" aria-pressed={remoteOnly && !!fields.field.LogonType} disabled={!fields.field.LogonType} onclick={() => (remoteOnly = !remoteOnly)}
        title={fields.field.LogonType ? 'Network (3) and remote interactive (10) logons only' : 'This package has no LogonType field'}>Remote logon types only</button>
      <button type="button" aria-pressed={hideMachines && !!fields.field.TargetUserName} disabled={!fields.field.TargetUserName} onclick={() => (hideMachines = !hideMachines)}
        title={fields.field.TargetUserName ? 'Leave out computer accounts, whose names end in $' : 'This package has no TargetUserName field'}>Hide computer accounts</button>
    </div>
    <Section title="Lateral movement" table={lateral} id="lateral-table" columns={lateralColumns} order={{ column: 'events', desc: true }} noun="links between hosts"
      note="Who reached which host: network (3) and Remote Desktop (10) logons from their source address to the host that recorded them, and explicit credentials (4648) from the host that used them to the target server. Logons from the host itself and credentials used for it are left out."
      events={(row) => row.events} open={(row) => explore(lateralTerms(fields, row, { hideMachines }))}
      unavailable="This package has no LogonType and IpAddress fields, nor TargetServerName, so no link between hosts can be drawn.">
      {#snippet figure()}
        <LateralGraph rows={lateral.answer?.rows ?? []} pending={lateral.list.slot.pending} open={(row) => explore(lateralTerms(fields, row, { hideMachines }))} />
      {/snippet}
    </Section>
    <Section title="Logons and failures" table={logons} id="logons-table" columns={logonColumns} order={{ column: 'failures', desc: true }} noun="logons"
      note="Security 4624 and 4625, grouped by host, account, logon type and source; failures first. Failure reasons come from SubStatus, or Status when SubStatus says nothing."
      events={(row) => row.successes + row.failures} open={(row) => explore(logonTerms(fields, row))} unavailable="" />
    <Section title="Explicit credentials" table={explicit} id="explicit-table" columns={explicitColumns} order={{ column: 'events', desc: true }} noun="uses of explicit credentials"
      note="Security 4648: a process on one host used the credentials of another account, often to reach a target server."
      events={(row) => row.events} open={(row) => explore(explicitTerms(fields, row))} unavailable="" />
    <Section title="Sessions" table={sessions} id="sessions-table" columns={sessionColumns} order={{ column: 'start', desc: false }} noun="sessions"
      note={'Each successful logon with its logoff (4634 or 4647) on the same host and logon ID; a logon ID used again after a reboot starts a new session. ' +
        (privilegesKnown ? 'Special privileges are those 4672 gave the logon. ' : 'This package has no SubjectLogonId or PrivilegeList field, so the special privileges (4672) of a session are not shown. ') +
        "The host opens the session's activity: the events on its host that carry its logon ID, from logon to logoff."}
      open={activity} opens={(row) => `Show what logon ID ${row.session} did on ${row.host ?? 'its host'}, in place of the search`}
      unavailable="This package has no TargetLogonId field, so logons cannot be paired with their logoffs." />
    <Section title="Remote Desktop" table={rdp} id="rdp-table" columns={rdpColumns} order={{ column: 'host', desc: false }} noun="Remote Desktop events"
      note="Remote Desktop authentications (1149), session logons, disconnections and reconnections, by the fields each kind of event records."
      events={(row) => row.events} open={(row) => explore(rdpTerms(fields, row))}
      unavailable="This package has none of the fields Remote Desktop events record (Param1, User or AccountName), or no Channel to tell their kinds apart." />
  {/if}
</main>

<style>
  .logons { overflow: auto; padding: 16px 24px 32px; background: var(--paper); min-width: 0; }
  h1 { margin: 0; font-size: var(--t-18); }
  .note { margin: 6px 0; color: var(--ink-2); font-size: var(--t-13); }
  .toggles { display: flex; flex-wrap: wrap; gap: 6px; margin: 10px 0; }
  button { min-height: 28px; padding: 3px 10px; background: none; border: 1px solid var(--rule); border-radius: var(--radius); cursor: pointer; color: var(--ink); font: inherit; font-size: var(--t-13); }
  button[aria-pressed='true'] { border-color: var(--signal); color: var(--signal); }
  button:disabled { opacity: 0.5; cursor: default; }
  .scope { align-self: center; color: var(--ink-2); font-size: var(--t-13); }
</style>
