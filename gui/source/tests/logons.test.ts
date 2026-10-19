import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Schema } from '../src/engine/schema';
import {
  explicitSql, explicitTerms, type LateralRow, lateralSql, lateralTerms, type LogonRow, logonFields, logonsSql, logonTerms, rdpSql, rdpTerms,
  type RdpRow, sessionActivity, type SessionRow, sessionsSql,
} from '../src/logons/logons';
import { timePredicate } from '../src/state/where';
import { compile } from '../src/search/compile';
import { parse } from '../src/search/parse';
import type { Fixture } from './fixture';
import { logonSchema, openLogonFixture } from './logonFixture';

let numeric: Fixture;
let text: Fixture;
beforeAll(async () => {
  numeric = await openLogonFixture(false);
  text = await openLogonFixture(true);
});
afterAll(() => {
  numeric.close();
  text.close();
});

const kinds = [['numeric EventID', false], ['text EventID', true]] as const;
const fixture = (textIds: boolean) => (textIds ? text : numeric);

describe.each(kinds)('logons, with a %s', (_name, textIds) => {
  const schema = logonSchema(textIds);
  const fields = logonFields(schema);
  const logons = async (options = {}) => (await fixture(textIds).rows(logonsSql(fields, 'TRUE', options) as string)) as unknown as LogonRow[];

  it('groups successes and failures by host, account, type and source, failures first', async () => {
    const rows = await logons();
    expect(rows.map((r) => [r.host, r.account, r.type_name, r.ip, r.workstation, r.successes, r.failures, r.reasons, r.sessions])).toEqual([
      ['DC01', 'CORP\\Alice', '3 Network', '10.0.0.5', 'WS1', 2, 1, 'bad password', 2],
      ['DC01', 'CORP\\bob', '3 Network', '10.0.0.9', null, 0, 1, 'no such user', 0],
      ['DC01', 'CORP\\alice', '2 Interactive', null, null, 1, 0, null, 1],
      ['DC01', 'CORP\\DC01$', '3 Network', '::1', null, 1, 0, null, 1],
      ['DC01', 'CORP\\eve', '3 Network', '10.0.0.8', null, 1, 0, null, 1],
      ['DC01', 'CORP\\frank', '3 Network', '10.0.0.8', null, 1, 0, null, 1],
      ['WS2', 'CORP\\carol', '10 RemoteInteractive', '10.0.0.7', null, 1, 0, null, 1],
      ['WS2', 'CORP\\WS1$', '3 Network', '10.0.0.5', null, 1, 0, null, 1],
    ]);
  });

  it('leaves out other channels, logoffs and other events', async () => {
    const rows = await logons();
    expect(rows.reduce((sum, r) => sum + r.successes + r.failures, 0)).toBe(10);
  });

  it('pivots each row to exactly its logons and failures', async () => {
    for (const row of await logons()) {
      const listed = await fixture(textIds).uids(compile(parse(logonTerms(fields, row)), schema));
      expect(listed.length, JSON.stringify(row)).toBe(row.successes + row.failures);
    }
  });

  it('keeps remote logon types only, and hides machine accounts, on request', async () => {
    expect((await logons({ remoteOnly: true })).map((r) => r.type_name)).not.toContain('2 Interactive');
    expect((await logons({ hideMachines: true })).map((r) => r.account)).not.toContain('CORP\\DC01$');
  });

  it('applies the page filters', async () => {
    const where = compile(parse('Computer:WS2'), schema);
    expect((await fixture(textIds).rows(logonsSql(fields, where, {}) as string)).length).toBe(2);
  });

  it('lists explicit credentials from the host they were used on', async () => {
    const rows = await fixture(textIds).rows(explicitSql(fields, 'TRUE', {}) as string);
    expect(rows.map((r) => [r.host, r.subject, r.account, r.server, r.process, r.events])).toEqual([
      ['WS1', 'CORP\\alice', 'CORP\\admin', 'DC01', 'C:\\Windows\\System32\\runas.exe', 1],
      ['WS1', 'CORP\\alice', 'CORP\\alice', 'localhost', 'C:\\Windows\\System32\\svchost.exe', 1],
      ['WS1', 'CORP\\alice', 'CORP\\alice', 'ws1', 'C:\\Windows\\System32\\svchost.exe', 1],
    ]);
    expect(await fixture(textIds).uids(compile(parse(explicitTerms(fields, rows[0] as never)), schema))).toEqual([9]);
    for (const row of rows) {
      expect(await fixture(textIds).uids(compile(parse(explicitTerms(fields, row as never)), schema))).toHaveLength(1);
    }
  });

  it('lists remote desktop events by kind, each pivoting to exactly its events', async () => {
    const rows = (await fixture(textIds).rows(rdpSql(fields, 'TRUE', {}) as string)) as unknown as RdpRow[];
    expect(rows.map((r) => [r.kind, r.host, r.account, r.source, r.client, r.events])).toEqual([
      ['1149 RDP authentication', 'WS2', 'CORP\\carol', '10.0.0.7', null, 1],
      ['4778 RDP session reconnected', 'WS2', 'CORP\\carol', '10.0.0.7', 'LAPTOP', 1],
    ]);
    for (const row of rows) {
      const listed = await fixture(textIds).uids(compile(parse(rdpTerms(fields, row)), schema));
      expect(listed.length, row.kind).toBe(row.events);
    }
  });
});

describe.each(kinds)('lateral movement, with a %s', (_name, textIds) => {
  const schema = logonSchema(textIds);
  const fields = logonFields(schema);
  const lateral = async (options = {}, where = 'TRUE') =>
    (await fixture(textIds).rows(lateralSql(fields, where, options) as string)) as unknown as LateralRow[];

  it('links each source to the host it reached: network and Remote Desktop logons, and explicit credentials', async () => {
    expect((await lateral()).map((r) => [r.source, r.target, r.kind, r.accounts, r.account_list, r.events])).toEqual([
      ['10.0.0.5', 'DC01', '3 Network logon', 1, 'CORP\\alice', 2],
      ['10.0.0.8', 'DC01', '3 Network logon', 2, 'CORP\\eve, CORP\\frank', 2],
      ['10.0.0.5', 'WS2', '3 Network logon', 1, 'CORP\\WS1$', 1],
      ['10.0.0.7', 'WS2', '10 Remote Desktop logon', 1, 'CORP\\carol', 1],
      ['WS1', 'DC01', '4648 Explicit credentials', 1, 'CORP\\admin', 1],
    ]);
  });

  it('leaves out logons from the host itself and credentials used for the host itself', async () => {
    const rows = await lateral();
    expect(rows.map((r) => r.source)).not.toContain('::1');
    expect(rows.map((r) => r.target.toLowerCase())).not.toContain('localhost');
    expect(rows.filter((r) => r.source.toLowerCase() === r.target.toLowerCase())).toEqual([]);
  });

  it('pivots each link to exactly its events', async () => {
    for (const options of [{}, { hideMachines: true }]) {
      for (const row of await lateral(options)) {
        const listed = await fixture(textIds).uids(compile(parse(lateralTerms(fields, row, options)), schema));
        expect(listed.length, JSON.stringify([row, options])).toBe(row.events);
      }
    }
  });

  it('hides computer accounts on request', async () => {
    expect((await lateral({ hideMachines: true })).map((r) => r.account_list)).not.toContain('CORP\\WS1$');
  });

  it('applies the page filters', async () => {
    expect((await lateral({}, compile(parse('Computer:WS2'), schema))).map((r) => r.target)).toEqual(['WS2', 'WS2']);
  });
});

describe.each(kinds)('sessions, with a %s', (_name, textIds) => {
  const schema = logonSchema(textIds);
  const fields = logonFields(schema);
  const at = (hhmm: string) => Date.UTC(2021, 5, 3, Number(hhmm.slice(0, 2)), Number(hhmm.slice(3)));
  const sessions = async (where = 'TRUE') => (await fixture(textIds).rows(sessionsSql(fields, where, {}) as string)) as unknown as SessionRow[];

  it('pairs each logon with its logoff, never the logoff of a later logon that reused its id', async () => {
    expect((await sessions()).map((r) => [r.host, r.account, r.session, r.start, r.end, r.minutes, r.next_logon])).toEqual([
      ['DC01', 'CORP\\alice', '0x1', at('08:00'), at('08:20'), 20, at('12:00')],
      ['DC01', 'CORP\\DC01$', '0x3', at('08:30'), null, null, null],
      ['DC01', 'CORP\\eve', '0x5', at('08:40'), null, null, at('09:10') - 3000],
      ['dc01', 'corp\\Alice', '0x2', at('09:00'), at('10:00'), 60, null],
      ['DC01', 'CORP\\frank', '0x5', at('09:10'), at('09:30'), 20, null],
      ['WS2', 'CORP\\carol', '0x1', at('11:00'), null, null, null],
      ['DC01', 'CORP\\alice', '0x1', at('12:00'), null, null, null],
      ['WS2', 'CORP\\WS1$', '0x9', at('13:00'), null, null, null],
    ]);
  });

  it('filters the logons, never the logoffs that close them', async () => {
    const rows = await sessions(compile(parse('LogonType:3'), schema));
    expect(rows.map((r) => [r.session, r.end])).toEqual([
      ['0x1', at('08:20')], ['0x3', null], ['0x5', null], ['0x2', at('10:00')], ['0x5', at('09:30')], ['0x9', null],
    ]);
  });

  it('opens a session\'s activity: its logon id on its host, from its special privileges or logon to its logoff', async () => {
    const [first, open] = await sessions();
    const activity = sessionActivity(fields, first);
    expect(activity.t).toEqual([at('08:00') - 2000, at('08:20') + 1]);
    const where = `(${compile(parse(activity.q), schema)}) AND (${timePredicate(activity.t)})`;
    expect(await fixture(textIds).uids(where)).toEqual([1, 6, 17]);
    // Open to the end of the logs: the package's last event.
    expect(sessionActivity(fields, open).t).toEqual([at('08:30'), at('13:20') + 1]);
  });

  it('flags the sessions given special privileges (4672), with the privileges they were given', async () => {
    expect((await sessions()).map((r) => [r.account, r.session, r.privileges, r.privileged_at])).toEqual([
      ['CORP\\alice', '0x1', 'SeDebugPrivilege, SeBackupPrivilege', at('08:00') - 2000],
      ['CORP\\DC01$', '0x3', null, null],
      ['CORP\\eve', '0x5', null, null],
      ['corp\\Alice', '0x2', null, null],
      ['CORP\\frank', '0x5', 'SeTcbPrivilege', at('09:10') - 3000],
      ['CORP\\carol', '0x1', null, null],
      ['CORP\\alice', '0x1', null, null],
      ['CORP\\WS1$', '0x9', null, null],
    ]);
  });

  it('keeps remote logon types only, and hides computer accounts, on request', async () => {
    const remote = (await fixture(textIds).rows(sessionsSql(fields, 'TRUE', { remoteOnly: true }) as string)) as unknown as SessionRow[];
    expect(remote.map((r) => r.type_name)).not.toContain('2 Interactive');
    expect(remote.map((r) => r.type_name)).toContain('10 RemoteInteractive');
    const people = (await fixture(textIds).rows(sessionsSql(fields, 'TRUE', { hideMachines: true }) as string)) as unknown as SessionRow[];
    expect(people.map((r) => r.account)).not.toContain('CORP\\DC01$');
    expect(people).toHaveLength(6);
  });

  it('ends the activity of a session that never logged off where the next logon with its id begins', async () => {
    const eve = (await sessions()).find((r) => r.account === 'CORP\\eve') as SessionRow;
    const activity = sessionActivity(fields, eve);
    // Frank's logon with eve's id begins with his special privileges, three seconds before the logon itself.
    expect(activity.t).toEqual([at('08:40'), at('09:10') - 3000]);
    const where = `(${compile(parse(activity.q), schema)}) AND (${timePredicate(activity.t)})`;
    expect(await fixture(textIds).uids(where)).toEqual([14]);
  });
});

describe('logons without the fields', () => {
  it('say which fields are missing, and query nothing', () => {
    const fields = logonFields(new Schema([], []));
    expect(fields.missing).toContain('EventID');
    expect(logonsSql(fields, 'TRUE', {})).toBeNull();
    expect(explicitSql(fields, 'TRUE', {})).toBeNull();
    expect(rdpSql(fields, 'TRUE', {})).toBeNull();
    expect(sessionsSql(fields, 'TRUE', {})).toBeNull();
    expect(lateralSql(fields, 'TRUE', {})).toBeNull();
  });
});
