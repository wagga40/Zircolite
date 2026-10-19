import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Schema } from '../src/engine/schema';
import {
  explicitSql, explicitTerms, type LogonRow, logonFields, logonsSql, logonTerms, rdpSql, rdpTerms, type RdpRow,
} from '../src/logons/logons';
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
      ['WS2', 'CORP\\carol', '10 RemoteInteractive', '10.0.0.7', null, 1, 0, null, 1],
    ]);
  });

  it('leaves out other channels, logoffs and other events', async () => {
    const rows = await logons();
    expect(rows.reduce((sum, r) => sum + r.successes + r.failures, 0)).toBe(7);
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
    expect((await fixture(textIds).rows(logonsSql(fields, where, {}) as string)).length).toBe(1);
  });

  it('lists explicit credentials from the host they were used on', async () => {
    const rows = await fixture(textIds).rows(explicitSql(fields, 'TRUE', {}) as string);
    expect(rows.map((r) => [r.host, r.subject, r.account, r.server, r.process, r.events])).toEqual([
      ['WS1', 'CORP\\alice', 'CORP\\admin', 'DC01', 'C:\\Windows\\System32\\runas.exe', 1],
    ]);
    for (const row of rows) {
      expect(await fixture(textIds).uids(compile(parse(explicitTerms(fields, row as never)), schema))).toEqual([9]);
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

describe('logons without the fields', () => {
  it('say which fields are missing, and query nothing', () => {
    const fields = logonFields(new Schema([], []));
    expect(fields.missing).toContain('EventID');
    expect(logonsSql(fields, 'TRUE', {})).toBeNull();
    expect(explicitSql(fields, 'TRUE', {})).toBeNull();
    expect(rdpSql(fields, 'TRUE', {})).toBeNull();
  });
});
