import { type Field, Schema } from '../src/engine/schema';
import { type Fixture, openFixture } from './fixture';

const SECURITY = 'Security';
const RCM = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational';

const TEXT = [
  'Channel', 'Computer', 'TargetUserName', 'TargetDomainName', 'IpAddress', 'WorkstationName', 'TargetLogonId', 'Status', 'SubStatus',
  'SubjectUserName', 'SubjectDomainName', 'TargetServerName', 'ProcessName', 'Param1', 'Param2', 'Param3',
  'AccountName', 'AccountDomain', 'ClientName', 'ClientAddress', 'SubjectLogonId', 'PrivilegeList',
];

/** A package's logon fields; EventID and LogonType are numbers, or text as in a package whose sources mixed them. */
export function logonSchema(textIds = false): Schema {
  const numeric: Field['type'] = textIds ? 'VARCHAR' : 'BIGINT';
  return new Schema([
    { name: 'EventID', key: 'eventid', type: numeric, count: 1 },
    { name: 'LogonType', key: 'logontype', type: numeric, count: 1 },
    ...TEXT.map((name): Field => ({ name, key: name.toLowerCase(), type: 'VARCHAR', count: 1 })),
  ], []);
}

type Event = Partial<Record<string, string | number>> & { uid: number; time: string | null; channel: string; id: number };

/**
 * Logons on DC01 and WS2: alice logs on twice and fails once, bob fails as an
 * unknown user, the machine account logs on, carol comes in over RDP, a logon
 * id is reused after a reboot, another is reused after a logon that never
 * logged off, WS1's computer account reaches WS2, alice uses her own
 * credentials on WS1, and an Application event shares id 4624. Special privileges
 * (4672) are written just before the logon they go with, as Windows writes
 * them.
 */
export const LOGON_EVENTS: Event[] = [
  { uid: 1, time: '2021-06-03 08:00:00', channel: SECURITY, id: 4624, Computer: 'DC01', TargetDomainName: 'CORP', TargetUserName: 'alice', LogonType: 3, IpAddress: '10.0.0.5', WorkstationName: 'WS1', TargetLogonId: '0x1' },
  { uid: 2, time: '2021-06-03 09:00:00', channel: SECURITY, id: 4624, Computer: 'dc01', TargetDomainName: 'corp', TargetUserName: 'Alice', LogonType: 3, IpAddress: '10.0.0.5', WorkstationName: 'WS1', TargetLogonId: '0x2' },
  { uid: 3, time: '2021-06-03 07:59:00', channel: SECURITY, id: 4625, Computer: 'DC01', TargetDomainName: 'CORP', TargetUserName: 'alice', LogonType: 3, IpAddress: '10.0.0.5', WorkstationName: 'WS1', Status: '0xC000006D', SubStatus: '0xC000006A' },
  { uid: 4, time: '2021-06-03 07:00:00', channel: SECURITY, id: 4625, Computer: 'DC01', TargetDomainName: 'CORP', TargetUserName: 'bob', LogonType: 3, IpAddress: '10.0.0.9', Status: '0xC000006D', SubStatus: '0xC0000064' },
  { uid: 5, time: '2021-06-03 08:30:00', channel: SECURITY, id: 4624, Computer: 'DC01', TargetDomainName: 'CORP', TargetUserName: 'DC01$', LogonType: 3, IpAddress: '::1', TargetLogonId: '0x3' },
  { uid: 6, time: '2021-06-03 08:20:00', channel: SECURITY, id: 4634, Computer: 'DC01', TargetDomainName: 'CORP', TargetUserName: 'alice', LogonType: 3, TargetLogonId: '0x1' },
  { uid: 7, time: '2021-06-03 10:00:00', channel: SECURITY, id: 4647, Computer: 'DC01', TargetDomainName: 'CORP', TargetUserName: 'alice', TargetLogonId: '0x2' },
  { uid: 8, time: '2021-06-03 11:00:00', channel: SECURITY, id: 4624, Computer: 'WS2', TargetDomainName: 'CORP', TargetUserName: 'carol', LogonType: 10, IpAddress: '10.0.0.7', TargetLogonId: '0x1' },
  { uid: 9, time: '2021-06-03 08:05:00', channel: SECURITY, id: 4648, Computer: 'WS1', SubjectDomainName: 'CORP', SubjectUserName: 'alice', TargetDomainName: 'CORP', TargetUserName: 'admin', TargetServerName: 'DC01', ProcessName: 'C:\\Windows\\System32\\runas.exe' },
  { uid: 10, time: '2021-06-03 10:59:00', channel: RCM, id: 1149, Computer: 'WS2', Param1: 'carol', Param2: 'CORP', Param3: '10.0.0.7' },
  { uid: 11, time: '2021-06-03 11:30:00', channel: SECURITY, id: 4778, Computer: 'WS2', AccountName: 'carol', AccountDomain: 'CORP', ClientName: 'LAPTOP', ClientAddress: '10.0.0.7' },
  { uid: 12, time: '2021-06-03 12:00:00', channel: 'Application', id: 4624, Computer: 'DC01' },
  { uid: 13, time: '2021-06-03 12:00:00', channel: SECURITY, id: 4624, Computer: 'DC01', TargetDomainName: 'CORP', TargetUserName: 'alice', LogonType: 2, TargetLogonId: '0x1' },
  // eve never logs off; her logon id comes back for frank, whose logoff must not close eve's session.
  { uid: 14, time: '2021-06-03 08:40:00', channel: SECURITY, id: 4624, Computer: 'DC01', TargetDomainName: 'CORP', TargetUserName: 'eve', LogonType: 3, IpAddress: '10.0.0.8', TargetLogonId: '0x5' },
  { uid: 15, time: '2021-06-03 09:10:00', channel: SECURITY, id: 4624, Computer: 'DC01', TargetDomainName: 'CORP', TargetUserName: 'frank', LogonType: 3, IpAddress: '10.0.0.8', TargetLogonId: '0x5' },
  { uid: 16, time: '2021-06-03 09:30:00', channel: SECURITY, id: 4634, Computer: 'DC01', TargetDomainName: 'CORP', TargetUserName: 'frank', LogonType: 3, TargetLogonId: '0x5' },
  { uid: 17, time: '2021-06-03 07:59:58', channel: SECURITY, id: 4672, Computer: 'DC01', SubjectDomainName: 'CORP', SubjectUserName: 'alice', SubjectLogonId: '0x1', PrivilegeList: 'SeDebugPrivilege\r\n\t\t\tSeBackupPrivilege' },
  // Frank's, not eve's: it comes three seconds before his logon, half an hour after hers.
  { uid: 18, time: '2021-06-03 09:09:57', channel: SECURITY, id: 4672, Computer: 'DC01', SubjectDomainName: 'CORP', SubjectUserName: 'frank', SubjectLogonId: '0x5', PrivilegeList: 'SeTcbPrivilege' },
  // Too long before alice's second logon to be its own.
  { uid: 19, time: '2021-06-03 08:59:50', channel: SECURITY, id: 4672, Computer: 'DC01', SubjectDomainName: 'CORP', SubjectUserName: 'alice', SubjectLogonId: '0x2', PrivilegeList: 'SeTcbPrivilege' },
  { uid: 20, time: '2021-06-03 13:00:00', channel: SECURITY, id: 4624, Computer: 'WS2', TargetDomainName: 'CORP', TargetUserName: 'WS1$', LogonType: 3, IpAddress: '10.0.0.5', TargetLogonId: '0x9' },
  // Explicit credentials used for the host itself: no movement.
  { uid: 21, time: '2021-06-03 13:10:00', channel: SECURITY, id: 4648, Computer: 'WS1', SubjectDomainName: 'CORP', SubjectUserName: 'alice', TargetDomainName: 'CORP', TargetUserName: 'alice', TargetServerName: 'localhost', ProcessName: 'C:\\Windows\\System32\\svchost.exe' },
  { uid: 22, time: '2021-06-03 13:20:00', channel: SECURITY, id: 4648, Computer: 'WS1', SubjectDomainName: 'CORP', SubjectUserName: 'alice', TargetDomainName: 'CORP', TargetUserName: 'alice', TargetServerName: 'ws1', ProcessName: 'C:\\Windows\\System32\\svchost.exe' },
];

const literal = (value: string | number | null | undefined) =>
  value === undefined || value === null ? 'NULL' : typeof value === 'number' ? String(value) : `'${value.replaceAll("'", "''")}'`;

/** The events above as a package's events table, with no detections. */
export async function openLogonFixture(textIds = false): Promise<Fixture> {
  const numeric = textIds ? 'VARCHAR' : 'BIGINT';
  const value = (event: Event, name: string) => {
    const raw = name === 'Channel' ? event.channel : event[name];
    return textIds && typeof raw === 'number' ? literal(String(raw)) : literal(raw);
  };
  const rows = LOGON_EVENTS.map((event) =>
    `(${event.uid}, 0, ${event.time ? `TIMESTAMP '${event.time}'` : 'NULL'}, NULL, ${textIds ? `'${event.id}'` : event.id}, ${value(event, 'LogonType')}, ` +
    `${TEXT.map((name) => value(event, name)).join(', ')})`);
  return openFixture([
    'DROP TABLE events',
    `CREATE TABLE events (_zl_uid BIGINT, _zl_part INTEGER, _zl_time TIMESTAMP, _zl_spelling VARCHAR, "EventID" ${numeric}, "LogonType" ${numeric}, ` +
      `${TEXT.map((name) => `"${name}" VARCHAR`).join(', ')})`,
    `INSERT INTO events VALUES ${rows.join(', ')}`,
    'DELETE FROM hits',
    'DELETE FROM event_levels',
  ]);
}
