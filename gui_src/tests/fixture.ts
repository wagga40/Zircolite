import { DuckDBInstance } from '@duckdb/node-api';
import { EVENT_LEVELS_SQL } from '../src/engine/sql';
import { type Field, Schema } from '../src/engine/schema';

/** Columns of the fixture's events table, as a package manifest would list them. */
export const FIELDS: Field[] = [
  { name: 'Channel', key: 'channel', type: 'VARCHAR', count: 6 },
  { name: 'EventID', key: 'eventid', type: 'BIGINT', count: 6 },
  { name: 'Computer', key: 'computer', type: 'VARCHAR', count: 6 },
  { name: 'TargetUserName', key: 'targetusername', type: 'VARCHAR', count: 2 },
  { name: 'Image', key: 'image', type: 'VARCHAR', count: 3 },
  { name: 'CommandLine', key: 'commandline', type: 'VARCHAR', count: 2 },
  { name: `it's "odd"`, key: `it's "odd"`, type: 'VARCHAR', count: 1 },
  { name: 'level', key: 'level', type: 'VARCHAR', count: 1 },
];

/** ATT&CK tactic short names in Zircolite's order: zircolite/attack.py TACTIC_ORDER, as the manifest lists them. */
export const TACTICS = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence', 'privilege-escalation',
  'stealth', 'defense-impairment', 'credential-access', 'discovery', 'lateral-movement', 'collection',
  'command-and-control', 'exfiltration', 'impact',
];

export const schema = new Schema(FIELDS, TACTICS);

const SETUP = [
  `CREATE TABLE events (_zl_uid BIGINT, _zl_part INTEGER, _zl_time TIMESTAMP, _zl_spelling VARCHAR,
     "Channel" VARCHAR, "EventID" BIGINT, "Computer" VARCHAR, "TargetUserName" VARCHAR, "Image" VARCHAR,
     "CommandLine" VARCHAR, "it's ""odd""" VARCHAR, "level" VARCHAR)`,
  `INSERT INTO events VALUES
     (1, 0, TIMESTAMP '2021-06-03 06:00:00', NULL, 'Security', 4624, 'DC01', 'bob', NULL, NULL, NULL, NULL),
     (2, 0, TIMESTAMP '2021-06-03 06:00:30', NULL, 'Security', 4634, 'DC01', 'alice', NULL, NULL, NULL, NULL),
     (3, 0, TIMESTAMP '2021-06-03 06:05:00', NULL, 'Microsoft-Windows-Sysmon/Operational', 1, 'WS02', NULL,
        'C:\\Windows\\System32\\cmd.exe', 'cmd.exe /c whoami', NULL, NULL),
     (4294967297, 1, TIMESTAMP '2021-06-03 07:00:00', NULL, 'Microsoft-Windows-Sysmon/Operational', 1, 'WS02', NULL,
        'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'powershell -enc SQBFAFgA 100% it''s', 'x', NULL),
     (4294967298, 1, NULL, '["computer"]', 'Windows PowerShell', 400, 'ws02', NULL, 'C:\\Tools\\50_off.exe', NULL, NULL, 'error'),
     (4294967299, 1, TIMESTAMP '2021-06-03 08:00:00', NULL, 'Security', 4688, 'DC01', NULL, NULL, NULL, NULL, NULL)`,
  `CREATE TABLE rules (rule_idx INTEGER, key VARCHAR, id VARCHAR, title VARCHAR, level VARCHAR, level_rank TINYINT,
     description VARCHAR, tactics VARCHAR[], techniques VARCHAR[])`,
  `INSERT INTO rules VALUES
     (0, 'r-enc', 'r-enc', 'Encoded PowerShell - Sysmon', 'high', 3, 'd', ['execution'], ['T1059.001']),
     (1, 'r-logon', 'r-logon', 'Successful logon', 'informational', 0, 'd', ['initial-access'], ['T1078']),
     (2, 'r-whoami', 'r-whoami', 'Whoami execution', 'medium', 2, 'd', ['discovery'], ['T1033']),
     (3, 'r-crit', 'r-crit', 'Critical thing', 'critical', 4, 'd', ['persistence'], ['T1053'])`,
  'CREATE TABLE hits (rule_idx INTEGER, _zl_uid BIGINT)',
  'INSERT INTO hits VALUES (0, 4294967297), (1, 1), (2, 3), (3, 4294967297)',
  EVENT_LEVELS_SQL.replace('CREATE OR REPLACE TEMP TABLE', 'CREATE TABLE'),
];

export interface Fixture {
  rows(sql: string): Promise<Record<string, unknown>[]>;
  /** Event ids matching a predicate, in order: the shape most search tests assert on. */
  uids(predicate: string): Promise<number[]>;
  close(): void;
}

function plain(value: unknown): unknown {
  return typeof value === 'bigint' ? Number(value) : value;
}

export async function openFixture(): Promise<Fixture> {
  const instance = await DuckDBInstance.create(':memory:');
  const conn = await instance.connect();
  for (const statement of SETUP) await conn.run(statement);
  const rows = async (sql: string) =>
    (await conn.runAndReadAll(sql)).getRowObjectsJS().map((row) =>
      Object.fromEntries(Object.entries(row).map(([k, v]) => [k, plain(v)])));
  return {
    rows,
    async uids(predicate) {
      return (await rows(`SELECT _zl_uid FROM events WHERE ${predicate} ORDER BY _zl_uid`)).map((r) => r._zl_uid as number);
    },
    close() {
      conn.closeSync();
      instance.closeSync();
    },
  };
}
