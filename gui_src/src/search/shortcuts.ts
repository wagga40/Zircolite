import { asciiLower } from '../engine/sql';

export interface Shortcut {
  name: string;
  description: string;
  example: string;
  /** Log fields searched by host: and user:, the first ones present in the package. */
  fields?: readonly string[];
}

export const SHORTCUTS: readonly Shortcut[] = [
  { name: 'rule', description: 'Events a rule matched, by title or id. * matches any characters.', example: 'rule:*powershell*' },
  { name: 'level', description: 'Events with a detection at this level. >=, >, <= and < compare levels.', example: 'level:>=high' },
  { name: 'tactic', description: 'Events detected under an ATT&CK tactic.', example: 'tactic:persistence' },
  { name: 'technique', description: 'Events detected under an ATT&CK technique, sub-techniques included.', example: 'technique:T1059' },
  { name: 'host', description: 'Events from a host, whichever field holds its name.', example: 'host:DC01', fields: ['Computer', 'ComputerName', 'Hostname', 'host'] },
  { name: 'user', description: 'Events naming an account, whichever field holds it.', example: 'user:administrator', fields: ['TargetUserName', 'SubjectUserName', 'User', 'UserName', 'AccountName'] },
];

export const SYNTAX: readonly { pattern: string; meaning: string }[] = [
  { pattern: 'powershell', meaning: 'Any field contains the word, in any case.' },
  { pattern: '"net user"', meaning: 'Any field contains the phrase.' },
  { pattern: 'EventID:4624', meaning: 'A field equals a value, in any case.' },
  { pattern: 'Image:*\\cmd.exe', meaning: '* matches any characters, outside quotes.' },
  { pattern: 'EventID:>4600', meaning: 'Numeric fields compare with >, >=, < and <=.' },
  { pattern: '-Channel:Security', meaning: 'Leave matches out. Events without the field stay in.' },
  { pattern: 'a OR b', meaning: 'Either term. Terms side by side must both match.' },
  { pattern: '(a OR b) c', meaning: 'Parentheses group terms.' },
  { pattern: '"level":error', meaning: "Quote a field name to search a log field that shares a shortcut's name." },
];

export function findShortcut(name: string): Shortcut | undefined {
  const key = asciiLower(name);
  return SHORTCUTS.find((shortcut) => shortcut.name === key);
}
