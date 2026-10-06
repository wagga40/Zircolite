import { describe, expect, it } from 'vitest';
import { CATALOG, isActive, parentId, replacement, subTechniques, tacticName, technique } from '../src/attack/catalog';
import { TACTICS } from './fixture';

describe('the ATT&CK catalogue', () => {
  it('names every tactic as ATT&CK does, one way for every view', () => {
    expect(['command-and-control', 'initial-access', 'stealth'].map(tacticName)).toEqual(['Command and Control', 'Initial Access', 'Stealth']);
    for (const short of TACTICS) expect(tacticName(short), short).toBe(CATALOG.tactics.find((t) => t.shortname === short)?.name);
    // A tactic the catalogue lacks, such as the retired Defense Evasion, is still named readably.
    expect(tacticName('defense-evasion')).toBe('Defense Evasion');
  });

  it('is Enterprise ATT&CK 19.2, with its tactics in Zircolite\'s order', () => {
    expect(CATALOG.version).toBe('19.2');
    expect(CATALOG.tactics.map((t) => t.shortname)).toEqual(TACTICS);
    expect(CATALOG.copyright).toMatch(/The MITRE Corporation/);
  });

  it('places every technique under at least one known tactic', () => {
    const known = new Set(TACTICS);
    for (const t of CATALOG.techniques) {
      expect(t.tactics.length, t.id).toBeGreaterThan(0);
      for (const tactic of t.tactics) expect(known.has(tactic), `${t.id} ${tactic}`).toBe(true);
    }
  });

  it('names techniques and their sub-techniques', () => {
    expect(technique('T1059')?.name).toBe('Command and Scripting Interpreter');
    expect(technique('T1059.001')?.name).toBe('PowerShell');
    expect(subTechniques('T1059').map((t) => t.id)).toContain('T1059.001');
    expect(parentId('T1059.001')).toBe('T1059');
    expect(parentId('T1059')).toBe('T1059');
  });

  it('knows what replaced a revoked technique, and that it is no longer active', () => {
    expect(isActive('T1562.001')).toBe(false);
    expect(technique('T1562.001')).toBeUndefined();
    expect(replacement('T1562.001')?.id).toBe('T1685');
    expect(replacement('T1059')).toBeUndefined();
    for (const target of Object.values(CATALOG.revoked)) expect(isActive(target), target).toBe(true);
  });
});
