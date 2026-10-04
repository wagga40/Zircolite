// Must equal zircolite/package.py PACKAGE_FORMAT; tests/test_viewer_source.py checks it.
export const PACKAGE_FORMAT = 1;

export interface PackageFile {
  name: string;
  kind: 'engine' | 'data';
  bytes: number;
  sha256: string;
  chunks: string[];
}

export interface TimeStats {
  column: string | null;
  min: number | null;
  max: number | null;
  unparsed: number;
  missing: number;
}

export interface Manifest {
  format: number;
  zircolite: string;
  created: string;
  run: {
    mode: string;
    executor: string;
    time_field: string;
    timestamp_format: string;
    event_filter: string;
    after: string;
    before: string;
    limit: number;
    rules_loaded: number;
  };
  tactics: string[];
  levels: string[];
  totals: { events: number; parts: number; rules_matched: number; hits: number; alerts: number };
  columns: { name: string; key: string; type: 'BIGINT' | 'DOUBLE' | 'VARCHAR'; count: number }[];
  families: { channel: string | null; eventid: string | null; columns: string[] }[];
  parts: { part: number; sources: string[]; events: number; spellings: Record<string, string>; time: TimeStats }[];
  failed_sources: string[];
  warnings: string[];
  files: PackageFile[];
}
