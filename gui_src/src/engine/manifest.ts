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
  // The version in the viewer.json of the viewer this package was written with.
  viewer: string;
  created: string;
  run: {
    mode: string;
    executor: string;
    time_field: string;
    timestamp_format: string;
    event_filter: string;
    // null when the run did not apply the time range: database input is read whole.
    after: string | null;
    before: string | null;
    limit: number;
    rules_loaded: number;
  };
  tactics: string[];
  levels: string[];
  // rules_matched counts distinct rule keys, as the run summary does; rules.parquet has one row
  // per matched ruleset entry, so a rule's Sysmon and Generic variants are two rows sharing a key.
  totals: { events: number; parts: number; rules_matched: number; hits: number; alerts: number };
  columns: { name: string; key: string; type: 'BIGINT' | 'DOUBLE' | 'VARCHAR'; count: number }[];
  families: { channel: string | null; eventid: string | null; columns: string[] }[];
  parts: {
    part: number;
    sources: string[];
    events: number;
    // 'partial' when a source could be read only in part or not at all; those sources are in unreadable.
    status: 'complete' | 'partial';
    unreadable: string[];
    spellings: Record<string, string>;
    time: TimeStats;
  }[];
  failed_sources: string[];
  warnings: string[];
  files: PackageFile[];
}
