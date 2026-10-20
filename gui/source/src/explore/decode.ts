/**
 * Encoded text inside an event's values: a PowerShell encoded command,
 * Base64 (maybe gzip or deflate packed), URL escapes and hex. A decoding is
 * offered only when it reads as text, and is shown as text, never markup.
 */

export type EncodedKind = 'powershell' | 'base64' | 'url' | 'hex';

export interface EncodedPart {
  kind: EncodedKind;
  /** The encoded text, without the flag or quotes around it. */
  source: string;
  start: number;
}

export interface Decoded {
  label: string;
  text: string;
  /** Only the first DECODED_LIMIT characters are kept. */
  truncated: boolean;
}

/** Characters of a decoding kept for display; past this the drawer would hold megabytes of text. */
export const DECODED_LIMIT = 64 * 1024;
/**
 * Logs are written by whoever attacked the host, so one value may be crafted
 * to exhaust the page: a payload may unpack to this much, a value's payloads
 * to this much in all, at most this many parts decode, and only this much of
 * a value is searched for them.
 */
const UNPACKED_LIMIT = 1024 * 1024;
const UNPACKED_TOTAL = 4 * 1024 * 1024;
export const DECODED_PARTS = 16;
export const SCANNED_LIMIT = 512 * 1024;

// -EncodedCommand and every prefix PowerShell accepts for it (-e, -en, -enc, …), and -ec, with - or /.
const POWERSHELL = /(?:^|[\s"'])[-/](?:e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?|ec)\s+["']?([A-Za-z0-9+/]{8,}={0,2})/gi;
const BASE64 = /[A-Za-z0-9+/]{24,}={0,2}/g;
const HEX = /(?:0x)?((?:[0-9A-Fa-f]{2}){12,})/g;
const URL_ESCAPE = /%[0-9A-Fa-f]{2}/;

/** The parts of a value that may be encoded, in the order they appear, each once. */
export function encodedParts(whole: string): EncodedPart[] {
  const value = whole.length > SCANNED_LIMIT ? whole.slice(0, SCANNED_LIMIT) : whole;
  const parts: EncodedPart[] = [];
  const seen = new Set<string>();
  const add = (kind: EncodedKind, source: string, start: number) => {
    const key = `${kind === 'powershell' ? 'base64' : kind}\u0000${source}`;
    if (seen.has(key)) return;
    seen.add(key);
    parts.push({ kind, source, start });
  };
  for (const match of value.matchAll(POWERSHELL)) add('powershell', match[1], (match.index ?? 0) + match[0].indexOf(match[1]));
  for (const match of value.matchAll(BASE64)) if (match[0].length % 4 !== 1) add('base64', match[0], match.index ?? 0);
  for (const match of value.matchAll(HEX)) add('hex', match[1], (match.index ?? 0) + match[0].indexOf(match[1]));
  if (URL_ESCAPE.test(value)) add('url', value, 0);
  const rank: Record<EncodedKind, number> = { powershell: 0, base64: 1, hex: 2, url: 3 };
  return parts.sort((a, b) => a.start - b.start || rank[a.kind] - rank[b.kind]);
}

function base64Bytes(text: string): Uint8Array | null {
  try {
    const padded = text.replace(/=+$/, '');
    const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

function hexBytes(text: string): Uint8Array {
  return Uint8Array.from(text.match(/../g) ?? [], (pair) => parseInt(pair, 16));
}

/** Whether bytes look like UTF-16LE: every other byte mostly zero, as Windows writes ASCII text. */
function wide(bytes: Uint8Array): boolean {
  let zeros = 0;
  for (let i = 1; i < bytes.length; i += 2) if (bytes[i] === 0) zeros++;
  return bytes.length >= 4 && bytes.length % 2 === 0 && zeros >= bytes.length / 2 * 0.3;
}

function bytesText(bytes: Uint8Array): string {
  return new TextDecoder(wide(bytes) ? 'utf-16le' : 'utf-8').decode(bytes);
}

/** Whether decoded text reads as text: almost no control characters or undecodable bytes. */
function readable(text: string): boolean {
  if (text.length < 4) return false;
  let odd = 0;
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0;
    if (char === '�' || (code < 32 && char !== '\t' && char !== '\n' && char !== '\r') || (code >= 0x7f && code < 0xa0)) odd++;
  }
  return odd <= text.length * 0.05;
}

/** What one value's decoding may still unpack, and whether that ran out. */
interface Budget {
  unpacked: number;
  spent: boolean;
}

interface Unpacked {
  bytes: Uint8Array;
  /** The payload broke off, or turned to bytes that do not unpack, after these. */
  cut: boolean;
}

async function unpack(bytes: Uint8Array, format: 'gzip' | 'deflate-raw', budget: Budget): Promise<Unpacked | null> {
  const limit = Math.min(UNPACKED_LIMIT, budget.unpacked);
  if (limit <= 0) {
    budget.spent = true;
    return null;
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  let cut = false;
  try {
    const reader = new Blob([bytes as BlobPart]).stream().pipeThrough(new DecompressionStream(format)).getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      size += value.length;
      if (size > limit) {
        await reader.cancel();
        break;
      }
    }
  } catch {
    // A script split across events, or cut by the log, still unpacks up to where it stops.
    cut = true;
  }
  if (size === 0) return null;
  if (size > limit && limit < UNPACKED_LIMIT) budget.spent = true;
  budget.unpacked -= Math.min(size, limit);
  const out = new Uint8Array(Math.min(size, limit));
  let at = 0;
  for (const chunk of chunks) {
    const room = out.length - at;
    if (room <= 0) break;
    out.set(chunk.subarray(0, room), at);
    at += Math.min(chunk.length, room);
  }
  return { bytes: out, cut };
}

function kept(label: string, text: string): Decoded {
  return text.length > DECODED_LIMIT ? { label, text: text.slice(0, DECODED_LIMIT), truncated: true } : { label, text, truncated: false };
}

async function decodeBase64(source: string, budget: Budget): Promise<Decoded | null> {
  const bytes = base64Bytes(source);
  if (!bytes) return null;
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) return unpacked('Base64, gzip', await unpack(bytes, 'gzip', budget));
  const text = bytesText(bytes);
  if (readable(text)) return kept('Base64', text);
  // Raw deflate carries no signature: it is tried only on bytes that are not text themselves.
  return unpacked('Base64, deflate', await unpack(bytes, 'deflate-raw', budget));
}

function unpacked(label: string, result: Unpacked | null): Decoded | null {
  // A cut payload can end inside a character: what TextDecoder makes of the last bytes is not held against it.
  const text = result && bytesText(result.bytes).replace(/\uFFFD+$/, '');
  if (!result || !text || !readable(text)) return null;
  return kept(result.cut ? `${label}, cut short` : label, text);
}

function decodeUrl(value: string): string {
  return value.replace(/(?:%[0-9A-Fa-f]{2})+/g, (run) => {
    try {
      return decodeURIComponent(run);
    } catch {
      return run;
    }
  });
}

async function decode(part: EncodedPart, budget: Budget): Promise<Decoded | null> {
  switch (part.kind) {
    case 'powershell': {
      // Other tools take -e as well (gpg, mysql, schtasks /ec): almost any token is valid UTF-16LE, so the
      // bytes must look like it before they are read as a command.
      const bytes = base64Bytes(part.source);
      const text = bytes && wide(bytes) && new TextDecoder('utf-16le').decode(bytes);
      return text && readable(text) ? kept('PowerShell -EncodedCommand', text) : null;
    }
    case 'base64':
      return decodeBase64(part.source, budget);
    case 'hex': {
      const text = bytesText(hexBytes(part.source));
      return readable(text) ? kept('Hex', text) : null;
    }
    case 'url': {
      const text = decodeUrl(part.source);
      return text !== part.source ? kept('URL encoding', text) : null;
    }
  }
}

export interface Decodings {
  decoded: Decoded[];
  /** What the limits kept from being decoded, said so that nothing goes missing unseen. */
  incomplete: string[];
}

/**
 * What a value decodes to, part by part, leaving out parts that do not decode
 * to text. An encoded command is tried first: junk in front of it must not use
 * up the tries.
 */
export async function decodeAll(value: string): Promise<Decodings> {
  const parts = encodedParts(value);
  const ordered = [...parts.filter((part) => part.kind === 'powershell'), ...parts.filter((part) => part.kind !== 'powershell')];
  const decoded: Decoded[] = [];
  const texts = new Set<string>();
  const budget: Budget = { unpacked: UNPACKED_TOTAL, spent: false };
  let tried = 0;
  // Parts that decode to nothing still cost a try each, so the tries are bounded as well as the decodings.
  for (const part of ordered) {
    if (decoded.length >= DECODED_PARTS || tried >= DECODED_PARTS * 2) break;
    tried++;
    const found = await decode(part, budget);
    if (!found || texts.has(found.text)) continue;
    texts.add(found.text);
    decoded.push(found);
  }
  const incomplete: string[] = [];
  if (value.length > SCANNED_LIMIT) incomplete.push(`Only the first ${SCANNED_LIMIT / 1024} KiB of the value was searched for encoded text.`);
  const left = ordered.length - tried;
  if (left > 0) incomplete.push(`${left} more encoded-looking ${left === 1 ? 'part was' : 'parts were'} not tried.`);
  if (budget.spent) incomplete.push(`Unpacking stopped after ${UNPACKED_TOTAL / 1024 / 1024} MiB of packed payloads.`);
  return { decoded, incomplete };
}

export async function decodings(value: string): Promise<Decoded[]> {
  return (await decodeAll(value)).decoded;
}
