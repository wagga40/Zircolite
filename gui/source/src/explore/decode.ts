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

/** Bytes as text: UTF-16LE when every other byte is mostly zero, as Windows writes ASCII text, UTF-8 otherwise. */
function bytesText(bytes: Uint8Array): string {
  let zeros = 0;
  for (let i = 1; i < bytes.length; i += 2) if (bytes[i] === 0) zeros++;
  const wide = bytes.length >= 4 && bytes.length % 2 === 0 && zeros >= bytes.length / 2 * 0.3;
  return new TextDecoder(wide ? 'utf-16le' : 'utf-8').decode(bytes);
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

/** What one decodings() call may still unpack. */
interface Budget {
  unpacked: number;
}

async function unpack(bytes: Uint8Array, format: 'gzip' | 'deflate-raw', budget: Budget): Promise<Uint8Array | null> {
  const limit = Math.min(UNPACKED_LIMIT, budget.unpacked);
  if (limit <= 0) return null;
  try {
    const reader = new Blob([bytes as BlobPart]).stream().pipeThrough(new DecompressionStream(format)).getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
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
    budget.unpacked -= Math.min(size, limit);
    const out = new Uint8Array(Math.min(size, limit));
    let at = 0;
    for (const chunk of chunks) {
      const room = out.length - at;
      if (room <= 0) break;
      out.set(chunk.subarray(0, room), at);
      at += Math.min(chunk.length, room);
    }
    return out;
  } catch {
    return null;
  }
}

function kept(label: string, text: string): Decoded {
  return text.length > DECODED_LIMIT ? { label, text: text.slice(0, DECODED_LIMIT), truncated: true } : { label, text, truncated: false };
}

async function decodeBase64(source: string, budget: Budget): Promise<Decoded | null> {
  const bytes = base64Bytes(source);
  if (!bytes) return null;
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    const unpacked = await unpack(bytes, 'gzip', budget);
    const text = unpacked && bytesText(unpacked);
    return text && readable(text) ? kept('Base64, gzip', text) : null;
  }
  const text = bytesText(bytes);
  if (readable(text)) return kept('Base64', text);
  // Raw deflate carries no signature: it is tried only on bytes that are not text themselves.
  const unpacked = await unpack(bytes, 'deflate-raw', budget);
  const inflated = unpacked && bytesText(unpacked);
  return inflated && readable(inflated) ? kept('Base64, deflate', inflated) : null;
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
      const bytes = base64Bytes(part.source);
      const text = bytes && new TextDecoder('utf-16le').decode(bytes);
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

/** What a value decodes to, part by part, leaving out parts that do not decode to text. */
export async function decodings(value: string): Promise<Decoded[]> {
  const found: Decoded[] = [];
  const texts = new Set<string>();
  const budget: Budget = { unpacked: UNPACKED_TOTAL };
  // Parts that decode to nothing still cost a try each, so the tries are bounded as well as the decodings.
  for (const part of encodedParts(value).slice(0, DECODED_PARTS * 2)) {
    if (found.length >= DECODED_PARTS) break;
    const decoded = await decode(part, budget);
    if (!decoded || texts.has(decoded.text)) continue;
    texts.add(decoded.text);
    found.push(decoded);
  }
  return found;
}
