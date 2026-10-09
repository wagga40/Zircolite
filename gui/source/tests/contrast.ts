import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Vitest runs from gui/source.
export const STYLESHEET = readFileSync(join(process.cwd(), 'src', 'app.css'), 'utf8');

/** A theme's colour tokens, read from the stylesheet the page uses: the light root block, or the dark one. */
export function tokens(theme: 'light' | 'dark'): Record<string, string> {
  const block = theme === 'light' ? /:root\s*\{([^}]*)\}/.exec(STYLESHEET) : /:root\[data-theme='dark'\]\s*\{([^}]*)\}/.exec(STYLESHEET);
  return Object.fromEntries([...(block?.[1] ?? '').matchAll(/(--[\w-]+):\s*(#[0-9a-f]{6})/gi)].map((m) => [m[1], m[2]]));
}

export const channels = (hex: string) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));

const linear = (rgb: number[]) =>
  rgb.map((c) => {
    const v = c / 255;
    return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  });

function luminance(rgb: number[]): number {
  const [r, g, b] = linear(rgb);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/** WCAG contrast ratio of two colours. */
export function contrast(a: number[], b: number[]): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

/** color-mix(in srgb, a p%, b): each channel mixed as written, then rounded as the browser stores it. */
export const mix = (a: string, b: string, p: number) => channels(a).map((c, i) => Math.round((c * p + channels(b)[i] * (100 - p)) / 100));

function lab(rgb: number[]): number[] {
  const [r, g, b] = linear(rgb);
  const f = (t: number) => (t > 216 / 24389 ? Math.cbrt(t) : (24389 / 27 * t + 16) / 116);
  const [x, y, z] = [(0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047, 0.2126 * r + 0.7152 * g + 0.0722 * b, (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883].map(f);
  return [116 * y - 16, 500 * (x - y), 200 * (y - z)];
}

/** CIE76 colour difference: about 2 is a just noticeable difference, past 40 two colours read as different hues. */
export function deltaE(a: number[], b: number[]): number {
  return Math.hypot(...lab(a).map((v, i) => v - lab(b)[i]));
}
