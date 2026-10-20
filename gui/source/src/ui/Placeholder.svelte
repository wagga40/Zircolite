<script lang="ts">
  /** What a panel shows before its first answer: what it is doing, over the shape of rows to come. */
  let { label, lines = 3 }: { label: string; lines?: number } = $props();
  const WIDTHS = [92, 74, 86, 64, 80, 70, 88, 60];
</script>

<div class="placeholder">
  <p role="status">{label}</p>
  {#each { length: lines } as _, i (i)}<span class="bar" style:width={`${WIDTHS[i % WIDTHS.length]}%`} aria-hidden="true"></span>{/each}
</div>

<style>
  .placeholder { display: grid; gap: 8px; padding: 8px 0; }
  p { margin: 0 0 2px; color: var(--ink-2); font-size: var(--t-13); }
  .bar { position: relative; display: block; height: 10px; overflow: hidden; border-radius: var(--radius); background: var(--rule); }
  /* A moving transform, which the compositor draws without repainting the page beside the queries. */
  .bar::after {
    content: ''; position: absolute; inset: 0; transform: translateX(-100%);
    background: linear-gradient(90deg, transparent, color-mix(in srgb, var(--panel) 55%, transparent), transparent);
    animation: shimmer 1.4s linear infinite;
  }
  @keyframes shimmer { to { transform: translateX(100%); } }
  @media (prefers-reduced-motion: reduce) { .bar::after { animation: none; display: none; } }
</style>
