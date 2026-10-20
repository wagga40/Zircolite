#!/usr/bin/env python3
"""Record a tour of the Zircolite Viewer as PNG frames with their timestamps.

Usage:
  uv run --no-project --with playwright==1.62.0 python record.py \
      --package <unpacked package dir> --viewer <viewer build dir> --out <work dir> [--dry]

The package directory is copied to <work dir>/site and the viewer's app.js, app.css and
index.html are copied over it, so the package itself is never changed. Frames go to
<work dir>/frames with <work dir>/frames.json; encode.py turns them into a WebP.
--dry runs the same storyboard without capturing and saves a screenshot per beat in
<work dir>/shots, to check targets and waits quickly.
"""

import argparse
import asyncio
import base64
import json
import math
import os
import shutil
import time
from contextlib import asynccontextmanager
from pathlib import Path

from playwright.async_api import async_playwright

WIDTH, HEIGHT = 1280, 800
REST = (930, 86)  # where the cursor waits on the Overview: blank header space, no hover target

# The storyboard below is tied to EVTX-ATTACK-SAMPLES: a rule title, two event times, plink.exe PID 2312
# and the 87 sessions of its Logons view. Another corpus needs those targets changed.

# The arrow follows real mouse events, so it shows exactly where Playwright points.
# It lives in a manual popover so it can be raised above a modal <dialog> in the top layer.
CURSOR_JS = r"""
(() => {
  const install = () => {
    if (document.getElementById('__tour_cursor')) return;
    const host = document.createElement('div');
    host.id = '__tour_cursor';
    host.setAttribute('popover', 'manual');
    const set = (el, props) => { for (const [k, v] of Object.entries(props)) el.style.setProperty(k, v, 'important'); };
    set(host, { position: 'fixed', inset: 'auto', left: '0px', top: '0px', margin: '0', padding: '0', border: '0',
      background: 'transparent', overflow: 'visible', width: '1px', height: '1px', 'pointer-events': 'none',
      'z-index': '2147483647', transform: 'translate(-60px, -60px)', 'will-change': 'transform' });
    const ring = document.createElement('div');
    set(ring, { position: 'absolute', left: '-17px', top: '-17px', width: '34px', height: '34px', 'border-radius': '50%',
      background: 'rgba(14, 116, 144, 0.32)', border: '2px solid rgba(14, 116, 144, 0.75)', opacity: '0', 'box-sizing': 'border-box' });
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('width', '24'); svg.setAttribute('height', '32'); svg.setAttribute('viewBox', '0 0 24 32');
    set(svg, { position: 'absolute', left: '-2px', top: '-2px', overflow: 'visible', 'transform-origin': '2px 2px' });
    const path = document.createElementNS(ns, 'path');
    path.setAttribute('d', 'M2 2 L2 25 L7.6 19.6 L11.4 28.4 L15.2 26.8 L11.5 18.2 L19 18.2 Z');
    path.setAttribute('fill', '#111');
    path.setAttribute('stroke', '#fff');
    path.setAttribute('stroke-width', '1.6');
    path.setAttribute('stroke-linejoin', 'round');
    svg.append(path);
    host.append(ring, svg);
    document.documentElement.append(host);
    const raise = () => { try { if (host.matches(':popover-open')) host.hidePopover(); host.showPopover(); } catch (e) {} };
    raise();
    addEventListener('mousemove', (e) => host.style.setProperty('transform', `translate(${e.clientX}px, ${e.clientY}px)`, 'important'),
      { capture: true, passive: true });
    addEventListener('mousedown', () => {
      ring.animate([{ opacity: 0.9, transform: 'scale(0.35)' }, { opacity: 0, transform: 'scale(1.35)' }], { duration: 420, easing: 'ease-out' });
      svg.animate([{ transform: 'scale(1)' }, { transform: 'scale(0.84)' }, { transform: 'scale(1)' }], { duration: 220, easing: 'ease-out' });
    }, { capture: true });
    new MutationObserver((records) => {
      if (records.some((r) => r.target instanceof HTMLDialogElement && r.target.open)) raise();
    }).observe(document.documentElement, { subtree: true, attributes: true, attributeFilter: ['open'] });
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', install); else install();
  // A steady caret: a blinking one would add a frame every half second while a field holds focus.
  const sheet = new CSSStyleSheet();
  sheet.replaceSync('* { caret-animation: manual !important; }');
  document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
})();
"""


def forbidden_strings() -> list[str]:
    home = str(Path.home())
    names = {'/Users/', home}
    user = os.environ.get('USER') or Path.home().name
    if user and len(user) >= 3:
        names.add(user)
    return sorted(names)


def prepare_site(package: Path, viewer: Path, site: Path) -> None:
    if not (package / 'index.html').is_file() or not (package / 'data' / 'manifest.js').is_file():
        raise SystemExit(f'{package} is not an unpacked package (index.html, data/manifest.js)')
    if site.exists():
        shutil.rmtree(site)
    shutil.copytree(package, site)
    for name in ('app.js', 'app.css', 'index.html'):
        source = viewer / name
        if not source.is_file():
            raise SystemExit(f'the viewer directory has no {name}')
        shutil.copyfile(source, site / name)


def check_manifest(site: Path) -> None:
    text = (site / 'data' / 'manifest.js').read_text(encoding='utf-8')
    found = [s for s in forbidden_strings() if s.lower() in text.lower()]
    if found:
        raise SystemExit(f'data/manifest.js holds {found}: make the package from relative paths')


class Tour:
    def __init__(self, page, work: Path, dry: bool):
        self.page = page
        self.work = work
        self.dry = dry
        self.mouse = REST
        self.frames: list[dict] = []
        self.marks: list[list[float]] = []
        self.coarse_spans: list[list[float]] = []
        self.beats: list[dict] = []
        self.leaks: list[str] = []
        self.cdp = None
        self.frames_dir = work / 'frames'
        self.shots_dir = work / 'shots'
        self.pending_acks: set = set()

    # Capture

    def _on_frame(self, params: dict) -> None:
        # Ack first: Chrome drops the frames it renders while one is unacknowledged.
        task = asyncio.ensure_future(self.cdp.send('Page.screencastFrameAck', {'sessionId': params['sessionId']}))
        self.pending_acks.add(task)
        task.add_done_callback(self.pending_acks.discard)
        self._save(base64.b64decode(params['data']), params['metadata']['timestamp'])

    def _save(self, png: bytes, at: float, settled: bool = False) -> None:
        path = self.frames_dir / f'{len(self.frames):05d}.png'
        path.write_bytes(png)
        self.frames.append({'file': path.name, 't': at, **({'settled': True} if settled else {})})

    async def settle(self) -> None:
        """Adds a screenshot of the page as it now stands.

        The screencast can drop the last frame of a change, which would leave a hold showing
        a half-drawn state; this frame, stamped after the capture, replaces it.
        """
        if self.dry:
            return
        await asyncio.sleep(0.16)
        shot = await self.cdp.send('Page.captureScreenshot', {'format': 'png'})
        self._save(base64.b64decode(shot['data']), time.time(), settled=True)

    async def start(self) -> None:
        if self.dry:
            self.shots_dir.mkdir(parents=True, exist_ok=True)
            return
        if self.frames_dir.exists():
            shutil.rmtree(self.frames_dir)
        self.frames_dir.mkdir(parents=True)
        self.cdp = await self.page.context.new_cdp_session(self.page)
        self.cdp.on('Page.screencastFrame', self._on_frame)
        await self.cdp.send('Page.startScreencast', {'format': 'png', 'everyNthFrame': 1, 'maxWidth': WIDTH, 'maxHeight': HEIGHT})
        self.started = time.time()

    async def stop(self) -> None:
        if self.dry:
            return
        end = time.time()
        await self.cdp.send('Page.stopScreencast')
        await asyncio.sleep(0.3)
        (self.work / 'frames.json').write_text(json.dumps({
            'width': WIDTH, 'height': HEIGHT, 'start': self.started, 'end': end,
            'frames': self.frames, 'compress': self.marks, 'coarse': self.coarse_spans, 'beats': self.beats,
        }, indent=1))
        print(f'{len(self.frames)} frames over {end - self.started:.1f} s')

    # Pointer

    async def point(self, target, fx: float = 0.5, fy: float = 0.5, dx: float = 0, dy: float = 0) -> tuple[float, float]:
        if isinstance(target, tuple):
            return target
        await target.wait_for(state='visible', timeout=30_000)
        box = await target.bounding_box()
        if box is None:
            raise RuntimeError(f'{target} has no box')
        return box['x'] + box['width'] * fx + dx, box['y'] + box['height'] * fy + dy

    async def glide(self, target, duration: float | None = None, **where) -> None:
        x, y = await self.point(target, **where)
        x0, y0 = self.mouse
        distance = math.hypot(x - x0, y - y0)
        if duration is None:
            duration = min(0.6, max(0.25, 0.16 + distance / 2200))
        steps = max(2, round(duration * 50))
        start = time.monotonic()
        for i in range(1, steps + 1):
            t = i / steps
            e = t * t * (3 - 2 * t)
            await self.page.mouse.move(x0 + (x - x0) * e, y0 + (y - y0) * e)
            delay = start + duration * t - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
        self.mouse = (x, y)

    async def click(self, target, settle: float = 0.08, **where) -> None:
        await self.glide(target, **where)
        await asyncio.sleep(settle)
        await self.page.mouse.down()
        await asyncio.sleep(0.07)
        await self.page.mouse.up()

    async def type(self, text: str, delay: float = 0.055) -> None:
        await self.page.keyboard.type(text, delay=delay * 1000)

    # Waiting

    async def until(self, read, what: str, timeout: float = 90) -> object:
        started = time.monotonic()
        while True:
            value = await read()
            if value:
                return value
            if time.monotonic() - started > timeout:
                raise TimeoutError(f'timed out waiting for {what}')
            await asyncio.sleep(0.04)

    @asynccontextmanager
    async def loading(self, cap: float = 0.2):
        """Marks a stretch spent waiting for data, which the encoder shortens to at most `cap` seconds."""
        begun = time.time()
        yield
        self.marks.append([begun, time.time(), cap])

    @asynccontextmanager
    async def coarse(self, fps: float = 5):
        """Marks a stretch, such as a scroll, that the encoder keeps at only `fps` frames a second."""
        begun = time.time()
        yield
        self.coarse_spans.append([begun, time.time(), fps])

    async def attr(self, selector: str, name: str) -> str | None:
        locator = self.page.locator(selector)
        if await locator.count() == 0:
            return None
        return await locator.first.get_attribute(name)

    async def results(self, after: int = -1) -> dict:
        """Waits for Explore's list to settle on a build newer than `after`, its first rows read."""
        async def read():
            out = self.page.locator('#result-count')
            if await out.count() == 0:
                return None
            busy, build, count = [await out.get_attribute(n) for n in ('data-busy', 'data-build', 'data-count')]
            if busy != 'false' or count in (None, '') or int(build or 0) <= after:
                return None
            if int(count) > 0:
                if await self.page.locator('#result-grid .rows [role=row]').count() == 0:
                    return None
                if await self.page.locator('#result-grid .rows [role=gridcell].loading').count() > 0:
                    return None
            return {'build': int(build), 'count': int(count)}
        return await self.until(read, 'the results')

    async def is_attr(self, locator, name: str, value: str) -> bool:
        return await locator.count() > 0 and (await locator.first.get_attribute(name)) == value

    async def first_header(self, table: str, text: str) -> bool:
        header = self.page.locator(f'{table} thead th').first
        return await header.count() > 0 and (await header.inner_text()).strip().startswith(text)

    async def attr_is_number(self, selector: str, name: str, test) -> bool:
        value = await self.attr(selector, name)
        return value not in (None, '') and test(float(value))

    async def drawer_read(self, drawer) -> bool:
        heading = drawer.locator('h2')
        if await heading.count() == 0 or (await heading.inner_text()).strip() in ('', 'Event'):
            return False
        return await drawer.locator('dt').count() > 0

    async def build(self) -> int:
        value = await self.attr('#result-count', 'data-build')
        return int(value) if value else -1

    async def ready_number(self, selector: str, name: str, what: str) -> float:
        async def read():
            value = await self.attr(selector, name)
            return None if value in (None, '') else float(value) + 1e-9
        return await self.until(read, what)

    # Holding and checking

    async def hold(self, seconds: float, name: str | None = None) -> None:
        begun = time.monotonic()
        await self.settle()
        if name:
            self.beats.append({'name': name, 't': time.time(), 'hold': seconds})
            await self.check(name)
            if self.dry:
                await asyncio.sleep(0.16)
                await self.page.screenshot(path=str(self.shots_dir / f'{len(self.beats):02d}-{name}.png'))
        left = seconds - (time.monotonic() - begun)
        if left > 0:
            await asyncio.sleep(left)

    async def check(self, name: str) -> None:
        text = await self.page.inner_text('body')
        html = await self.page.content()
        for needle in forbidden_strings():
            for where, haystack in (('text', text), ('html', html)):
                at = haystack.lower().find(needle.lower())
                if at >= 0:
                    self.leaks.append(f'{name}: {needle!r} in the page {where}: …{haystack[max(0, at - 60):at + 60]!r}…')

    async def nav(self, name: str) -> None:
        await self.click(self.page.locator('nav[aria-label="Views"] button', has_text=name).first)


async def wait_ready(page) -> None:
    started = time.monotonic()
    while True:
        title = await page.title()
        if 'ready' in title:
            break
        if 'error' in title:
            raise SystemExit(f'the viewer reports an error: {title}')
        if time.monotonic() - started > 180:
            raise SystemExit('the viewer did not become ready')
        await asyncio.sleep(0.2)
    # The full-text index loads in the background; wait for it so nothing changes mid-tour.
    while time.monotonic() - started < 180:
        status = await page.locator('#engine-check').get_attribute('data-text-index')
        if status in ('ready', 'failed', 'none', 'absent', None):
            break
        await asyncio.sleep(0.2)


# The storyboard. Each beat leaves the page where the next expects it.

async def overview(t: Tour) -> None:
    await t.ready_number('#overview-tiles', 'data-events', 'the overview')
    await t.hold(2.2, 'overview')


async def detections(t: Tour) -> None:
    p = t.page
    await t.nav('Detections')
    async with t.loading():
        await t.ready_number('#detections-summary', 'data-rules', 'the detections')
    await t.hold(0.5, 'detections')
    row = p.locator('button[data-key]', has_text='Hacktool Execution - Imphash - Sysmon').first
    await t.click(row, fx=0.25)
    async with t.loading():
        await p.locator('li.rule .details').first.wait_for()
    await t.hold(2.0, 'rule-expanded')
    show = p.locator('li.rule:has(button[aria-expanded="true"]) .details button', has_text='Show events').first
    before = await t.build()
    await t.click(show)
    async with t.loading():
        await t.results(before)
    await t.hold(0.9, 'explore-rule')


async def explore(t: Tour) -> None:
    p = t.page
    family = p.locator('.bar button', has_text='Columns for').first
    await t.click(family)
    async with t.loading():
        await p.locator('[data-field-key="image"]').wait_for()
        await asyncio.sleep(0.1)
        await t.results()
    await t.hold(1.5, 'columns-for-family')
    chip = p.locator('ul[aria-label="Active filters"] li button').first
    before = await t.build()
    await t.click(chip)
    async with t.loading():
        await t.results(before)
    await t.hold(0.3, 'all-events')
    cell = p.get_by_label('Filter Image', exact=True)
    await t.click(cell)
    await t.type('powershell')
    await asyncio.sleep(0.2)
    before = await t.build()
    await p.keyboard.press('Enter')
    async with t.loading():
        await t.results(before)
    await t.hold(1.0, 'image-filter')
    funnel = p.locator('[data-column-funnel="image"]')
    await t.click(funnel)
    menu = p.locator('[data-column-menu]')
    async with t.loading():
        await menu.locator('li[data-value]').first.wait_for()
    await t.hold(0.6, 'funnel-menu')
    rare = menu.get_by_role('button', name='Rarest first')
    await t.click(rare)
    async with t.loading():
        await t.until(lambda: t.is_attr(rare, 'aria-pressed', 'true'), 'rarest first')
        await t.until(lambda: t.is_attr(menu.locator('section.values'), 'aria-busy', 'false'), 'the rarest values')
    await t.hold(1.6, 'rarest-first')
    await p.keyboard.press('Escape')
    await menu.wait_for(state='detached')
    sort = p.locator('#result-grid [role=columnheader] button.sort', has_text='Level').first
    before = await t.build()
    await t.click(sort, fx=0.3)
    async with t.loading():
        await t.results(before)
    await t.hold(1.0, 'sorted')


async def event_drawer(t: Tour) -> None:
    p = t.page
    drawer = p.get_by_role('complementary', name='Event details')
    rows = p.locator('#result-grid .rows [role=row]')

    async def row_with(time_text: str):
        for i in range(await rows.count()):
            cell = rows.nth(i).locator('[role=gridcell]').first
            if (await cell.text_content() or '').startswith(time_text):
                return rows.nth(i)
        raise RuntimeError(f'no row at {time_text}')

    async def heading_is(text: str) -> bool:
        sub = drawer.locator('header .sub')
        return await sub.count() > 0 and (await sub.inner_text()).startswith(text)

    # An encoded PowerShell command started by a web server: nine rules matched it.
    await t.click(await row_with('2019-05-27 01:28:42'), fx=0.12)
    async with t.loading():
        await drawer.wait_for()
        await t.until(lambda: heading_is('2019-05-27 01:28:42'), 'the encoded event')
        await t.until(lambda: drawer.get_by_role('button', name='Show what CommandLine decodes to').count(), 'the decode button')
    await t.hold(1.2, 'drawer-detections')
    decode = drawer.get_by_role('button', name='Show what CommandLine decodes to')
    # Bring the end of the encoded value and its Decode button into the drawer's upper half.
    async with t.coarse(5):
        await decode.evaluate("""(button) => {
            const aside = button.closest('aside');
            const top = button.getBoundingClientRect().top - aside.getBoundingClientRect().top + aside.scrollTop;
            aside.scrollTo({ top: top - 250, behavior: 'smooth' });
        }""")
        await t.glide(decode, duration=0.55)
        await t.until(lambda: drawer.evaluate('(a) => new Promise((r) => { let last = a.scrollTop; const tick = () => requestAnimationFrame(() => { if (a.scrollTop === last) r(true); else { last = a.scrollTop; tick(); } }); setTimeout(tick, 60); })'), 'the drawer scroll')
    await t.hold(0.4, 'drawer-encoded')
    await t.click(decode)
    async with t.loading():
        await drawer.locator('.decoded pre').first.wait_for()
    await t.hold(2.6, 'decoded')

    # A download cradle: its process made a network connection and wrote a file.
    await t.click(await row_with('2019-07-29 21:33:23'), fx=0.12)
    async with t.loading():
        await drawer.evaluate('(a) => { a.scrollTop = 0; }')
        await t.until(lambda: heading_is('2019-07-29 21:33:23'), 'the cradle event')
        await t.until(lambda: drawer.locator('section.activity button[data-events]').count(), 'the process activity')
        await drawer.evaluate('(a) => { a.scrollTop = 0; }')
    await t.hold(0.6, 'drawer-activity')
    await t.glide(drawer.locator('section.activity button', has_text='Network').first, duration=0.5)
    await t.hold(1.4)
    show = drawer.get_by_role('button', name='Show in all events')
    before = await t.build()
    await t.click(show)
    async with t.loading():
        await t.results(before)
        await asyncio.sleep(0.2)
    await t.hold(1.5, 'shown-in-all')
    await p.keyboard.press('Escape')
    async with t.loading():
        await drawer.wait_for(state='detached')
    await t.hold(0.1)


async def timeline(t: Tour) -> None:
    await t.nav('Timeline')
    async with t.loading():
        await t.ready_number('#timeline-marks', 'data-count', 'the timeline')
    await t.hold(2.4, 'timeline')


async def attack(t: Tour) -> None:
    await t.nav('ATT&CK')
    async with t.loading():
        await t.ready_number('#attack-matrix', 'data-techniques', 'the ATT&CK matrix')
    await t.hold(2.4, 'attack')


async def entities(t: Tour) -> None:
    p = t.page
    await t.nav('Entities')
    async with t.loading():
        await t.ready_number('#entities-table', 'data-rows', 'the hosts')
    await t.hold(1.0, 'entities-hosts')
    await t.click(p.get_by_role('button', name='Users', exact=True))
    async with t.loading():
        await t.until(lambda: t.is_attr(p.get_by_role('button', name='Users', exact=True), 'aria-pressed', 'true'), 'users')
        await t.until(lambda: t.first_header('#entities-table', 'Users'), 'the users column')
        await t.ready_number('#entities-table', 'data-rows', 'the users')
    await t.hold(1.5, 'entities-users')


async def stacking(t: Tour) -> None:
    p = t.page
    await t.nav('Stacking')
    async with t.loading():
        await t.ready_number('#stacking-table', 'data-rows', 'the stack')
    await t.hold(1.2, 'stacking-image')
    preset = p.locator('[aria-label="Stack"] button', has_text='ServiceName + ImagePath')
    await t.click(preset)
    async with t.loading():
        await t.until(lambda: t.is_attr(preset, 'aria-pressed', 'true'), 'the preset')
        await t.until(lambda: t.first_header('#stacking-table', 'ServiceName'), 'the service column')
        await t.ready_number('#stacking-table', 'data-rows', 'the service stack')
    await t.hold(1.8, 'stacking-services')


async def logons(t: Tour) -> None:
    p = t.page

    async def answered():
        tables = await p.locator('main.logons table').all()
        if not tables:
            return False
        for table in tables:
            if (await table.get_attribute('data-rows')) == '':
                return False
        return await p.locator('#lateral-graph').count() > 0

    await t.nav('Logons')
    async with t.loading():
        await p.locator('main.logons').wait_for()
        await t.until(answered, 'every logon table')
    await t.glide((700, 380), duration=0.5)
    await t.hold(2.2, 'logons-graph')
    sessions = p.locator('#sessions-table')
    # Sessions sit far below; jump there, then to the table's right edge, where Special privileges is.
    await sessions.evaluate('(el) => { el.closest("section").scrollIntoView({ block: "start" }); el.closest(".wrap").scrollLeft = 10000; }')
    privileges = sessions.locator('thead th', has_text='Special privileges').first
    cell = privileges.locator('input').first
    await t.hold(0.5, 'logons-sessions')
    await t.click(cell, fx=0.3)
    await t.type('*', delay=0.1)
    await asyncio.sleep(0.15)
    await p.keyboard.press('Enter')
    async with t.loading():
        await t.until(lambda: t.attr_is_number('#sessions-table', 'data-rows', lambda n: 0 < n < 87), 'the privileged sessions')
    await t.hold(2.2, 'logons-privileged')


async def processes(t: Tour) -> None:
    p = t.page
    await t.nav('Processes')
    async with t.loading():
        await t.ready_number('#process-tree', 'data-starts', 'the process tree')
    await t.hold(0.8, 'processes')
    row = p.locator('[role=treeitem]').filter(has=p.locator('.image', has_text='plink.exe')).filter(has=p.locator('.pid', has_text='2312')).first
    drawer = p.get_by_role('complementary', name='Event details')
    await t.click(row, fx=0.08)
    async with t.loading():
        await drawer.wait_for()
        await t.until(lambda: t.drawer_read(drawer), 'the process start')
    await t.hold(1.2, 'process-event')
    await p.keyboard.press('Escape')
    async with t.loading():
        await drawer.wait_for(state='detached')
    network = p.locator('main.processes header .actions button', has_text='Network').first
    await network.wait_for()
    await t.glide(network, duration=0.5)
    await t.hold(1.5, 'process-activity')


async def sql(t: Tour) -> None:
    p = t.page
    await t.nav('SQL')
    async with t.loading():
        await p.locator('#sql-editor').wait_for()
    await t.hold(0.3, 'sql')
    editor = p.locator('#sql-editor')
    await t.click(editor, fx=0.3, fy=0.3)
    await p.keyboard.press('ControlOrMeta+A')
    await p.keyboard.press('Backspace')
    await t.type('SELECT Image, count(*) AS n FROM events WHERE Image IS NOT NULL GROUP BY Image ORDER BY n DESC LIMIT 10', delay=0.024)
    await asyncio.sleep(0.25)
    run = p.get_by_role('button', name='Run', exact=True)
    await t.click(run)
    async with t.loading():
        await t.ready_number('#sql-result', 'data-rows', 'the SQL result')
    await t.hold(2.4, 'sql-result')


async def closing(t: Tour) -> None:
    p = t.page
    await t.nav('Overview')
    async with t.loading():
        await t.ready_number('#overview-tiles', 'data-events', 'the overview')
    await t.hold(0.5, 'overview-again')
    await t.click(p.get_by_role('button', name='Run details'))
    dialog = p.locator('dialog[open]')
    async with t.loading():
        await dialog.wait_for()
    await t.hold(2.2, 'run-details')
    await t.click(p.get_by_role('button', name='Close run details'))
    async with t.loading():
        await dialog.wait_for(state='detached')
    await t.glide(REST, duration=0.6)
    await t.hold(0.8, 'end')


STORYBOARD = [overview, detections, explore, event_drawer, timeline, attack, entities, stacking, logons, processes, sql, closing]


async def privacy_pass(browser, url: str) -> list[str]:
    """Visits every view and the Run details dialog, before the recording, looking for local paths."""
    context = await browser.new_context(viewport={'width': WIDTH, 'height': HEIGHT}, device_scale_factor=1,
                                        color_scheme='light', bypass_csp=True)
    page = await context.new_page()
    leaks = []
    await page.goto(url + '#/overview')
    await wait_ready(page)
    for route in ('overview', 'detections', 'explore', 'timeline', 'attack', 'entities', 'stacking', 'logons', 'processes', 'sql'):
        await page.evaluate(f'location.hash = "#/{route}"')
        await page.wait_for_timeout(2000)
        text = await page.inner_text('body')
        html = await page.content()
        for needle in forbidden_strings():
            if needle.lower() in text.lower() or needle.lower() in html.lower():
                leaks.append(f'{route}: {needle!r}')
    await page.evaluate('location.hash = "#/overview"')
    await page.get_by_role('button', name='Run details').click()
    await page.locator('dialog[open]').wait_for()
    text = await page.locator('dialog[open]').inner_text()
    for needle in forbidden_strings():
        if needle.lower() in text.lower():
            leaks.append(f'Run details: {needle!r}')
    print(f'privacy pass: 10 views and the Run details dialog checked for {forbidden_strings()}')
    await context.close()
    return leaks


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--package', required=True, type=Path, help='unpacked package directory')
    parser.add_argument('--viewer', required=True, type=Path, help='viewer build directory (app.js, app.css, index.html)')
    parser.add_argument('--out', required=True, type=Path, help='work directory for the site copy and the frames')
    parser.add_argument('--dry', action='store_true', help='no capture: a screenshot per beat in <out>/shots')
    parser.add_argument('--only', help='comma-separated beats to run after the overview (dry runs)')
    args = parser.parse_args()

    work = args.out.resolve()
    work.mkdir(parents=True, exist_ok=True)
    site = work / 'site'
    prepare_site(args.package.resolve(), args.viewer.resolve(), site)
    check_manifest(site)
    url = (site / 'index.html').as_uri()

    async with async_playwright() as p:
        browser = await p.chromium.launch()
        leaks = await privacy_pass(browser, url)
        if leaks:
            raise SystemExit('local paths in the viewer:\n' + '\n'.join(leaks))
        context = await browser.new_context(viewport={'width': WIDTH, 'height': HEIGHT}, device_scale_factor=1,
                                            color_scheme='light', bypass_csp=True)
        await context.add_init_script(CURSOR_JS)
        page = await context.new_page()
        await page.goto(url + '#/overview')
        await wait_ready(page)
        tour = Tour(page, work, args.dry)
        await page.mouse.move(*REST)
        await asyncio.sleep(0.5)
        beats = STORYBOARD
        if args.only:
            wanted = args.only.split(',')
            beats = [overview] + [b for b in STORYBOARD if b.__name__ in wanted]
        await tour.start()
        try:
            for beat in beats:
                print('beat', beat.__name__, flush=True)
                await beat(tour)
        finally:
            await tour.stop()
            await browser.close()
        if tour.leaks:
            raise SystemExit('local paths in the recording:\n' + '\n'.join(tour.leaks))
        print('privacy: no local path in any view, the Run details dialog or the recorded beats')


if __name__ == '__main__':
    asyncio.run(main())
