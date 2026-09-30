"""Record the product walkthrough video (about 60 s, 1920x1080 MP4).

It starts `phish serve --demo` on a spare port, so only generated example emails appear
on screen, never real mail. Playwright drives the dashboard, the Chrome DevTools
screencast captures the frames, and ffmpeg encodes them.

    pip install -e ".[demo]"
    python -m playwright install chromium
    python scripts/record_demo.py                 # -> demo/phishing-analyzer-demo.mp4
                                                  #    + .srt and .vtt captions
    python scripts/record_demo.py --burn-captions --out demo/phishing-analyzer-demo-captioned.mp4
    python scripts/record_demo.py --theme light   # dark is the default, as in the brand
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import imageio_ffmpeg
from playwright.async_api import Page, async_playwright

from phishanalyzer.web.demo import TEMPLATES, _build

ROOT = Path(__file__).resolve().parent.parent
PORT = 8123
BASE = f"http://127.0.0.1:{PORT}"
VIEWPORT = {"width": 1280, "height": 720}
SCALE = 1.5  # 1280x720 layout rendered at 1920x1080
FPS = 30

# Fake cursor, click ripple, captions and title cards. Injected into every page; they
# remember their state in sessionStorage so they carry over page loads without a flicker.
OVERLAY_JS = r"""
(() => {
  const S = sessionStorage;
  const css = `
  #demo-cursor{position:fixed;left:0;top:0;z-index:2147483647;pointer-events:none;
    margin:-2px 0 0 -4px;transform:translate(var(--x,-60px),var(--y,-60px))}
  #demo-cursor svg{display:block;filter:drop-shadow(0 2px 3px rgba(0,0,0,.35))}
  .demo-ripple{position:fixed;width:40px;height:40px;margin:-20px 0 0 -20px;border-radius:50%;
    background:rgba(20,116,111,.45);pointer-events:none;z-index:2147483646;
    animation:demo-ripple .55s cubic-bezier(.16,1,.3,1) forwards}
  @keyframes demo-ripple{from{transform:scale(.3);opacity:1}to{transform:scale(1.7);opacity:0}}
  /* Subtitles in the ebertero-brand style: a slim dark pill with a hairline border, Geist
     at a medium weight. Fixed dark colors so they read the same over
     the light report page as over the dark dashboard. */
  #demo-caption{position:fixed;left:50%;bottom:28px;max-width:92%;padding:7px 18px;
    white-space:nowrap;border-radius:999px;
    background:rgba(10,10,10,.8);border:1px solid rgba(255,255,255,.12);color:#ededed;
    font:500 16px/1.4 "Geist",ui-sans-serif,system-ui,sans-serif;letter-spacing:-.01em;
    transform:translate(-50%,8px);opacity:0;pointer-events:none;z-index:2147483645;
    transition:opacity .45s cubic-bezier(.16,1,.3,1),transform .45s cubic-bezier(.16,1,.3,1)}
  #demo-caption.on{opacity:1;transform:translate(-50%,0)}
  #demo-card{position:fixed;inset:0;display:flex;flex-direction:column;align-items:center;
    justify-content:center;gap:14px;text-align:center;z-index:2147483644;pointer-events:none;
    background:color-mix(in srgb,var(--background,#0a0a0a) 94%,transparent);
    color:var(--foreground,#ededed);font-family:"Geist",ui-sans-serif,system-ui,sans-serif;
    opacity:0;transition:opacity .6s cubic-bezier(.16,1,.3,1)}
  #demo-card.on{opacity:1}
  #demo-card svg{width:64px;height:64px;color:var(--brand,#14746f)}
  #demo-card h1{font-size:56px;line-height:1.1;margin:8px 0 0;font-weight:600;letter-spacing:-.03em}
  #demo-card p{font-size:22px;margin:0;color:var(--muted,#a1a1aa)}
  .conn{visibility:hidden}  /* "Not watching a mailbox": true of the demo only */
  `;
  const SHIELD = '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 2 4 5v6c0 '
    + '5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Zm0 5a1 1 0 0 1 1 1v4a1 1 0 1 1-2 0V8a1 1 0 0 1 '
    + '1-1Zm0 8.2a1.2 1.2 0 1 1 0 2.4 1.2 1.2 0 0 1 0-2.4Z"/></svg>';
  function el(id) { return document.getElementById(id); }
  function place(x, y) {
    const c = el('demo-cursor');
    if (c) { c.style.setProperty('--x', x + 'px'); c.style.setProperty('--y', y + 'px'); }
  }
  function showNow(node) {
    node.style.transition = 'none'; node.classList.add('on');
    void node.offsetWidth; node.style.transition = '';
  }
  function mount() {
    const style = document.createElement('style');
    style.textContent = css;
    document.head.appendChild(style);
    const cursor = document.createElement('div');
    cursor.id = 'demo-cursor';
    cursor.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24">'
      + '<path d="M4 2l16 11.6-7.1 1.1 4.3 7.2-3 1.7-4.2-7.3L4 21.4z" fill="#111" '
      + 'stroke="#fff" stroke-width="1.6" stroke-linejoin="round"/></svg>';
    document.body.appendChild(cursor);
    const pos = JSON.parse(S.getItem('demo-pos') || 'null');
    if (pos) place(pos[0], pos[1]);
    const cap = document.createElement('div');
    cap.id = 'demo-caption';
    document.body.appendChild(cap);
    const saved = S.getItem('demo-caption');
    if (saved) { cap.textContent = saved; showNow(cap); }
  }
  window.addEventListener('mousemove', e => {
    place(e.clientX, e.clientY);
    S.setItem('demo-pos', JSON.stringify([e.clientX, e.clientY]));
  }, true);
  window.addEventListener('mousedown', e => {
    const r = document.createElement('div');
    r.className = 'demo-ripple';
    r.style.left = e.clientX + 'px'; r.style.top = e.clientY + 'px';
    document.body.appendChild(r);
    setTimeout(() => r.remove(), 700);
  }, true);
  window.__demoCaption = async (text) => {
    const cap = el('demo-caption');
    S.setItem('demo-caption', text);
    if (cap.classList.contains('on')) {
      cap.classList.remove('on');
      await new Promise(r => setTimeout(r, 350));
    }
    cap.textContent = text;
    if (text) cap.classList.add('on');
  };
  window.__demoCard = (title, sub, instant) => {
    let card = el('demo-card');
    if (!title) { if (card) card.classList.remove('on'); return; }
    if (!card) {
      card = document.createElement('div');
      card.id = 'demo-card';
      document.body.appendChild(card);
    }
    card.innerHTML = SHIELD + '<h1></h1><p></p>';
    card.querySelector('h1').textContent = title;
    card.querySelector('p').textContent = sub;
    if (instant) showNow(card); else { void card.offsetWidth; card.classList.add('on'); }
  };
  window.__demoScroll = (dy, ms) => new Promise(done => {
    const start = scrollY, end = Math.max(0, Math.min(start + dy,
      document.documentElement.scrollHeight - innerHeight));
    const t0 = performance.now();
    (function step(now) {
      const t = Math.min(1, (now - t0) / ms), e = t < .5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2;
      scrollTo(0, start + (end - start) * e);
      if (t < 1) requestAnimationFrame(step); else done();
    })(t0);
  });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount);
  else mount();
})();
"""


class Recorder:
    """Collects Chrome DevTools screencast frames with their capture times."""

    def __init__(self, cdp):
        self.cdp = cdp
        self.frames: list[tuple[float, bytes]] = []
        self._acks: set[asyncio.Future] = set()
        cdp.on("Page.screencastFrame", self._on_frame)

    def _on_frame(self, params: dict) -> None:
        self.frames.append((params["metadata"]["timestamp"], base64.b64decode(params["data"])))
        ack = asyncio.ensure_future(
            self.cdp.send("Page.screencastFrameAck", {"sessionId": params["sessionId"]})
        )
        self._acks.add(ack)
        ack.add_done_callback(self._acks.discard)

    async def start(self) -> None:
        await self.cdp.send(
            "Page.startScreencast",
            {
                "format": "jpeg",
                "quality": 95,
                "maxWidth": int(VIEWPORT["width"] * SCALE),
                "maxHeight": int(VIEWPORT["height"] * SCALE),
            },
        )

    async def stop(self) -> None:
        await self.cdp.send("Page.stopScreencast")

    def encode(self, out: Path, tail: float = 0.5) -> float:
        """Write the frames as an H.264 MP4, holding each one until the next arrived."""
        work = Path(tempfile.mkdtemp(prefix="phish-frames-"))
        try:
            lines = []
            for i, (ts, data) in enumerate(self.frames):
                name = f"f{i:05d}.jpg"
                (work / name).write_bytes(data)
                nxt = self.frames[i + 1][0] if i + 1 < len(self.frames) else ts + tail
                lines += [f"file '{name}'", f"duration {max(nxt - ts, 0.001):.4f}"]
            lines.append(lines[-2])  # the concat demuxer ignores the last entry's duration
            (work / "frames.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
            out.parent.mkdir(parents=True, exist_ok=True)
            w, h = int(VIEWPORT["width"] * SCALE), int(VIEWPORT["height"] * SCALE)
            subprocess.run(
                [
                    imageio_ffmpeg.get_ffmpeg_exe(),
                    "-y",
                    "-loglevel",
                    "error",
                    "-f",
                    "concat",
                    "-safe",
                    "0",
                    "-i",
                    str(work / "frames.txt"),
                    "-vf",
                    f"fps={FPS},scale={w}:{h}:flags=lanczos:out_range=tv,format=yuv420p",
                    "-color_range",
                    "tv",
                    "-colorspace",
                    "bt709",
                    "-color_primaries",
                    "bt709",
                    "-color_trc",
                    "bt709",
                    "-c:v",
                    "libx264",
                    "-preset",
                    "slow",
                    "-crf",
                    "18",
                    "-movflags",
                    "+faststart",
                    str(out),
                ],
                check=True,
            )
        finally:
            shutil.rmtree(work, ignore_errors=True)
        return self.frames[-1][0] - self.frames[0][0] + tail


class Director:
    """Moves the (visible) cursor, clicks, scrolls and captions at a watchable pace."""

    def __init__(self, page: Page, burn_captions: bool):
        self.page = page
        self.burn_captions = burn_captions
        self.captions: list[tuple[float, str]] = []  # (wall-clock time, text; "" hides)
        self.x, self.y = VIEWPORT["width"] * 0.55, VIEWPORT["height"] * 0.14

    async def wait(self, seconds: float) -> None:
        await asyncio.sleep(seconds)

    async def glide(self, x: float, y: float, duration: float = 0.7) -> None:
        x0, y0 = self.x, self.y
        start = time.perf_counter()
        while True:
            t = min(1.0, (time.perf_counter() - start) / duration)
            e = t * t * (3 - 2 * t)
            await self.page.mouse.move(x0 + (x - x0) * e, y0 + (y - y0) * e)
            if t >= 1:
                break
            await asyncio.sleep(1 / 60)
        self.x, self.y = x, y

    async def point(self, selector: str, duration: float = 0.7, fx: float = 0.5) -> None:
        box = await self.page.locator(selector).first.bounding_box()
        # Off screen, or hidden behind the caption: bring it into view first.
        if box["y"] < 70 or box["y"] + box["height"] > VIEWPORT["height"] - 110:
            await self.scroll(box["y"] - VIEWPORT["height"] * 0.4, 0.9)
            await self.wait(0.2)
            box = await self.page.locator(selector).first.bounding_box()
        await self.glide(box["x"] + box["width"] * fx, box["y"] + box["height"] / 2, duration)

    async def click(self, selector: str, duration: float = 0.7, fx: float = 0.5) -> None:
        await self.point(selector, duration, fx)
        await self.wait(0.2)
        async with self.page.expect_navigation():
            await self.page.mouse.down()
            await asyncio.sleep(0.08)
            await self.page.mouse.up()
        await self.page.wait_for_load_state("networkidle")

    async def caption(self, text: str) -> None:
        if self.burn_captions:
            await self.page.evaluate("t => window.__demoCaption(t)", text)
        elif self.captions and self.captions[-1][1]:
            await self.wait(0.35)  # the fade between captions: same pacing either way
        self.captions.append((time.time(), text))

    async def card(self, title: str = "", sub: str = "", instant: bool = False) -> None:
        await self.page.evaluate("a => window.__demoCard(...a)", [title, sub, instant])

    async def scroll(self, dy: float, duration: float = 1.2) -> None:
        await self.page.evaluate("a => window.__demoScroll(...a)", [dy, duration * 1000])


def pick_email() -> int:
    """The Critical demo email with a report and the most findings: the best showcase."""
    html = httpx.get(f"{BASE}/emails", params={"level": "critical"}).text
    best, best_findings = None, -1
    for email_id in dict.fromkeys(re.findall(r'href="/emails/(\d+)"', html)):
        page = httpx.get(f"{BASE}/emails/{email_id}").text
        if "Open report" not in page:
            continue
        why = page.split("<h2>Why</h2>", 1)[1].split("</table>", 1)[0]
        findings = why.count("<tr>") - 1
        if findings > best_findings:
            best, best_findings = int(email_id), findings
    if best is None:
        raise SystemExit("The demo data has no Critical email with a report")
    return best


def upload_sample() -> Path:
    """A generated .eml (the fake invoice with a disguised .exe) to show the upload page."""
    template = next(t for t in TEMPLATES if t.attachments and t.subject == "Outstanding invoice")
    path = Path(tempfile.mkdtemp(prefix="phish-upload-")) / "Outstanding invoice.eml"
    path.write_bytes(_build(template, 142))
    return path


async def walkthrough(d: Director, email_id: int, sample: Path) -> None:
    page = d.page

    # 1. Overview, under the title card (about 16 s)
    await d.wait(2.6)
    await d.card()
    await d.wait(0.6)
    await d.caption("Every new email is scanned, scored 0\u2013100 and labelled in Gmail")
    await d.wait(1.2)
    columns = page.locator(".chart-wrap .col")
    n = await columns.count()
    for i in (n - 6, n - 4, n - 2):
        box = await columns.nth(i).bounding_box()
        await d.glide(box["x"] + box["width"] / 2, box["y"] + box["height"] * 0.7, 0.6)
        await d.wait(0.9)
    await d.glide(d.x, d.y - 330, 0.7)  # off the chart, towards the tiles
    await d.caption("Threats stand out at a glance")
    await d.scroll(430, 1.4)
    await d.wait(1.6)
    await d.scroll(-430, 1.0)
    await d.wait(0.3)
    await d.click('a.tile[href="/emails?level=critical"]', 0.8)

    # 2. Email list (about 4 s)
    await d.caption("Filter and search everything the scanner has seen")
    await d.wait(1.8)
    await d.click(f'a.subject[href="/emails/{email_id}"]', 0.9, fx=0.2)

    # 3. Why it scored what it did (about 10 s)
    await d.caption("Every point is explained: spoofed sender, fake domain, disguised link")
    await d.scroll(180, 0.9)
    rows = page.locator("section.card:has(h2:text-is('Why')) tbody tr")
    for i in range(min(await rows.count(), 5)):
        box = await rows.nth(i).bounding_box()
        await d.glide(box["x"] + 150, box["y"] + box["height"] / 2, 0.55)
        await d.wait(0.65)
    await d.wait(0.6)
    open_report = 'a.btn.primary[href^="/reports/"]'
    await page.locator(open_report).evaluate("a => a.removeAttribute('target')")
    await d.caption("Critical emails get an incident report automatically")
    await d.wait(0.5)
    await d.click(open_report, 0.8)

    # 4. The report (about 8 s)
    await d.caption("HTML and PDF reports, with every indicator defanged")
    await d.wait(1.6)
    await d.scroll(520, 2.6)
    await d.wait(0.9)
    await d.scroll(700, 2.4)
    await d.wait(0.6)
    await d.caption("")
    await page.go_back()
    await page.wait_for_load_state("networkidle")

    # 5. Sandbox approvals (about 7 s)
    await d.click('nav.main a[href="/sandbox"]', 0.8)
    await d.caption("Unknown attachments go to the sandbox only with your approval")
    await d.wait(1.0)
    await d.point("td .actions button:text-is('Upload')", 0.9)
    await d.wait(2.0)

    # 6. On-demand upload (about 10 s)
    await d.click('nav.main a[href="/upload"]', 0.8)
    await d.caption("Or drop in any saved .eml to check it on demand")
    await d.point('input[type="file"]', 0.8, fx=0.12)
    await d.wait(0.4)
    await page.set_input_files('input[type="file"]', str(sample))
    await d.wait(1.0)
    await d.click('button:text-is("Analyse")', 0.8)
    await d.caption("A verdict in seconds, with the reasons")
    await d.wait(3.0)
    await d.caption("")
    await d.card("Phishing Email Analyzer", "Runs on your own computer \u00b7 Works with Gmail")
    await d.wait(2.5)


def start_server() -> subprocess.Popen:
    phish = Path(sys.executable).with_name("phish.exe" if sys.platform == "win32" else "phish")
    proc = subprocess.Popen(
        [str(phish), "serve", "--demo", "--port", str(PORT)],
        cwd=tempfile.mkdtemp(prefix="phish-demo-cwd-"),  # no config.yaml or .env from here
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(120):
        try:
            if httpx.get(f"{BASE}/healthz").status_code == 200:
                return proc
        except httpx.TransportError:
            pass
        if proc.poll() is not None:
            raise SystemExit("phish serve --demo exited early")
        time.sleep(0.5)
    proc.terminate()
    raise SystemExit("The demo dashboard did not start")


def _stamp(seconds: float, sep: str) -> str:
    ms = round(max(seconds, 0) * 1000)
    h, m, sec = ms // 3_600_000, ms // 60_000 % 60, ms // 1000 % 60
    return f"{h:02d}:{m:02d}:{sec:02d}{sep}{ms % 1000:03d}"


def write_subtitles(out: Path, captions: list[tuple[float, str]], start: float, end: float):
    """Write the captions as SubRip (.srt) and WebVTT (.vtt, for an HTML <track>)."""
    cues = []
    for i, (at, text) in enumerate(captions):
        until = captions[i + 1][0] if i + 1 < len(captions) else start + end
        if text:
            cues.append((at - start, until - start, text))
    srt, vtt = [], ["WEBVTT", ""]
    for n, (a, b, text) in enumerate(cues, 1):
        srt += [str(n), f"{_stamp(a, ',')} --> {_stamp(b, ',')}", text, ""]
        vtt += [f"{_stamp(a, '.')} --> {_stamp(b, '.')}", text, ""]
    out.with_suffix(".srt").write_text("\n".join(srt), encoding="utf-8")
    out.with_suffix(".vtt").write_text("\n".join(vtt), encoding="utf-8")


async def record(out: Path, theme: str, burn_captions: bool) -> None:
    server = start_server()
    try:
        email_id = pick_email()
        sample = upload_sample()
        async with async_playwright() as pw:
            browser = await pw.chromium.launch()
            context = await browser.new_context(
                viewport=VIEWPORT,
                device_scale_factor=SCALE,
                color_scheme=theme,
                bypass_csp=True,  # lets the overlay script run on the dashboard's strict CSP
            )
            await context.add_init_script(OVERLAY_JS)
            page = await context.new_page()
            await page.goto(BASE + "/")
            await page.wait_for_load_state("networkidle")
            director = Director(page, burn_captions)
            await page.mouse.move(director.x, director.y)
            recorder = Recorder(await context.new_cdp_session(page))
            await director.card(
                "Phishing Email Analyzer",
                "Every email in your inbox, scored and explained",
                instant=True,
            )
            await recorder.start()
            await walkthrough(director, email_id, sample)
            await recorder.stop()
            await browser.close()
        length = recorder.encode(out)
        print(f"Wrote {out} ({length:.1f} s, {len(recorder.frames)} frames)")
        if not burn_captions:
            write_subtitles(out, director.captions, recorder.frames[0][0], length)
            print(f"Wrote {out.with_suffix('.srt')} and {out.with_suffix('.vtt')}")
    finally:
        server.terminate()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "demo" / "phishing-analyzer-demo.mp4")
    parser.add_argument("--theme", choices=["light", "dark"], default="dark")
    parser.add_argument(
        "--burn-captions",
        action="store_true",
        help="Draw the captions into the video instead of writing .srt/.vtt files beside it",
    )
    args = parser.parse_args()
    asyncio.run(record(args.out, args.theme, args.burn_captions))


if __name__ == "__main__":
    main()
