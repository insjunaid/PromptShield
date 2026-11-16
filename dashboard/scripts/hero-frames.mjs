// Captures frames of one real Red-Team Lab comparison for the README's hero GIF: pick the scenario,
// run it without and with the shield, screenshot the page every INTERVAL_MS until both finish.
// The GIF is assembled by scripts/make_hero_gif.py, which labels it as sped up.
//
// Needs `make demo` (or the API + `pnpm dev`) running, and Ollama for the agent.
//   PLAYWRIGHT_BROWSERS_PATH=../.playwright node scripts/hero-frames.mjs [scenario] [outDir]
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { chromium } from "@playwright/test";

const BASE = "http://127.0.0.1:5173";
const SCENARIO = process.argv[2] ?? "A02";
const OUT = resolve(process.argv[3] ?? "../data/hero_frames");
const INTERVAL_MS = 1500;
const RUN_TIMEOUT_MS = 8 * 60 * 1000;

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
let index = 0;
const frames = [];

async function frame(note) {
  const name = `frame_${String(index).padStart(4, "0")}.png`;
  await page.screenshot({ path: `${OUT}/${name}` });
  frames.push({ name, ms: Date.now(), note });
  index += 1;
}

let exitCode = 0;
try {
  await page.goto(`${BASE}/lab`);
  const toggle = page.getByRole("button", { name: /Switch to (light|dark) theme/ });
  if ((await toggle.getAttribute("aria-label")) === "Switch to dark theme") await toggle.click();
  await page.waitForFunction(() => document.documentElement.dataset.theme === "dark");
  await page.getByRole("button", { name: new RegExp(`^${SCENARIO}\\b`) }).click();
  await page.waitForTimeout(500);
  await frame("picked");
  await page.getByRole("button", { name: "Run comparison" }).click();
  const started = Date.now();
  const done = page.getByRole("button", { name: "Run comparison" });
  while (Date.now() - started < RUN_TIMEOUT_MS) {
    await page.waitForTimeout(INTERVAL_MS);
    await frame("running");
    if (await done.isVisible()) break;
  }
  await page.waitForTimeout(800);
  await frame("finished");
  const seconds = Math.round((Date.now() - started) / 1000);
  const verdicts = {};
  for (const panel of ["Without PromptShield", "With PromptShield"]) {
    const banner = page.getByRole("region", { name: panel }).getByRole("status").last();
    verdicts[panel] = (await banner.innerText()).replace(/\s+/g, " ");
  }
  writeFileSync(`${OUT}/frames.json`, JSON.stringify({ scenario: SCENARIO, seconds, verdicts, frames }, null, 2));
  console.log(`${frames.length} frames over ${seconds} s`);
  console.log(JSON.stringify(verdicts));
} catch (error) {
  console.error(error instanceof Error ? error.message.split("\n")[0] : String(error));
  exitCode = 1;
} finally {
  await browser.close();
  process.exitCode = exitCode;
}
