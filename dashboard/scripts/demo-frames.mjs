// Captures the frames of the demo video from one real session: the attack page as a person sees it,
// the hidden instruction revealed by selecting the text, a live comparison run, the replay, the
// overview and the benchmarks. scripts/make_demo_video.py adds captions and title cards.
//
// Needs `make demo` running and Ollama for the agent.
//   PLAYWRIGHT_BROWSERS_PATH=../.playwright node scripts/demo-frames.mjs [outDir]
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { chromium } from "@playwright/test";

const BASE = "http://127.0.0.1:5173";
const PAGE = "http://127.0.0.1:8081/a02_article.html";
const OUT = resolve(process.argv[2] ?? "../data/demo_frames");
const INTERVAL_MS = 1500;
const RUN_TIMEOUT_MS = 8 * 60 * 1000;

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
const shots = [];
let index = 0;

// seconds: how long the frame stays on screen in the video. caption: the scene's text.
async function shot(scene, seconds, caption) {
  const file = `frame_${String(index).padStart(4, "0")}.png`;
  await page.screenshot({ path: `${OUT}/${file}` });
  shots.push({ file, scene, seconds, caption });
  index += 1;
}

let exitCode = 0;
try {
  await page.goto(PAGE);
  await page.waitForTimeout(500);
  await shot("page", 3.5, "This looks like a normal news article.");
  await page.keyboard.press("Control+A");
  await page.waitForTimeout(400);
  await shot("reveal", 4.5, "Select the text: white-on-white words tell any AI to send your secrets to an attacker.");

  await page.goto(`${BASE}/lab`);
  const toggle = page.getByRole("button", { name: /Switch to (light|dark) theme/ });
  if ((await toggle.getAttribute("aria-label")) === "Switch to dark theme") await toggle.click();
  await page.waitForFunction(() => document.documentElement.dataset.theme === "dark");
  await page.getByRole("button", { name: /^A02\b/ }).click();
  await page.waitForTimeout(500);
  await shot("lab", 3, "The Red-Team Lab runs the same attack twice: without and with PromptShield.");
  await page.getByRole("button", { name: "Run comparison" }).click();
  const started = Date.now();
  const done = page.getByRole("button", { name: "Run comparison" });
  while (Date.now() - started < RUN_TIMEOUT_MS) {
    await page.waitForTimeout(INTERVAL_MS);
    await shot("running", 0.25, "Live run on a laptop CPU, sped up.");
    if (await done.isVisible()) break;
  }
  await page.waitForTimeout(800);
  const seconds = Math.round((Date.now() - started) / 1000);
  await shot("result", 6, "Left: the agent obeys and leaks the secrets. Right: PromptShield removes the hidden text, nothing leaks, and the summary still gets written.");
  const verdicts = {};
  for (const panel of ["Without PromptShield", "With PromptShield"]) {
    const banner = page.getByRole("region", { name: panel }).getByRole("status").last();
    verdicts[panel] = (await banner.innerText()).replace(/\s+/g, " ");
  }

  await page.getByRole("region", { name: "With PromptShield" }).getByRole("link", { name: "Open replay" }).click();
  await page.getByRole("list", { name: "Session timeline" }).waitFor();
  await page.waitForTimeout(800);
  await shot("replay", 5, "Attack Replay shows what each layer saw and why it decided.");

  await page.getByRole("link", { name: "Overview" }).first().click();
  await page.getByText("Live threat feed").waitFor();
  await page.waitForTimeout(1500);
  await shot("overview", 4.5, "Every verdict streams to a live security dashboard.");

  await page.getByRole("link", { name: "Benchmarks" }).first().click();
  await page.waitForTimeout(2000);
  await shot("benchmarks", 5, "Measured: attack success 37% to 0%, every benign task still completed, 46 ms added per tool result.");

  writeFileSync(`${OUT}/frames.json`, JSON.stringify({ seconds, verdicts, shots }, null, 2));
  console.log(`${shots.length} frames; comparison took ${seconds} s`);
  console.log(JSON.stringify(verdicts));
} catch (error) {
  console.error(error instanceof Error ? error.message.split("\n")[0] : String(error));
  exitCode = 1;
} finally {
  await browser.close();
  process.exitCode = exitCode;
}
