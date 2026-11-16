// Takes the design-review screenshots by using the dashboard like a person would: pick a scenario,
// run the comparison, wait for both verdicts, then capture Lab and Overview in both themes.
//
// Needs the API (127.0.0.1:8000) and `pnpm dev` (127.0.0.1:5173) running, and Ollama for the agent.
//   PLAYWRIGHT_BROWSERS_PATH=../.playwright node scripts/screenshots.mjs [scenario] [outDir]
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";

import { chromium } from "@playwright/test";

const BASE = "http://127.0.0.1:5173";
const SCENARIO = process.argv[2] ?? "A02";
const OUT = resolve(process.argv[3] ?? "../docs/screenshots");
const RUN_TIMEOUT_MS = 8 * 60 * 1000;

mkdirSync(OUT, { recursive: true });
const problems = [];

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
page.on("console", (message) => {
  if (message.type() === "error") problems.push(`console: ${message.text()}`);
});
page.on("pageerror", (error) => problems.push(`page error: ${error.message}`));

async function theme(wanted) {
  const toggle = page.getByRole("button", { name: /Switch to (light|dark) theme/ });
  const label = await toggle.getAttribute("aria-label");
  if (label !== `Switch to ${wanted === "dark" ? "light" : "dark"} theme`) await toggle.click();
  await page.waitForFunction((t) => document.documentElement.dataset.theme === t, wanted);
  await page.waitForTimeout(400); // let colour transitions settle
}

async function shot(name) {
  const path = `${OUT}/${name}.png`;
  await page.screenshot({ path, fullPage: true });
  console.log(`saved ${path}`);
}

try {
  await page.goto(`${BASE}/lab`);
  await theme("dark");
  await page.getByRole("button", { name: new RegExp(`^${SCENARIO}\\b`) }).click();
  await page.getByRole("button", { name: "Run comparison" }).click();
  console.log(`running ${SCENARIO} without and with the shield...`);
  const started = Date.now();
  await page.getByRole("button", { name: "Running…" }).waitFor({ timeout: 30_000 });
  await page.getByRole("button", { name: "Run comparison" }).waitFor({ timeout: RUN_TIMEOUT_MS });
  console.log(`both runs finished in ${Math.round((Date.now() - started) / 1000)} s`);
  for (const panel of ["Without PromptShield", "With PromptShield"]) {
    const banner = page.getByRole("region", { name: panel }).getByRole("status").last();
    console.log(`${panel}: ${(await banner.innerText()).replace(/\s+/g, " ")}`);
  }

  await shot("lab-dark");
  await theme("light");
  await shot("lab-light");

  // The shield-on run's replay, opened the way a person would, from its panel.
  await page.getByRole("region", { name: "With PromptShield" }).getByRole("link", { name: "Open replay" }).click();
  await page.getByRole("list", { name: "Session timeline" }).waitFor();
  await page.waitForTimeout(600);
  await shot("replay-light");
  await theme("dark");
  await shot("replay-dark");

  // Client-side navigation keeps the live store, so the Overview shows what just happened.
  await page.getByRole("link", { name: "Overview" }).first().click();
  await page.getByText("Live threat feed").waitFor();
  await page.waitForTimeout(1500);
  await shot("overview-dark");
  await theme("light");
  await shot("overview-light");
  await theme("dark");

  const blocked = page.getByText("Blocked", { exact: true }).first();
  if (await blocked.isVisible()) {
    await blocked.click();
    await page.getByRole("dialog").waitFor();
    await page.waitForTimeout(400);
    await page.screenshot({ path: `${OUT}/overview-detail-dark.png` });
    console.log(`saved ${OUT}/overview-detail-dark.png`);
  }
} catch (error) {
  problems.push(`script: ${error instanceof Error ? error.message.split("\n")[0] : String(error)}`);
} finally {
  await browser.close();
  console.log(problems.length === 0 ? "no console errors" : `problems:\n${problems.join("\n")}`);
  process.exitCode = problems.length === 0 ? 0 : 1;
}
