// Drives the Approvals, Tool Registry, Policies and Benchmarks pages against the running API and
// saves screenshots. Point the API at a copy of the policy (PROMPTSHIELD_POLICY_PATH): this
// script saves a change through the Policies page.
//   PLAYWRIGHT_BROWSERS_PATH=../.playwright node scripts/pages.mjs [outDir]
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";

import { chromium } from "@playwright/test";

const BASE = "http://127.0.0.1:5173";
const OUT = resolve(process.argv[2] ?? "../docs/screenshots");
mkdirSync(OUT, { recursive: true });
const problems = [];
const notes = [];

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
page.on("console", (message) => {
  if (message.type() === "error") problems.push(`console: ${message.text()}`);
});
page.on("pageerror", (error) => problems.push(`page error: ${error.message}`));

async function shot(name) {
  await page.waitForTimeout(500);
  await page.screenshot({ path: `${OUT}/${name}.png`, fullPage: true });
  console.log(`saved ${OUT}/${name}.png`);
}

async function go(title) {
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: title }).click();
}

try {
  await page.goto(`${BASE}/`);
  await page.evaluate(() => localStorage.setItem("promptshield.theme", "dark"));
  await page.reload();

  // Approvals: shield-on A13 runs with nobody answering. Deleting a file needs approval, but the
  // agent only sometimes tries, so up to three runs, stopping at the first approval.
  await go("Approvals");
  const card = page.getByRole("region", { name: /^Approval for / });
  // EXTERNAL_APPROVAL=1: something else (a gateway client) raises the approval; just wait for it.
  const external = process.env.EXTERNAL_APPROVAL === "1";
  let appeared = false;
  if (external) appeared = await card.first().waitFor({ timeout: 90_000 }).then(() => true, () => false);
  for (let attempt = 1; attempt <= 3 && !appeared && !external; attempt += 1) {
    const runId = await page.evaluate(async () => {
      const response = await fetch("/v1/lab/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario_id: "A13", shield: true, auto_approve: null }),
      });
      return (await response.json()).run_id;
    });
    console.log(`A13 run ${attempt}: ${runId}`);
    const deadline = Date.now() + 180_000;
    while (Date.now() < deadline && !appeared) {
      appeared = (await card.count()) > 0;
      if (appeared) break;
      const status = await page.evaluate(async (id) => (await (await fetch(`/v1/lab/runs/${id}`)).json()).status, runId);
      if (status === "finished" || status === "failed") break;
      await page.waitForTimeout(1500);
    }
  }
  try {
    await card.first().waitFor({ timeout: appeared ? 5_000 : 1 });
    notes.push(`approval: ${await card.first().getAttribute("aria-label")}`);
    const toast = page.getByText(/^Approval needed:/);
    notes.push(`toast shown: ${await toast.isVisible().catch(() => false)}`);
    const badge = await page.getByRole("navigation", { name: "Main" }).getByText("waiting").count();
    notes.push(`sidebar badge: ${badge > 0}`);
    const focused = await page.evaluate(() => document.activeElement?.textContent ?? "");
    notes.push(`focused button: ${focused}`);
    await shot("approvals-dark");
    await card.first().getByRole("button", { name: "Deny" }).click();
    await page.getByText("No approvals waiting").waitFor({ timeout: 15_000 });
    notes.push("denied through the page: queue empty again");
  } catch {
    notes.push("approval: none appeared (the agent may not have tried to delete the file this time)");
    await shot("approvals-dark");
  }

  await go("Tool Registry");
  await page.waitForTimeout(1500);
  await shot("registry-dark");

  await go("Benchmarks");
  await page.getByText("Attack success by category").waitFor({ timeout: 15_000 });
  notes.push(`benchmarks headline: ${(await page.getByLabel("Headline numbers").innerText()).split("\n").slice(0, 2).join(" ")}`);
  await shot("benchmarks-dark");

  await go("Policies");
  await page.getByRole("button", { name: "Save" }).waitFor({ timeout: 15_000 });
  await shot("policy-dark");
  const slider = page.getByLabel("Block at risk");
  const target = (await slider.inputValue()) === "0.8" ? "0.75" : "0.8";
  await slider.fill(target);
  await page.getByRole("button", { name: "Save" }).click();
  await page.getByText("Saved and live").waitFor({ timeout: 10_000 });
  const live = await page.evaluate(async () => (await (await fetch("/v1/config")).json()).block_threshold);
  notes.push(`policy saved through the page, live block threshold: ${live}`);

  await page.getByRole("button", { name: /Switch to light theme/ }).click();
  await shot("policy-light");
  await go("Benchmarks");
  await page.getByText("Attack success by category").waitFor();
  await shot("benchmarks-light");
} catch (error) {
  problems.push(`script: ${error instanceof Error ? error.message.split("\n")[0] : String(error)}`);
} finally {
  await browser.close();
  for (const note of notes) console.log(note);
  console.log(problems.length === 0 ? "no console errors" : `problems:\n${problems.join("\n")}`);
  process.exitCode = problems.length === 0 ? 0 : 1;
}
