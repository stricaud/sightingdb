// Capture the management interface for the book.
//
// Needs a server with data in it. The galaxy in doc/docker is what these were
// taken from:
//
//     docker compose -f doc/docker/docker-compose.yml up -d
//     make screenshots
//
// Light mode is forced: the interface follows the system theme, and a dark
// screenshot on a white page looks like a mistake rather than a choice.
//
// Puppeteer is borrowed from mermaid-cli, which the book already needs, so
// there is nothing extra to install.

import { execSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { createRequire } from "node:module";

const LB = process.env.SIGHTINGDB_LB ?? "http://localhost:9999";
const NODE = process.env.SIGHTINGDB_NODE ?? "http://localhost:9991";
const KEY = process.env.SIGHTINGDB_KEY ?? "demo";
const OUT = "images";

// Resolved from mermaid-cli's own directory rather than from here: npm
// hoists its dependencies, so where puppeteer actually sits depends on the
// install, and asking from inside the package that depends on it works either
// way.
const root = execSync("npm root -g", { encoding: "utf8" }).trim();
let puppeteer;
for (const from of [
  `${root}/@mermaid-js/mermaid-cli/package.json`,
  `${root}/`,
  `${process.cwd()}/`,
]) {
  try {
    puppeteer = createRequire(from)("puppeteer");
    break;
  } catch {
    // Try the next place.
  }
}
if (!puppeteer) {
  console.error(
    "puppeteer was not found. It comes with mermaid-cli, which this book\n" +
    "already needs for its diagrams:\n" +
    "  npm install -g @mermaid-js/mermaid-cli",
  );
  process.exit(1);
}

// What to capture. `at` is where to go, `prepare` runs once the page is up.
const shots = [
  {
    name: "browse",
    at: `${NODE}/_management/`,
    wait: "#ns-rows tr",
    note: "the namespace tree",
  },
  {
    name: "values",
    at: `${NODE}/_management/misp/ips`,
    wait: "#v-rows tr",
    note: "the values in a namespace, with their tags",
  },
  {
    name: "value",
    at: `${NODE}/_management/misp/ips`,
    wait: "#v-rows tr td.v a",
    async prepare(page) {
      await page.click("#v-rows tr td.v a");
      await page.waitForSelector("#d-cards .card", { timeout: 15000 });
    },
    note: "one value, its history and its tags",
  },
  {
    name: "tags",
    at: `${NODE}/_management/`,
    wait: "#nav-tags",
    async prepare(page) {
      await page.click("#nav-tags");
      await page.waitForSelector("#t-rows tr", { timeout: 15000 });
    },
    note: "the tag vocabulary",
  },
  {
    name: "galaxy",
    at: `${LB}/_management/`,
    wait: "#nav-galaxy",
    async prepare(page) {
      await page.click("#nav-galaxy");
      await page.waitForSelector("#p-rows tr", { timeout: 20000 });
      // The graph is drawn by echarts into a canvas; give it a moment.
      await new Promise((r) => setTimeout(r, 2500));
    },
    note: "the galaxy, and the peers under it",
  },
  {
    name: "keys",
    at: `${NODE}/_management/`,
    wait: "#nav-keys",
    async prepare(page) {
      await page.click("#nav-keys");
      await page.waitForSelector("#k-rows tr", { timeout: 15000 });
    },
    note: "the keys a server accepts, and what each may reach",
  },
];

mkdirSync(OUT, { recursive: true });

const browser = await puppeteer.launch({
  headless: "new",
  args: ["--hide-scrollbars", "--force-color-profile=srgb"],
});

let failures = 0;
for (const shot of shots) {
  const page = await browser.newPage();
  try {
    await page.setViewport({ width: 1150, height: 880, deviceScaleFactor: 2 });
    await page.emulateMediaFeatures([
      { name: "prefers-color-scheme", value: "light" },
    ]);

    // Sign in before anything loads, so the login dialog never appears.
    await page.evaluateOnNewDocument((key) => {
      sessionStorage.setItem("sightingdb.key", key);
    }, KEY);

    await page.goto(shot.at, { waitUntil: "networkidle2", timeout: 30000 });
    if (shot.wait) await page.waitForSelector(shot.wait, { timeout: 20000 });
    if (shot.prepare) await shot.prepare(page);

    // Trim to what is actually drawn: a full viewport of empty page below the
    // table makes every figure in the book mostly whitespace.
    const box = await page.evaluate(() => {
      const main = document.querySelector("main");
      const height = main ? main.getBoundingClientRect().bottom : 0;
      return Math.min(Math.max(Math.ceil(height) + 24, 320), 900);
    });

    await page.screenshot({
      path: `${OUT}/ui-${shot.name}.png`,
      clip: { x: 0, y: 0, width: 1150, height: box },
    });
    console.log(`  ui-${shot.name}.png   ${shot.note}`);
  } catch (e) {
    failures += 1;
    console.error(`  ui-${shot.name}: ${e.message.split("\n")[0]}`);
  } finally {
    await page.close();
  }
}

await browser.close();
if (failures) {
  console.error(
    `\n${failures} shot(s) failed. Is the galaxy running, with data in it?\n` +
    "  docker compose -f ../docker/docker-compose.yml up -d",
  );
  process.exit(1);
}
