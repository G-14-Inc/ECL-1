/**
 * The browser verifier (web/verifier/index.html), opened from file:// in Chromium through
 * playwright-core. Chromium comes from PLAYWRIGHT_BROWSERS_PATH; nothing is downloaded.
 *
 * Every test records each request the browser makes and refuses any request that is not one of
 * the page's own two files; a test fails on any other request, on a content-security-policy
 * violation, on a console error and on an uncaught exception.
 */

import assert from "node:assert/strict";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { pathToFileURL } from "node:url";
import { chromium } from "playwright-core";
import type { Browser, BrowserContext, Page } from "playwright-core";
import { json, repoRoot } from "../unit/helpers.js";
import type { JsonObject } from "../../src/index.js";

const ROOT = repoRoot();
const PAGE = pathToFileURL(join(ROOT, "web/verifier/index.html")).href;
const SCRIPT = pathToFileURL(join(ROOT, "web/verifier/verifier.js")).href;
const SUITE = "conformance/suites/evidence-bundle";
const PACKAGES = "conformance/suites/offline-package";
const NOW = "2026-10-01T00:00:00Z";
const VERDICT_TITLES: Readonly<Record<string, string>> = {
  verified: "Verified",
  invalid: "Invalid",
  incomplete: "Incomplete",
  "current-trust-failed": "Current trust failed",
};

interface Session {
  readonly context: BrowserContext;
  readonly page: Page;
  readonly requests: string[];
  readonly problems: string[];
}

let browser: Browser;

before(async () => {
  try {
    browser = await chromium.launch();
  } catch (error) {
    throw new Error(
      "Chromium could not be started. Set PLAYWRIGHT_BROWSERS_PATH to a directory holding the Chromium build that playwright-core expects " +
        `(revision 1194 for playwright-core 1.56.1). ${error instanceof Error ? error.message : String(error)}`,
    );
  }
});

after(async () => {
  await browser.close();
});

async function open(options: { width?: number; colorScheme?: "light" | "dark" } = {}): Promise<Session> {
  const context = await browser.newContext({
    viewport: { width: options.width ?? 1000, height: 800 },
    colorScheme: options.colorScheme ?? "light",
    serviceWorkers: "block",
  });
  const requests: string[] = [];
  const problems: string[] = [];
  context.on("request", (request) => {
    requests.push(request.url());
  });
  await context.route("**/*", async (route) => {
    const url = route.request().url();
    if (url === PAGE || url === SCRIPT) {
      await route.continue();
    } else {
      problems.push(`request refused: ${url}`);
      await route.abort();
    }
  });
  await context.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (event) => {
      console.error(`content security policy violation: ${event.violatedDirective} ${event.blockedURI}`);
    });
  });
  const page = await context.newPage();
  page.on("console", (message) => {
    if (message.type() === "error" || message.type() === "warning") {
      problems.push(`console ${message.type()}: ${message.text()}`);
    }
  });
  page.on("pageerror", (error) => problems.push(`page error: ${error.message}`));
  page.on("websocket", (socket) => problems.push(`websocket: ${socket.url()}`));
  await page.goto(PAGE);
  return { context, page, requests, problems };
}

/** Close the session after checking that only the page and its script were requested. */
async function close(session: Session): Promise<void> {
  await session.context.close();
  assert.deepEqual(session.problems, []);
  assert.deepEqual([...new Set(session.requests)].sort(), [PAGE, SCRIPT].sort());
}

interface Run {
  readonly bundle: string;
  readonly policy: string;
  readonly history?: readonly string[];
  readonly now?: string;
  readonly trustedTime?: boolean;
  readonly accept?: boolean;
  readonly register?: string;
}

async function verify(page: Page, run: Run): Promise<void> {
  await page.setInputFiles("#bundle", join(ROOT, run.bundle));
  await page.setInputFiles("#policy", join(ROOT, run.policy));
  await page.setInputFiles("#history", (run.history ?? []).map((path) => join(ROOT, path)));
  await page.setInputFiles("#register", run.register === undefined ? [] : [join(ROOT, run.register)]);
  await page.fill("#now", run.now ?? NOW);
  await page.setChecked("#trusted-time", run.trustedTime === true);
  await page.setChecked("#accept", run.accept === true);
  await page.click("#verify");
  await page.waitForFunction(() => {
    const text = document.getElementById("status")?.textContent ?? "";
    return text.startsWith("Verification finished") || document.getElementById("problem")?.hidden === false;
  });
}

function vectors(suite = SUITE): JsonObject[] {
  return json(`${suite}/manifest.json`)["vectors"] as JsonObject[];
}

function runOf(vector: JsonObject): Run {
  return {
    bundle: vector["path"] as string,
    policy: vector["trust_policy_path"] as string,
    history: vector["trust_policy_history_paths"] as string[],
    now: vector["evaluated_at"] as string,
    trustedTime: vector["require_trusted_time"] === true,
    // EBMP2-060: a vector that accepts a current trust failure is verified with that acceptance.
    accept: vector["accept_current_trust_failure"] === true,
    ...(typeof vector["register_path"] === "string" ? { register: vector["register_path"] } : {}),
  };
}

function vectorById(id: string): JsonObject {
  return vectors().find((item) => item["id"] === id) as JsonObject;
}

test("the page loads from file:// with its own two files only, under a strict content security policy", async () => {
  const session = await open();
  const { page } = session;
  const policy = await page.getAttribute('meta[http-equiv="Content-Security-Policy"]', "content");
  assert.ok(policy !== null);
  for (const directive of ["default-src 'none'", "script-src 'self'", "connect-src 'none'", "img-src 'none'", "form-action 'none'", "base-uri 'none'", "require-trusted-types-for 'script'"]) {
    assert.ok(policy.includes(directive), directive);
  }
  assert.match(policy, /style-src 'sha256-[A-Za-z0-9+/]{43}='/);
  const references = await page.evaluate(() => ({
    scripts: Array.from(document.scripts, (script) => script.getAttribute("src")),
    links: document.querySelectorAll("link, img, iframe, object, embed, audio, video, source, base").length,
    inline: Array.from(document.querySelectorAll("[style], [onclick], [onload], [onerror], [onsubmit]")).length,
  }));
  assert.deepEqual(references, { scripts: ["verifier.js"], links: 0, inline: 0 });
  assert.equal(await page.isEnabled("#verify"), true);
  assert.equal(await page.isHidden("#script-state"), true);
  await close(session);
});

test("the content security policy blocks a connection that a script attempts", async () => {
  const session = await open();
  // The page reports the violation in a task of its own, which can run after fetch() has
  // rejected, and its console message then crosses to this process: wait for it before closing.
  const reported = session.page.waitForEvent("console", {
    predicate: (message) => message.type() === "error" && message.text().startsWith("content security policy violation: connect-src"),
    timeout: 10_000,
  });
  const outcome = await session.page.evaluate(async () => {
    try {
      await fetch("https://example.invalid/");
      return "sent";
    } catch {
      return "blocked";
    }
  });
  assert.equal(outcome, "blocked");
  await reported;
  await session.context.close();
  // The refused connection never became a request.
  assert.deepEqual([...new Set(session.requests)].sort(), [PAGE, SCRIPT].sort());
  assert.ok(session.problems.some((problem) => problem.includes("content security policy violation: connect-src")));
  assert.ok(!session.problems.some((problem) => problem.startsWith("request refused")));
});

test("every evidence-bundle vector: the page shows the reference verdict and the expected identifiers", async () => {
  const session = await open();
  const { page } = session;
  const verdicts = new Map<string, number>();
  for (const vector of vectors()) {
    await verify(page, runOf(vector));
    const expected = vector["expected_verdict"] as string;
    assert.equal(await page.getAttribute("#verdict", "data-verdict"), expected, vector["id"] as string);
    assert.equal(await page.innerText("#verdict"), `Verdict: ${VERDICT_TITLES[expected]}`, vector["id"] as string);
    const text = await page.innerText("#result");
    const identifiers = [vector["expected_primary_id"], ...((vector["expected_secondary_ids"] as string[] | undefined) ?? [])].filter((item) => typeof item === "string");
    for (const identifier of identifiers) {
      assert.ok(text.includes(identifier as string), `${vector["id"] as string}: ${identifier as string}`);
    }
    // A verified row that accepts a current trust failure states the acceptance with the verdict.
    if (vector["accept_current_trust_failure"] === true && expected === "verified") {
      assert.match(text, /You chose to accept a current trust failure for a signer or other trust dependency in this run\./, vector["id"] as string);
    }
    verdicts.set(expected, (verdicts.get(expected) ?? 0) + 1);
  }
  assert.deepEqual([...verdicts.keys()].sort(), ["current-trust-failed", "incomplete", "invalid", "verified"]);
  await close(session);
});

test("every offline-package vector: the page verifies the package and shows the reference verdict and primary finding", async () => {
  const session = await open();
  const { page } = session;
  const verdicts = new Map<string, number>();
  for (const vector of vectors(PACKAGES)) {
    await verify(page, runOf(vector));
    const expected = vector["expected_verdict"] as string;
    assert.equal(await page.getAttribute("#verdict", "data-verdict"), expected, vector["id"] as string);
    const text = await page.innerText("#result");
    assert.match(text, /An offline package of [0-9]+ bytes/, vector["id"] as string);
    const primary = vector["expected_primary_id"];
    if (typeof primary === "string") {
      assert.ok(text.includes(primary), `${vector["id"] as string}: ${primary}`);
    }
    verdicts.set(expected, (verdicts.get(expected) ?? 0) + 1);
  }
  assert.deepEqual([...verdicts.keys()].sort(), ["current-trust-failed", "incomplete", "invalid", "verified"]);
  // A package refused before its bundle is verified says so, and lists no envelope.
  await verify(page, { bundle: `${PACKAGES}/package-invalid-name-outside-portable-set.zip`, policy: `${PACKAGES}/trust-policy.json` });
  const refused = await page.innerText("#result");
  assert.match(refused, /Its evidence bundle could not be evaluated\./);
  assert.match(refused, /The evidence bundle was not verified\./);
  assert.match(refused, /ecl\.error\.semantic-invalid\.v1/);
  // A verified package shows its bundle's envelopes, as a bundle would.
  await verify(page, { bundle: `${PACKAGES}/package-valid-verified.zip`, policy: `${PACKAGES}/trust-policy.json` });
  assert.match(await page.innerText("#result"), /The result includes the checks performed on its evidence bundle and any package findings, listed first\./);
  assert.ok((await page.locator("ol.items > li").count()) > 0);
  await close(session);
});

test("EBMP2-076: what the verdict does not establish is shown beside it, then what the verifier checked", async () => {
  const session = await open();
  const { page } = session;
  await verify(page, runOf(vectorById("bundle-valid-prerelease-obligations-discharged")));
  assert.equal(await page.getAttribute("#verdict", "data-verdict"), "verified");
  // The list follows the verdict and its explanation, before anything else in the result.
  const order = await page.evaluate(() => Array.from(document.querySelectorAll("#result-body > *"), (node) => node.id).slice(0, 5));
  assert.deepEqual(order, ["verdict", "", "not-established-lead", "not-established", "established-lead"]);
  const missing = await page.innerText("#not-established");
  for (const item of ["prerelease-obligations-met", "recorded-times-true", "effects-occurred", "deployment-assessed", "statements-true"]) {
    assert.ok(missing.includes(item), item);
  }
  assert.match(missing, /That each recorded time is the true time of its event/);
  const held = await page.innerText("#established");
  assert.ok(held.includes("prerelease-obligations-discharge-recorded"));
  assert.ok(!held.includes("recorded-times-true"));
  await verify(page, runOf(vectorById("bundle-invalid-prerelease-approval-unmet")));
  assert.equal(await page.getAttribute("#verdict", "data-verdict"), "invalid");
  assert.match(await page.innerText("#not-established"), /prerelease-obligations-discharge-recorded/);
  assert.equal(await page.locator("#established").count(), 0);
  assert.match(await page.innerText("#established-lead"), /It establishes nothing that the verifier checked/);
  assert.match(await page.innerText("#result"), /ecl\.rule\.prerelease-obligations-discharged\.v1/);
  // An item a stated reason keeps out of `established` shows the reason, the proofs the
  // bundle carries are reported verified, and a late answer from the server is information.
  await verify(page, runOf(vectorById("bundle-valid-prerelease-proofs-not-carried")));
  assert.equal(await page.getAttribute("#verdict", "data-verdict"), "verified");
  assert.match(await page.innerText("#not-established"), /prerelease-obligations-proofs-verified[^]*Reason: proof-not-ecl-object/);
  await verify(page, runOf(vectorById("bundle-valid-prerelease-proofs-carried")));
  assert.match(await page.innerText("#established"), /prerelease-obligations-proofs-verified/);
  await verify(page, runOf(vectorById("bundle-valid-discharge-witness-source-not-named")));
  assert.match(await page.innerText("#not-established"), /prerelease-obligations-proofs-verified[^]*Reason: issuer-not-named/);
  assert.equal(await page.locator("#completion-after-window").count(), 0);
  await verify(page, runOf(vectorById("bundle-valid-cancelled-after-consumption")));
  assert.match(await page.innerText("#not-established"), /release-within-authority[^]*Reason: no-release-recorded/);
  await verify(page, runOf(vectorById("bundle-valid-mcp-forward-completed-after-valid-until")));
  assert.equal(await page.getAttribute("#verdict", "data-verdict"), "verified");
  assert.match(await page.innerText("#completion-after-window"), /arrived after the authorization's window/);
  await close(session);
});

test("a current trust failure is explained, and accepting it is stated with the verdict", async () => {
  const session = await open();
  const { page } = session;
  const vector = vectors().find((item) => item["id"] === "bundle-current-trust-failed-revoked-after-use") as JsonObject;
  await verify(page, runOf(vector));
  const verdict = await page.innerText("#result");
  assert.match(verdict, /Current trust failed/);
  assert.match(verdict, /The checks on the original records passed/);
  await page.locator("#result summary").filter({ hasText: "Report as JSON" }).click();
  const json = JSON.parse(await page.locator("#result details pre code").innerText());
  assert.equal(json.primary, "ecl.error.revoked.v1");
  assert.match(verdict, /At the evaluation time\s+Not valid: Key revoked\./);
  assert.match(verdict, /When it was signed\s+Valid\./);
  await verify(page, { ...runOf(vector), accept: true });
  assert.equal(await page.getAttribute("#verdict", "data-verdict"), "verified");
  assert.match(await page.innerText("#result"), /You chose to accept a current trust failure/);
  await close(session);
});

test("the decision basis is required of every decision response, and the register is shown", async () => {
  const session = await open();
  const { page } = session;
  const plain = vectorById("bundle-invalid-missing-decision-basis");
  await verify(page, runOf(plain));
  assert.equal(await page.getAttribute("#verdict", "data-verdict"), "invalid");
  assert.match(await page.innerText("#result"), /ecl\.rule\.decision-basis-required\.v1/);
  // Without a register, the page says what it did not check (DCMP2-053).
  assert.match(
    await page.innerText("#result"),
    /Consequential Action Register\s+None supplied, so the declared classes and inputs of each decision basis were not checked against a register\./,
  );
  const matched = vectorById("bundle-valid-decision-basis-matches-register");
  await verify(page, runOf(matched));
  assert.equal(await page.getAttribute("#verdict", "data-verdict"), "verified");
  let text = await page.innerText("#result");
  assert.match(text, /Consequential Action Register\s+urn:/);
  await verify(page, { ...runOf(matched), register: "conformance/suites/evidence-bundle/register-version-2.json" });
  assert.equal(await page.getAttribute("#verdict", "data-verdict"), "invalid");
  text = await page.innerText("#result");
  assert.match(text, /ecl\.rule\.decision-basis-matches-register\.v1/);
  await verify(page, { ...runOf(matched), register: `${SUITE}/trust-policy.json` });
  assert.match(await page.getByRole("alert").innerText(), /malformed register/);
  assert.match(await page.getByRole("alert").innerText(), /ecl\.error\.schema-invalid\.v1/);
  assert.equal(await page.isHidden("#result"), true);
  // A register that declares an action class twice is refused before any check (DCMP2-053).
  await verify(page, { ...runOf(matched), register: "conformance/suites/document-coverage/register-invalid-action-class-declared-twice.json" });
  assert.match(await page.getByRole("alert").innerText(), /malformed register: the register breaks ecl\.rule\.register-declarations-consistent\.v1/);
  assert.equal(await page.isHidden("#result"), true);
  await close(session);
});

test("keyboard: every control in order with a visible focus indicator, and submission without a pointer", async () => {
  const session = await open();
  const { page } = session;
  await page.setInputFiles("#bundle", join(ROOT, `${SUITE}/bundle-valid-succeeded.json`));
  await page.setInputFiles("#policy", join(ROOT, `${SUITE}/trust-policy.json`));
  await page.fill("#now", NOW);
  await page.click("h1");
  const order: string[] = [];
  for (let step = 0; step < 8; step += 1) {
    await page.keyboard.press("Tab");
    const focus = await page.evaluate(() => {
      const element = document.activeElement as HTMLElement;
      const style = getComputedStyle(element);
      return { id: element.id, outline: style.outlineStyle, width: Number.parseFloat(style.outlineWidth) };
    });
    order.push(focus.id);
    assert.notEqual(focus.outline, "none", focus.id);
    assert.ok(focus.width >= 2, focus.id);
  }
  assert.deepEqual(order, ["bundle", "policy", "history", "register", "now", "trusted-time", "accept", "verify"]);
  await page.keyboard.press("Shift+Tab");
  await page.keyboard.press("Shift+Tab");
  await page.keyboard.press("Space");
  assert.equal(await page.isChecked("#trusted-time"), true);
  await page.keyboard.press("Space");
  await page.keyboard.press("Tab");
  await page.keyboard.press("Space");
  assert.equal(await page.isChecked("#accept"), true);
  await page.keyboard.press("Space");
  assert.equal(await page.isChecked("#accept"), false);
  await page.keyboard.press("Tab");
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => (document.getElementById("status")?.textContent ?? "").startsWith("Verification finished"));
  assert.equal(await page.evaluate(() => document.activeElement?.id), "result-heading");
  assert.equal(await page.getAttribute("#verdict", "data-verdict"), "verified");
  await close(session);
});

test("names and structure for assistive technology", async () => {
  const session = await open();
  const { page } = session;
  assert.equal(await page.getAttribute("html", "lang"), "en");
  assert.equal(await page.getByRole("heading", { level: 1, name: "Verify ECL-1 evidence" }).count(), 1);
  for (const label of ["Evidence bundle or offline package", "Trust policy", "Earlier trust-policy versions (optional)", "Consequential Action Register (optional)", "Evaluation time (UTC)"]) {
    const field = page.getByLabel(label, { exact: true });
    assert.equal(await field.count(), 1, label);
    const described = (await field.getAttribute("aria-describedby")) ?? "";
    assert.notEqual(described, "", label);
    assert.ok((await page.locator(`#${described}`).innerText()).length > 10, label);
  }
  for (const name of ["Require trusted time", "Accept a current trust failure"]) {
    assert.equal(await page.getByRole("checkbox", { name }).count(), 1, name);
  }
  assert.equal(await page.getByRole("button", { name: "Verify" }).count(), 1);
  assert.equal(await page.getByRole("status").count(), 1);
  await verify(page, { bundle: `${SUITE}/bundle-invalid-responds-to-digest.json`, policy: `${SUITE}/trust-policy.json` });
  assert.equal(await page.getByRole("region", { name: "Result" }).count(), 1);
  for (const name of ["Summary", "Findings", "Envelopes", "Bindings", "Effects"]) {
    assert.equal(await page.getByRole("heading", { level: 3, name }).count(), 1, name);
  }
  assert.match(await page.innerText("#status"), /Verdict: Invalid\./);
  await close(session);
});

test("input problems are announced, and nothing is reported as verified", async () => {
  const session = await open();
  const { page } = session;
  await page.click("#verify");
  await page.waitForFunction(() => document.getElementById("problem")?.hidden === false);
  assert.equal(await page.getByRole("alert").innerText(), "Choose an evidence bundle or offline package file.");
  await verify(page, { bundle: `${SUITE}/bundle-valid-succeeded.json`, policy: "conformance/suites/trust-policy/trust-policy-invalid-bad-point.json" });
  let alert = await page.getByRole("alert").innerText();
  assert.match(alert, /The files could not be verified\./);
  assert.match(alert, /ecl\.error\.semantic-invalid\.v1/);
  assert.equal(await page.isHidden("#result"), true);
  await verify(page, { bundle: `${SUITE}/bundle-valid-succeeded.json`, policy: `${SUITE}/trust-policy.json`, now: "yesterday" });
  assert.match(await page.getByRole("alert").innerText(), /Write the evaluation time in UTC/);
  await page.setInputFiles("#bundle", { name: "large.json", mimeType: "application/json", buffer: Buffer.alloc(1024 * 1024 + 1, 0x20) });
  await page.fill("#now", NOW);
  await page.click("#verify");
  await page.waitForFunction(() => (document.getElementById("problem")?.textContent ?? "").includes("larger than"));
  alert = await page.getByRole("alert").innerText();
  assert.match(alert, /larger than 1024 KiB/);
  // TP1-007: the refusal names the registered code, as the library and the command line do.
  assert.match(alert, /ecl\.error\.resource-limit-exceeded\.v1/);
  assert.equal(await page.isHidden("#result"), true);
  // An offline package is a ZIP file, refused without reading it above its own larger limit.
  const large = Buffer.alloc(16 * 1024 * 1024 + 1, 0);
  large.write("PK", 0, "latin1");
  await page.setInputFiles("#bundle", { name: "large.zip", mimeType: "application/zip", buffer: large });
  await page.click("#verify");
  await page.waitForFunction(() => (document.getElementById("problem")?.textContent ?? "").includes("16384 KiB"));
  alert = await page.getByRole("alert").innerText();
  assert.match(alert, /offline package large\.zip is larger than 16384 KiB/);
  assert.match(alert, /ecl\.error\.resource-limit-exceeded\.v1/);
  assert.equal(await page.isHidden("#result"), true);
  await close(session);
});

test("phone width: no horizontal scrolling, with or without a result", async () => {
  const session = await open({ width: 320 });
  const { page } = session;
  const overflow = (): Promise<number> => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  assert.ok((await overflow()) <= 0);
  for (const vector of vectors().filter((item) => ["bundle-valid-trusted-time", "bundle-invalid-terminal-authority-digest"].includes(item["id"] as string))) {
    await verify(page, runOf(vector));
    assert.ok((await overflow()) <= 0, vector["id"] as string);
    await page.click("summary");
    assert.ok((await overflow()) <= 0, `${vector["id"] as string} with the JSON report open`);
  }
  await close(session);
});

for (const colorScheme of ["light", "dark"] as const) {
  test(`text contrast meets WCAG 2.2 level AA (${colorScheme} color scheme)`, async () => {
    const session = await open({ colorScheme });
    const { page } = session;
    const vector = vectors().find((item) => item["id"] === "bundle-current-trust-failed-revoked-after-use") as JsonObject;
    await verify(page, { ...runOf(vector), accept: true });
    await page.click("summary");
    // A keyboard move, so that the focused control shows its focus indicator.
    await page.focus("#now");
    await page.keyboard.press("Tab");
    const failures = await page.evaluate(() => {
      function rgb(value: string): [number, number, number, number] {
        const parts = value.match(/[0-9.]+/g)?.map(Number) ?? [0, 0, 0];
        return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0, parts[3] ?? 1];
      }
      function luminance([red, green, blue]: [number, number, number, number]): number {
        const channel = (value: number): number => {
          const scaled = value / 255;
          return scaled <= 0.04045 ? scaled / 12.92 : ((scaled + 0.055) / 1.055) ** 2.4;
        };
        return 0.2126 * channel(red) + 0.7152 * channel(green) + 0.0722 * channel(blue);
      }
      function background(element: Element | null): [number, number, number, number] {
        for (let current = element; current !== null; current = current.parentElement) {
          const color = rgb(getComputedStyle(current).backgroundColor);
          if (color[3] > 0) {
            return color;
          }
        }
        return [255, 255, 255, 1];
      }
      const problems: string[] = [];
      let checked = 0;
      for (const element of Array.from(document.querySelectorAll("body *"))) {
        const own = Array.from(element.childNodes).some((node) => node.nodeType === Node.TEXT_NODE && (node.textContent ?? "").trim() !== "");
        const box = element.getBoundingClientRect();
        if (!own || box.width === 0 || box.height === 0) {
          continue;
        }
        const style = getComputedStyle(element);
        const [lighter, darker] = [luminance(rgb(style.color)), luminance(background(element))].sort((a, b) => b - a) as [number, number];
        const ratio = (lighter + 0.05) / (darker + 0.05);
        const size = Number.parseFloat(style.fontSize);
        const large = size >= 24 || (size >= 18.66 && Number.parseInt(style.fontWeight, 10) >= 700);
        checked += 1;
        if (ratio < (large ? 3 : 4.5)) {
          problems.push(`${element.tagName.toLowerCase()} "${(element.textContent ?? "").trim().slice(0, 40)}": ${ratio.toFixed(2)}`);
        }
      }
      const focus = document.activeElement as HTMLElement;
      const outline = luminance(rgb(getComputedStyle(focus).outlineColor));
      const page = luminance(background(document.body));
      const outlineRatio = (Math.max(outline, page) + 0.05) / (Math.min(outline, page) + 0.05);
      if (outlineRatio < 3) {
        problems.push(`focus outline: ${outlineRatio.toFixed(2)}`);
      }
      return { problems, checked };
    });
    assert.deepEqual(failures.problems, []);
    assert.ok(failures.checked > 50);
    await close(session);
  });
}
