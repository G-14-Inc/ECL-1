/**
 * The browser verifier (web/verifier/index.html). It reads the files the person chooses, verifies
 * the evidence bundle, or the offline package that carries one, with this library exactly as the
 * reference verifies it, and explains the result. It builds the page with DOM calls and text nodes
 * only, never HTML strings, and it makes no network request: the page's content security policy
 * forbids every connection.
 *
 * scripts/build-verifier.mjs bundles this file and the library into web/verifier/verifier.js.
 */

// The modules the page uses, imported one by one so that the bundle carries the evidence and
// package verifiers and nothing else of the library (not the binding-profile rules or document
// stage).
import { MAX_BUNDLE_BYTES, MAX_REGISTER_BYTES, VerifierInputError, verifyBundleBytes } from "../src/evidence/bytes.js";
import { describeCode, describeVerdict } from "../src/evidence/explain.js";
import { CAUSAL_CLOSURE_INCOMPLETE, CURRENT_TRUST_FAILED, REFERENCE_PROFILE, RESOURCE_LIMIT, SCOPE_TEXT, TRUSTED_TIME_PROFILE, reportToJson } from "../src/evidence/verify.js";
import type { BindingCheck, BundleReport, EffectEvidence, EnvelopeCheck, TrustDependency } from "../src/evidence/verify.js";
import { verifyPackageBytes } from "../src/offline/package.js";
import { DEFAULT_OFFLINE_RESOURCE_LIMITS } from "../src/offline/zip.js";
import { MAX_TRUST_POLICY_BYTES } from "../src/trust/policy.js";
import type { TrustPolicy } from "../src/trust/policy.js";

const KIB = 1024;
/** The largest offline package the page reads: its declared archive limit (IE1-028). */
const MAX_PACKAGE_BYTES = 16 * 1024 * KIB;
/** The page's declared package limits: the reference's, with the archive bounded as above. */
const PACKAGE_LIMITS = { ...DEFAULT_OFFLINE_RESOURCE_LIMITS, maxArchiveBytes: MAX_PACKAGE_BYTES };

/** What the person chose: an evidence bundle (JSON) or an offline package (a ZIP archive). */
interface Evidence {
  readonly kind: "bundle" | "package";
  readonly bytes: number;
}

type Child = Node | string;

function element<K extends keyof HTMLElementTagNameMap>(tag: K, attributes: Record<string, string> = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) {
    node.setAttribute(name, value);
  }
  for (const child of children) {
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

function code(text: string): HTMLElement {
  return element("code", {}, text);
}

function required<T extends HTMLElement>(id: string, type: new () => T): T {
  const node = document.getElementById(id);
  if (!(node instanceof type)) {
    throw new Error(`the page has no ${id} element`);
  }
  return node;
}

/** A definition list from label and content pairs. */
function details(rows: ReadonlyArray<readonly [string, Child | readonly Child[]]>): HTMLDListElement {
  const list = element("dl");
  for (const [label, content] of rows) {
    list.append(element("dt", {}, label), element("dd", {}, ...(Array.isArray(content) ? content : [content as Child])));
  }
  return list;
}

/** "Valid", or the title of the refusal with its explanation and identifier. */
function status(value: string): Child[] {
  if (value === "valid") {
    return ["Valid."];
  }
  const explanation = describeCode(value);
  return [element("strong", {}, `Not valid: ${explanation.title}.`), ` ${explanation.text} `, code(value)];
}

function kindLabel(kind: string): string {
  return kind === "unknown" ? "not readable" : kind.replaceAll("_", " ");
}

const BINDINGS: Record<string, string> = {
  response: "The decision response in envelope {n} answers its request.",
  authority: "The authority event in envelope {n} matches the decision that granted the authority.",
  execution: "The execution event in envelope {n} matches its request and decision.",
  "request-reference": "The event in envelope {n} names its request correctly.",
  "decision-reference": "The event in envelope {n} names its decision correctly.",
  "decision-content": "The decision event in envelope {n} records the decision's outcome and policy.",
};

function bindingText(check: BindingCheck): string {
  const [name = "", index = ""] = check.name.split(":");
  const template = BINDINGS[name];
  return template === undefined ? `Binding check ${check.name}.` : template.replace("{n}", index);
}

const LEVELS: Record<EffectEvidence["level"], string> = {
  none: "None. The final state of this action is not supported by an envelope that was valid when it was signed.",
  "issuer-asserted":
    "Issuer-asserted. The enforcement point signed a statement of this final state. That is an authenticated statement, not proof that the effect happened.",
  corroborated:
    "Corroborated. An observer, a different principal with its own keys, also signed a passing check of every side effect, made no earlier than the final state.",
};

const AUTHORITY: Record<EffectEvidence["authority"], string> = {
  consumed: "Used. The enforcement point consumed the authority that the decision granted.",
  "issued-unused": "Issued and not used.",
  none: "None was issued.",
};

const CAUSAL: Record<string, string> = {
  complete: "Complete. Every causal predecessor is in the bundle, and every request and action attempt has a final state.",
  incomplete: "Incomplete. A causal predecessor or a final state is missing from the bundle.",
  indeterminate: "Could not be determined, because the records break a causal rule. The findings name it.",
};

function recordText(status: string): Child[] {
  const parts: Child[] = [CAUSAL[status] ?? "", " ", code(status)];
  if (status === "incomplete") {
    // The registered error that conformance reports name for this verdict (EBMP2-060).
    parts.push(" ", code(CAUSAL_CLOSURE_INCOMPLETE));
  }
  return parts;
}

function profileText(profile: string): Child[] {
  if (profile === TRUSTED_TIME_PROFILE) {
    return ["Reference profile with trusted time. Every envelope needs a valid trusted-time countersignature. ", code(profile)];
  }
  if (profile === REFERENCE_PROFILE) {
    return ["Reference profile. ", code(profile)];
  }
  return [code(profile)];
}

function registerText(report: BundleReport): Child[] {
  const register = report.register;
  if (register === null) {
    return ["None supplied, so the declared classes and inputs of each decision basis were not checked against a register."];
  }
  const digest = register["digest"] as { value: string };
  const version = typeof register["version"] === "string" ? [", version ", code(register["version"])] : [];
  return [code(String(register["uri"])), ...version, ". SHA-256 of its canonical form: ", code(digest.value)];
}

function evidenceText(evidence: Evidence): Child[] {
  if (evidence.kind === "package") {
    return [
      `An offline package of ${evidence.bytes} bytes: an `,
      code("ecl.zip.store.v1"),
      " archive whose archive and manifest are checked first, and whose evidence bundle is then verified under your trust policy (IE1-022). The trust policy, keys and snapshots inside the package are evidence for you to read, not trust.",
    ];
  }
  return [`An evidence bundle of ${evidence.bytes} bytes (JSON).`];
}

/** One item of the scope as a sentence, with its identifier and its stated reason (EBMP2-076). */
function scopeItem(item: string, reason?: string): HTMLLIElement {
  const text = SCOPE_TEXT[item] ?? item;
  const parts: Child[] = [`${text.charAt(0).toUpperCase()}${text.slice(1)}. `, code(item)];
  if (reason !== undefined) {
    parts.push(" Reason: ", code(reason), ".");
  }
  return element("li", {}, ...parts);
}

/**
 * EBMP2-076: what the verdict does not establish, shown with the verdict, then the checks that the
 * verifier made and that held.
 */
function scopeSection(report: BundleReport): HTMLElement[] {
  const missing = element("ul", { class: "scope", id: "not-established", "aria-labelledby": "not-established-lead" });
  for (const item of report.scope.notEstablished) {
    missing.append(scopeItem(item, report.scope.reasons[item]));
  }
  const parts: HTMLElement[] = [element("p", { id: "not-established-lead" }, element("strong", {}, "This verdict does not establish:")), missing];
  if (report.completionAfterWindow) {
    // EBMP2-072: the server's answer arrived after the authorization's window; the release itself
    // was inside it. Information, not a finding.
    parts.push(
      element(
        "p",
        { id: "completion-after-window" },
        "The server's answer to the forwarded call arrived after the authorization's window ended (",
        code("completion_after_window"),
        "). The release itself was inside the window; the late answer is not a finding.",
      ),
    );
  }
  if (report.scope.established.length === 0) {
    parts.push(
      element(
        "p",
        { id: "established-lead" },
        "It establishes nothing that the verifier checked: a check failed, or no envelope could be evaluated.",
      ),
    );
    return parts;
  }
  const held = element("ul", { class: "scope", id: "established", "aria-labelledby": "established-lead" });
  for (const item of report.scope.established) {
    held.append(scopeItem(item));
  }
  parts.push(element("p", { id: "established-lead" }, element("strong", {}, "What the verifier checked and found to hold:")), held);
  return parts;
}

function findingsSection(report: BundleReport): HTMLElement[] {
  const heading = element("h3", {}, "Findings");
  if (report.findings.length === 0) {
    const text =
      report.verdict === CURRENT_TRUST_FAILED || report.acceptedCurrentTrustFailure
        ? "No rule findings are reported. Read the scope and trust dependencies in the JSON report for the checks that held and any current trust failure."
        : report.verdict === "incomplete"
          ? "No rule findings are reported. The supplied evidence is incomplete, as the summary says."
          : "No rule findings are reported. Read the scope and trust dependencies in the JSON report for the checks that held.";
    return [heading, element("p", {}, text)];
  }
  const list = element("ul", { class: "findings" });
  for (const finding of report.findings) {
    const explanation = describeCode(finding.code);
    list.append(
      element(
        "li",
        {},
        element("p", {}, element("strong", {}, explanation.title), " ", code(finding.code)),
        element("p", {}, explanation.text),
        element("p", { class: "detail" }, `Detail: ${finding.message}`),
      ),
    );
  }
  return [heading, list];
}

/**
 * The time authorities of one envelope (TP1-006): each key that signed one of its time
 * attestations, with the attested time and its status then and at the evaluation time.
 */
function authorities(dependencies: readonly TrustDependency[]): Child[] {
  if (dependencies.length === 0) {
    return ["None."];
  }
  return dependencies.flatMap((dependency, position): Child[] => [
    ...(position === 0 ? [] : ["; "]),
    code(dependency.keyId),
    ...(dependency.at === null ? [] : [" at ", code(dependency.at)]),
    ": then ",
    code(dependency.historical),
    ", now ",
    code(dependency.current),
  ]);
}

function envelopeItem(check: EnvelopeCheck, dependencies: readonly TrustDependency[]): HTMLLIElement {
  return element(
    "li",
    {},
    element("p", { class: "item-title" }, `Envelope ${check.index}: ${kindLabel(check.kind)}`),
    details([
      ["Object", check.objectId === null ? "Not readable." : code(check.objectId)],
      ["Signed by", check.signerKeyIds.length === 0 ? "No signature." : check.signerKeyIds.flatMap((keyId, position) => (position === 0 ? [code(keyId)] : [", ", code(keyId)]))],
      ["When it was signed", status(check.historical)],
      ["At the evaluation time", status(check.current)],
      ["Trust-policy version used for the time of signing", check.historicalPolicyVersion ?? "None."],
      ["Trusted time", check.trustedTime === null ? "None." : code(check.trustedTime)],
      ["Time authorities", authorities(dependencies.filter((dependency) => dependency.index === check.index && dependency.role === "time-authority"))],
    ]),
  );
}

function effectItem(effect: EffectEvidence): HTMLLIElement {
  return element(
    "li",
    {},
    element("p", { class: "item-title" }, "Action ", code(effect.actionId)),
    details([
      ["Final state", effect.state.replaceAll("_", " ")],
      ["Evidence level", [LEVELS[effect.level], " ", code(effect.level)]],
      ["Authority", [AUTHORITY[effect.authority], " ", code(effect.authority)]],
      ["Reason", effect.reason === null ? "None given." : code(effect.reason)],
    ]),
  );
}

function render(container: HTMLElement, report: BundleReport, policy: TrustPolicy, now: string, evidence: Evidence): void {
  const verdict = describeVerdict(report.verdict);
  const parts: Node[] = [
    element("p", { class: "verdict", "data-verdict": report.verdict, id: "verdict" }, "Verdict: ", element("strong", {}, verdict.title)),
    element("p", {}, verdict.text),
    ...scopeSection(report),
  ];
  // A package that failed before its bundle was verified has no envelope, binding or effect.
  const unverifiedBundle = evidence.kind === "package" && report.causalStatus === "not-analyzed" && report.envelopeChecks.length === 0;
  if (evidence.kind === "package") {
    parts.push(
      element(
        "p",
        {},
        unverifiedBundle
          ? "This is an offline package. Its evidence bundle could not be evaluated. The findings identify archive, manifest or evidence issues, or missing required material."
          : "This is an offline package. The result includes the checks performed on its evidence bundle and any package findings, listed first.",
      ),
    );
  }
  if (report.acceptedCurrentTrustFailure) {
    parts.push(
      element(
        "p",
        { class: "note" },
        "You chose to accept a current trust failure for a signer or other trust dependency in this run. The report records that choice. It does not establish current trust, waive package expiry or restore historically invalid evidence.",
      ),
    );
  }
  parts.push(
    element("h3", {}, "Summary"),
    details([
      ["Evidence", evidenceText(evidence)],
      ["Evaluation time", code(now)],
      ["Verification profile", profileText(report.verificationProfile)],
      ["Trust policy", [code(policy.policyId), `, version ${policy.version}. SHA-256 of its canonical form: `, code(policy.digest)]],
      ["Consequential Action Register", registerText(report)],
      ["Record of actions", recordText(report.causalStatus)],
    ]),
    ...findingsSection(report),
    element("h3", {}, "Envelopes"),
  );
  const envelopes = element("ol", { class: "items", start: "0" });
  for (const check of report.envelopeChecks) {
    envelopes.append(envelopeItem(check, report.trustDependencies));
  }
  const noEnvelope = unverifiedBundle ? "The evidence bundle was not verified." : "The bundle holds no envelope that could be read.";
  parts.push(report.envelopeChecks.length === 0 ? element("p", {}, noEnvelope) : envelopes, element("h3", {}, "Bindings"));
  if (report.bindingChecks.length === 0) {
    parts.push(element("p", {}, "No binding was checked."));
  } else {
    const bindings = element("ul", { class: "bindings" });
    for (const check of report.bindingChecks) {
      const outcome = check.passed ? element("strong", {}, "Passed: ") : element("strong", {}, "Failed: ");
      const item = element("li", {}, outcome, bindingText(check));
      if (check.code !== null) {
        item.append(` ${describeCode(check.code).title}. `, code(check.code));
      }
      bindings.append(item);
    }
    parts.push(bindings);
  }
  parts.push(element("h3", {}, "Effects"));
  if (report.effects.length === 0) {
    parts.push(element("p", {}, "The bundle records no final state of an action."));
  } else {
    const effects = element("ul", { class: "items" });
    for (const effect of report.effects) {
      effects.append(effectItem(effect));
    }
    parts.push(effects);
  }
  parts.push(
    element(
      "details",
      {},
      element("summary", {}, "Report as JSON"),
      element("p", {}, "The same report that the command-line verifier prints with --json."),
      element("pre", {}, element("code", {}, JSON.stringify(reportToJson(report), null, 2))),
    ),
  );
  container.replaceChildren(...parts);
}

/** A file the page refuses before reading it; `code` is the registered refusal, when there is one. */
class InputProblem extends Error {
  readonly code: string | undefined;

  constructor(message: string, code?: string) {
    super(message);
    this.code = code;
  }
}

async function read(file: File, limit: number, name: string): Promise<Uint8Array> {
  if (file.size > limit) {
    // TP1-007: a file above its byte limit is refused unread, with the registered code.
    throw new InputProblem(`The ${name} ${file.name} is larger than ${limit / KIB} KiB. The verifier refuses it without reading it.`, RESOURCE_LIMIT);
  }
  return new Uint8Array(await file.arrayBuffer());
}

function evaluationTime(field: HTMLInputElement): string {
  const text = field.value.trim();
  return text === "" ? new Date().toISOString() : text;
}

function start(): void {
  const form = required("verify-form", HTMLFormElement);
  const bundleField = required("bundle", HTMLInputElement);
  const policyField = required("policy", HTMLInputElement);
  const historyField = required("history", HTMLInputElement);
  const registerField = required("register", HTMLInputElement);
  const nowField = required("now", HTMLInputElement);
  const trustedField = required("trusted-time", HTMLInputElement);
  const acceptField = required("accept", HTMLInputElement);
  const button = required("verify", HTMLButtonElement);
  const statusLine = required("status", HTMLElement);
  const problem = required("problem", HTMLElement);
  const result = required("result", HTMLElement);
  const resultBody = required("result-body", HTMLElement);
  const resultHeading = required("result-heading", HTMLElement);
  let busy = false;

  function showProblem(message: string, detail?: string, registered?: string): void {
    const parts: Node[] = [element("p", {}, element("strong", {}, message))];
    if (detail !== undefined) {
      parts.push(element("p", { class: "detail" }, `Detail: ${detail}`));
    }
    if (registered !== undefined) {
      const explanation = describeCode(registered);
      parts.push(element("p", {}, `${explanation.title}. ${explanation.text} `, code(registered)));
    }
    problem.replaceChildren(...parts);
    problem.hidden = false;
    statusLine.textContent = "";
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (busy) {
      return;
    }
    busy = true;
    button.setAttribute("aria-disabled", "true");
    problem.hidden = true;
    problem.replaceChildren();
    result.hidden = true;
    resultBody.replaceChildren();
    statusLine.textContent = "Verifying.";
    void verify().finally(() => {
      busy = false;
      button.removeAttribute("aria-disabled");
    });
  });

  async function verify(): Promise<void> {
    const bundleFile = bundleField.files?.[0];
    const policyFile = policyField.files?.[0];
    if (bundleFile === undefined || policyFile === undefined) {
      showProblem(bundleFile === undefined ? "Choose an evidence bundle or offline package file." : "Choose a trust policy file.");
      return;
    }
    let report: BundleReport;
    let policy: TrustPolicy;
    let evidence: Evidence;
    const now = evaluationTime(nowField);
    try {
      // An offline package is a ZIP archive, whose bytes begin with "PK"; a JSON bundle cannot.
      const head = new Uint8Array(await bundleFile.slice(0, 2).arrayBuffer());
      const kind = head[0] === 0x50 && head[1] === 0x4b ? "package" : "bundle";
      const data =
        kind === "package" ? await read(bundleFile, MAX_PACKAGE_BYTES, "offline package") : await read(bundleFile, MAX_BUNDLE_BYTES, "evidence bundle");
      evidence = { kind, bytes: data.length };
      const trustPolicy = await read(policyFile, MAX_TRUST_POLICY_BYTES, "trust policy");
      const history: Uint8Array[] = [];
      for (const file of Array.from(historyField.files ?? [])) {
        history.push(await read(file, MAX_TRUST_POLICY_BYTES, "earlier trust-policy version"));
      }
      const registerFile = registerField.files?.[0];
      const register = registerFile === undefined ? undefined : await read(registerFile, MAX_REGISTER_BYTES, "register");
      // Let the status line reach assistive technology before the work starts.
      await new Promise((resolve) => setTimeout(resolve, 0));
      const options = {
        now,
        history,
        requireTrustedTime: trustedField.checked,
        acceptCurrentTrustFailure: acceptField.checked,
        ...(register === undefined ? {} : { register }),
      };
      ({ report, policy } = kind === "package" ? verifyPackageBytes(data, trustPolicy, { ...options, limits: PACKAGE_LIMITS }) : verifyBundleBytes(data, trustPolicy, options));
    } catch (error) {
      if (error instanceof InputProblem) {
        showProblem(error.message, undefined, error.code);
      } else if (error instanceof VerifierInputError) {
        if (error.message.startsWith("invalid evaluation time")) {
          showProblem("Write the evaluation time in UTC like 2026-10-01T00:00:00Z, with 0, 3 or 6 digits after the seconds, or leave it empty.", error.message);
        } else {
          showProblem("The files could not be verified.", error.message, error.code);
        }
      } else {
        showProblem("The verifier stopped with an unexpected error.", error instanceof Error ? error.message : String(error));
      }
      return;
    }
    render(resultBody, report, policy, now, evidence);
    result.hidden = false;
    statusLine.textContent = `Verification finished. Verdict: ${describeVerdict(report.verdict).title}.`;
    resultHeading.focus();
  }

  required("script-state", HTMLElement).hidden = true;
  button.disabled = false;
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start);
} else {
  start();
}
