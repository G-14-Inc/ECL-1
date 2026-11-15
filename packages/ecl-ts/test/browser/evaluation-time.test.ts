/** Local browser guidance must describe the public verifier's evaluation-time domain. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { chromium } from "playwright-core";
import { repoRoot } from "../unit/helpers.js";
const ROOT=repoRoot();
const WEB=resolve(process.env["ECL_BROWSER_ROOT"]??ROOT);
const OUTPUT=process.env["ECL_BROWSER_EVIDENCE_DIR"];
test("evaluation time accepts whole seconds, milliseconds and microseconds and explains refused precision",async()=>{
  const browser=await chromium.launch({headless:true});
  const results:unknown[]=[];
  try {
    const context=await browser.newContext({viewport:{width:1100,height:900},serviceWorkers:"block"});
    const page=await context.newPage();const errors:string[]=[];const requests:string[]=[];
    const url=pathToFileURL(join(WEB,"web/verifier/index.html")).href;
    const script=pathToFileURL(join(WEB,"web/verifier/verifier.js")).href;
    await context.route("**/*",route=>[url,script].includes(route.request().url())?route.continue():route.abort());
    page.on("pageerror",error=>errors.push(String(error)));page.on("request",request=>requests.push(request.url()));
    await page.goto(url);
    await page.locator("#policy").setInputFiles(join(ROOT,"conformance/suites/offline-package/trust-policy.json"));
    await page.locator("#bundle").setInputFiles(join(ROOT,"conformance/suites/offline-package/package-valid-verified.zip"));
    for(const digits of [0,1,3,6,9]) {
      const time="2026-10-01T00:00:00"+(digits?"."+"0".repeat(digits):"")+"Z";
      await page.locator("#now").fill(time);await page.locator("#verify").click();
      await page.waitForFunction(()=>!document.querySelector<HTMLElement>("#result")!.hidden||!document.querySelector<HTMLElement>("#problem")!.hidden);
      const invalid=digits===1||digits===9;
      const problem=await page.locator("#problem").textContent();
      const report=invalid?null:JSON.parse((await page.locator("#result-body details pre code").textContent())!);
      const observation={digits,time,problem,report};results.push(observation);
      if(OUTPUT){mkdirSync(OUTPUT,{recursive:true});writeFileSync(join(OUTPUT,"evaluation-time.json"),JSON.stringify(results,null,2)+"\n");await page.screenshot({path:join(OUTPUT,`time-${digits}.png`),fullPage:true});}
      assert.equal(await page.locator("#problem").isVisible(),invalid);
      if(invalid){assert.match(problem??"",/whole seconds or three or six fractional digits/);assert.doesNotMatch(problem??"",/up to nine/);}
      else assert.equal(report.verdict,"verified");
    }
    assert.deepEqual(errors,[]);assert.ok(requests.every(request=>[url,script].includes(request)));
    if(OUTPUT)writeFileSync(join(OUTPUT,"browser-events.json"),JSON.stringify({errors,requests},null,2)+"\n");
    await context.close();
  }finally{await browser.close();}
});
