/** Local Chromium regression: package input bounds must remain reportable and unread. */
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

test("oversized PK input is refused before full read with an ordinary invalid JSON report",async()=>{
  const browser=await chromium.launch({headless:true});
  const results:unknown[]=[];
  try {
    for(const oversized of [false,true]) {
      const context=await browser.newContext({viewport:{width:1100,height:900},serviceWorkers:"block"});
      const page=await context.newPage();const errors:string[]=[];const requests:string[]=[];
      const url=pathToFileURL(join(WEB,"web/verifier/index.html")).href;
      const script=pathToFileURL(join(WEB,"web/verifier/verifier.js")).href;
      await context.route("**/*",route=>[url,script].includes(route.request().url())?route.continue():route.abort());
      page.on("pageerror",error=>errors.push(String(error)));page.on("request",request=>requests.push(request.url()));
      await page.addInitScript(()=>{
        const original=File.prototype.arrayBuffer;
        (window as unknown as {fullFileReads:{name:string;size:number}[]}).fullFileReads=[];
        File.prototype.arrayBuffer=function(){
          (window as unknown as {fullFileReads:{name:string;size:number}[]}).fullFileReads.push({name:this.name,size:this.size});
          return original.call(this);
        };
      });
      await page.goto(url);
      await page.locator("#policy").setInputFiles(join(ROOT,"conformance/suites/offline-package/trust-policy.json"));
      if(oversized){
        const buffer=Buffer.alloc(16*1024*1024+1);buffer[0]=0x50;buffer[1]=0x4b;
        await page.locator("#bundle").setInputFiles({name:"oversized-package.zip",mimeType:"application/zip",buffer});
      }else await page.locator("#bundle").setInputFiles(join(ROOT,"conformance/suites/offline-package/package-valid-verified.zip"));
      await page.locator("#now").fill("2026-10-01T00:00:00Z");await page.locator("#verify").click();
      await page.waitForFunction(()=>!document.querySelector<HTMLElement>("#result")!.hidden||!document.querySelector<HTMLElement>("#problem")!.hidden);
      assert.equal(await page.locator("#problem").isVisible(),false);
      const report=JSON.parse((await page.locator("#result-body details pre code").textContent())!);
      const reads=await page.evaluate(()=>(window as unknown as {fullFileReads:{name:string;size:number}[]}).fullFileReads);
      assert.equal(report.verdict,oversized?"invalid":"verified");
      if(oversized){
        assert.equal(reads.some(file=>file.name==="oversized-package.zip"),false);
        assert.equal(report.primary,"ecl.error.resource-limit-exceeded.v1");
        assert.match(report.findings[0],/^ecl\.error\.resource-limit-exceeded\.v1:/);
        assert.deepEqual(report.scope.established,[]);assert.deepEqual(report.scope.checks,{});
        assert.deepEqual(report.envelope_checks,[]);assert.deepEqual(report.binding_checks,[]);assert.deepEqual(report.effects,[]);
      }
      assert.deepEqual(errors,[]);assert.ok(requests.every(request=>[url,script].includes(request)));
      results.push({case:oversized?"oversized":"valid-control",report,reads,errors,requests});
      if(OUTPUT) {mkdirSync(OUTPUT,{recursive:true});await page.screenshot({path:join(OUTPUT,oversized?"oversized.png":"valid-control.png"),fullPage:true});}
      await context.close();
    }
  }finally{await browser.close();}
  if(OUTPUT)writeFileSync(join(OUTPUT,"result.json"),JSON.stringify(results,null,2)+"\n");
});
