// Stored metadata and declared budgets. Robert F. Tilley Jr.; G-14, Inc.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {ArchiveRefusal,TrustPolicy,readStoredZip,verifyOfflinePackage,packageIdentifiers} from '../../src/index.js';
import {bytes,json} from './helpers.js';
interface Case {id:string;archive_base64:string;limits:{max_archive_bytes:number;max_member_count:number;max_entry_uncompressed_bytes:number;max_total_uncompressed_bytes:number;max_compression_ratio:number;max_path_bytes:number};reader_code:string;package_verdict:string;package_codes:string[];}
const cases=json('tests/fixtures/archive-metadata-boundaries.json')['cases'] as unknown as Case[];
const policy=TrustPolicy.load(bytes('conformance/suites/offline-package/trust-policy.json'));
for(const row of cases)test('archive metadata boundary: '+row.id,()=>{
 const data=Buffer.from(row.archive_base64,'base64'),given=row.limits;
 const limits={maxArchiveBytes:given.max_archive_bytes,maxMemberCount:given.max_member_count,maxEntryUncompressedBytes:given.max_entry_uncompressed_bytes,maxTotalUncompressedBytes:given.max_total_uncompressed_bytes,maxCompressionRatio:given.max_compression_ratio,maxPathBytes:given.max_path_bytes};
 let code='accepted';
 try{readStoredZip(data,limits);}catch(error){assert.ok(error instanceof ArchiveRefusal);code=error.limit?'ecl.error.resource-limit-exceeded.v1':'ecl.error.semantic-invalid.v1';}
 assert.equal(code,row.reader_code);
 const report=verifyOfflinePackage(data,policy,{now:'2026-10-01T00:00:00Z',limits});
 assert.equal(report.verdict,row.package_verdict);assert.deepEqual(packageIdentifiers(report).sort(),row.package_codes);
});
