"""Generate small ZIP metadata cases; declared sizes never allocate member data.

Robert F. Tilley Jr.; G-14, Inc.
"""
from pathlib import Path
import argparse,base64,hashlib,json,struct,zlib

ROOT=Path(__file__).resolve().parents[1]
RESOURCE='ecl.error.resource-limit-exceeded.v1'
SEMANTIC='ecl.error.semantic-invalid.v1'
CLOSURE='ecl.error.causal-closure-incomplete.v1'
LIMITS={'max_archive_bytes':64*1024*1024,'max_member_count':1000,'max_entry_uncompressed_bytes':16*1024*1024,'max_total_uncompressed_bytes':64*1024*1024,'max_compression_ratio':1000,'max_path_bytes':4096}

def entry(name=b'a', *, flags=0, size=0, stored=0, disk=0, extra=b'', version=20, bad_signature=False):
    return dict(name=name,flags=flags,size=size,stored=stored,disk=disk,extra=extra,version=version,bad_signature=bad_signature)

def archive(entries):
    local=bytearray();central=bytearray()
    for e in entries:
        offset=len(local);name=e['name']
        local+=struct.pack('<IHHHHHIIIHH',0x04034b50,20,e['flags'],0,0,33,0,0,0,len(name),0)+name
        central+=struct.pack('<IHHHHHHIIIHHHHHII',0x02014b50 if not e['bad_signature'] else 0,0x314,e['version'],e['flags'],0,0,33,0,e['stored'],e['size'],len(name),len(e['extra']),0,e['disk'],0,0o100644<<16,offset)+name+e['extra']
    return bytes(local+central+struct.pack('<IHHHHIIH',0x06054b50,0,0,len(entries),len(entries),len(central),len(local),0))

def stored_archive(entries):
    local=bytearray();central=bytearray()
    for e in entries:
        offset=len(local);name=e.get('name',b'a');data=e.get('data',b'')
        stored=e.get('stored',len(data));size=e.get('size',len(data));crc=e.get('crc',zlib.crc32(data))
        local+=struct.pack('<IHHHHHIIIHH',0x04034b50,20,0,0,0,33,crc,stored,size,len(name),0)+name+data
        central+=struct.pack('<IHHHHHHIIIHHHHHII',0x02014b50,0x314,20,0,0,0,33,crc,stored,size,len(name),0,0,0,0,0o100644<<16,offset)+name
    return bytes(local+central+struct.pack('<IHHHHIIH',0x06054b50,0,0,len(entries),len(entries),len(central),len(local),0))

def z64(value):
    return struct.pack('<HHQ',1,8,value)

def build():
    rows=[]
    def add(name, entries, expected, *, archive_bytes=None, **limits):
        data=archive(entries) if archive_bytes is None else archive_bytes;assert len(data)<65536
        rows.append({'id':name,'archive_base64':base64.b64encode(data).decode(),'archive_sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'limits':{**LIMITS,**limits},'reader_code':expected,'package_verdict':'incomplete' if expected=='accepted' else 'invalid','package_codes':[CLOSURE if expected=='accepted' else expected]})
    add('empty-control',[],'accepted')
    add('ascii-control',[entry()],'accepted')
    for count in [1365,1366,1500,4096,4097]:
        add(f'cp437-name-{count}',[entry(b'\xb0'*count)],RESOURCE if count>4096 else SEMANTIC)
    add('ascii-name-at-limit',[entry(b'a'*4096)],'accepted')
    add('ascii-name-over-limit',[entry(b'a'*4097)],RESOURCE)
    add('nul-name-before-path-limit',[entry(b'a\x00'+b'b'*4097)],SEMANTIC)
    add('utf8-name-under-limit',[entry(('░'*1365).encode(),flags=0x800)],SEMANTIC)
    add('utf8-name-over-limit',[entry(('░'*1366).encode(),flags=0x800)],RESOURCE)
    add('invalid-utf8-before-size-budget',[entry(b'\xff',flags=0x800,size=100_000_000)],SEMANTIC)
    add('zip64-empty-volume-before-entry-budget',[entry(size=100_000_000,disk=0xffff,extra=struct.pack('<HH',1,0))],RESOURCE)
    add('zip64-empty-volume-under-budget',[entry(disk=0xffff,extra=struct.pack('<HH',1,0))],SEMANTIC)
    add('zip64-complete-volume-over-budget',[entry(size=100_000_000,disk=0xffff,extra=struct.pack('<HHI',1,4,0))],RESOURCE)
    add('zip64-empty-field-no-volume-over-budget',[entry(size=100_000_000,extra=struct.pack('<HH',1,0))],RESOURCE)
    add('zip64-duplicate-max-then-small',[entry(size=0xffffffff,extra=z64(0xffffffffffffffff)+z64(10))],RESOURCE)
    add('zip64-duplicate-max-then-empty',[entry(size=0xffffffff,extra=z64(0xffffffffffffffff)+struct.pack('<HH',1,0))],RESOURCE)
    add('zip64-duplicate-small-then-max',[entry(size=0xffffffff,extra=z64(10)+z64(0xffffffffffffffff))],SEMANTIC)
    add('zip64-duplicate-saturated32-then-small',[entry(size=0xffffffff,extra=z64(0xffffffff)+z64(10))],SEMANTIC)
    add('zip64-entry-at-budget',[entry(size=0xffffffff,stored=16*1024*1024,extra=z64(16*1024*1024))],SEMANTIC)
    add('zip64-entry-over-budget',[entry(size=0xffffffff,stored=16*1024*1024+1,extra=z64(16*1024*1024+1))],RESOURCE)
    add('zip64-missing-required-size',[entry(size=0xffffffff,extra=struct.pack('<HH',1,0))],SEMANTIC)
    add('encrypted-before-size-budget',[entry(flags=1,size=100_000_000)],SEMANTIC)
    add('later-size-budget-before-earlier-name',[entry(b'bad!'),entry(b'b',size=100_000_000)],RESOURCE)
    add('member-count-before-entry-budget',[entry(b'a'),entry(b'b',size=100_000_000)],RESOURCE,max_member_count=1)
    add('later-malformed-directory-before-count',[entry(b'a'),entry(b'b'),entry(b'c',bad_signature=True)],SEMANTIC,max_member_count=1)
    add('archive-byte-limit-before-structure',[entry(b'a',bad_signature=True)],RESOURCE,max_archive_bytes=1)
    add('earlier-profile-before-later-path-budget',[entry(b'a',disk=1),entry(b'b'*4097)],SEMANTIC)
    add('later-stdlib-volume-before-earlier-path',[entry(b'b'*4097),entry(b'c',disk=0xffff,extra=struct.pack('<HH',1,0))],RESOURCE)
    # Contradictory stored sizes are archive-profile refusals at check 1,
    # before manifest artifact integrity is evaluated. Keep member ordering.
    add('stored-size-greater-than-zero-stored',[],SEMANTIC,archive_bytes=stored_archive([{'size':10,'stored':0}]))
    add('stored-size-greater-than-nonzero-stored',[],SEMANTIC,archive_bytes=stored_archive([{'data':b'abc','size':5,'stored':3}]))
    add('stored-size-greater-with-wrong-crc',[],SEMANTIC,archive_bytes=stored_archive([{'data':b'abc','size':5,'stored':3,'crc':1}]))
    add('stored-size-less-than-stored-full-crc',[],SEMANTIC,archive_bytes=stored_archive([{'data':b'abcde','size':3,'stored':5}]))
    add('stored-size-less-than-stored-prefix-crc',[],SEMANTIC,archive_bytes=stored_archive([{'data':b'abcde','size':3,'stored':5,'crc':zlib.crc32(b'abc')}]))
    add('stored-nonempty-control',[],'accepted',archive_bytes=stored_archive([{'data':b'abc'}]))
    add('stored-wrong-crc',[],SEMANTIC,archive_bytes=stored_archive([{'data':b'abc','crc':1}]))
    add('stored-data-truncated',[],SEMANTIC,archive_bytes=stored_archive([{'data':b'ab','size':3,'stored':3}]))
    add('stored-size-mismatch-after-path-budget',[],RESOURCE,archive_bytes=stored_archive([{'name':b'b'*4097,'size':10,'stored':0}]))
    add('stored-size-mismatch-before-later-path-budget',[],SEMANTIC,archive_bytes=stored_archive([{'name':b'a','size':10,'stored':0},{'name':b'b'*4097}]))
    add('later-size-budget-before-earlier-size-mismatch',[],RESOURCE,archive_bytes=stored_archive([{'name':b'a','size':10,'stored':0},{'name':b'b','size':100_000_000,'stored':0}]))
    for length in (4,12,20):
        extra=struct.pack('<HH',1,length)+b'\0'*length
        add(f'volume-{length}-same-entry-path-budget',[entry(b'b'*4097,disk=0xffff,extra=extra)],RESOURCE)
        add(f'volume-{length}-later-entry-path-budget',[entry(b'b'*4097),entry(b'c',disk=0xffff,extra=extra)],RESOURCE)
    # Unicode Path extra fields are forbidden by the profile; their contents
    # cannot preempt the ordered stored-name budget on newer archive libraries.
    def unicode_extra(name, payload=b'', *, version=1, crc=None):
        body=struct.pack('<BI',version,zlib.crc32(name) if crc is None else crc)+payload
        return struct.pack('<HH',0x7075,len(body))+body
    long=b'b'*4097;empty_unicode=struct.pack('<HH',0x7075,0)
    add('unicode-empty-same-entry-before-path-budget',[entry(long,extra=empty_unicode)],RESOURCE)
    add('unicode-empty-later-entry-after-path-budget',[entry(long),entry(b'c',extra=empty_unicode)],RESOURCE)
    add('unicode-short-header-before-path-budget',[entry(long,extra=struct.pack('<HHI',0x7075,4,0))],RESOURCE)
    add('unicode-invalid-utf8-same-entry-before-path-budget',[entry(long,extra=unicode_extra(long,b'\xff'))],RESOURCE)
    add('unicode-invalid-utf8-later-entry-after-path-budget',[entry(long),entry(b'c',extra=unicode_extra(b'c',b'\xff'))],RESOURCE)
    add('unicode-valid-rename-same-entry-before-path-budget',[entry(long,extra=unicode_extra(long,b'x'))],RESOURCE)
    add('unicode-valid-rename-later-entry-after-path-budget',[entry(long),entry(b'c',extra=unicode_extra(b'c',b'x'))],RESOURCE)
    add('unicode-identical-name-before-path-budget',[entry(long,extra=unicode_extra(long,long))],RESOURCE)
    add('unicode-mismatched-crc-invalid-utf8-ignored',[entry(long,extra=unicode_extra(long,b'\xff',crc=0))],RESOURCE)
    add('unicode-other-version-invalid-utf8-ignored',[entry(long,extra=unicode_extra(long,b'\xff',version=2))],RESOURCE)
    add('unicode-under-budget-always-refused',[entry(b'a',extra=empty_unicode)],SEMANTIC)
    add('unicode-valid-rename-under-budget-refused',[entry(b'a',extra=unicode_extra(b'a',b'x'))],SEMANTIC)
    add('unicode-name-at-budget-extra-still-refused',[entry(b'b'*4096,extra=unicode_extra(b'b'*4096,b'x'))],SEMANTIC)
    add('earlier-profile-before-later-unicode-path-budget',[entry(b'a',disk=1),entry(long,extra=empty_unicode)],SEMANTIC)
    bad_local=bytearray(archive([entry(b'a'),entry(long,extra=empty_unicode)]))
    struct.pack_into('<I',bad_local,0,0)
    add('earlier-local-header-before-later-unicode-path-budget',[],SEMANTIC,archive_bytes=bytes(bad_local))
    add('structurally-truncated-unicode-extra-before-path-budget',[entry(long,extra=struct.pack('<HHB',0x7075,10,0))],SEMANTIC)
    add('size-budget-before-unicode-content',[entry(b'a',size=100_000_000,extra=empty_unicode)],RESOURCE)
    add('nul-name-before-unicode-path-budget',[entry(b'a\x00'+long,extra=unicode_extra(b'a\x00'+long,b'x'))],SEMANTIC)
    prefix_crc = zlib.crc32(b'abc')
    mismatch = {'name':b'a','data':b'abcde','size':3,'stored':5,'crc':prefix_crc}
    add('stored-extra-bytes-before-later-path-budget',[],SEMANTIC,archive_bytes=stored_archive([mismatch,{'name':b'b'*4097}]))
    add('stored-extra-bytes-same-member-path-budget',[],RESOURCE,archive_bytes=stored_archive([{**mismatch,'name':b'b'*4097}]))
    add('stored-extra-bytes-later-size-budget-first',[],RESOURCE,archive_bytes=stored_archive([mismatch,{'name':b'b','size':100_000_000}]))
    add('stored-two-members-at-path-limit',[],'accepted',archive_bytes=stored_archive([{'name':b'a','data':b'abc'},{'name':b'b'*4096}]))
    return {'schema_version':'archive_metadata_boundary_cases_v1' ,'limits_note':'Explicit common test profile; library defaults remain unchanged. No member content is allocated for declared sizes.','cases':rows}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    target=ROOT/'tests/fixtures/archive-metadata-boundaries.json';encoded=json.dumps(build(),indent=2)+'\n'
    if args.check:
        if not target.is_file() or target.read_text()!=encoded:raise SystemExit('archive metadata fixtures are stale')
    else:target.write_text(encoded)
    print('archive metadata fixtures: '+('current' if args.check else 'written'))

if __name__=='__main__':main()
