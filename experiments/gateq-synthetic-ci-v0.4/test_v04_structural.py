"""MAJOR-SYN-01 synthetic ZIP structure regression fixtures. No actual Gate Q access."""
import io
import json
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import gateq_ci_prototype as g
from test_synthetic import j, zip_bytes

EOCD=b'PK\x05\x06'; CENTRAL=b'PK\x01\x02'; LOCAL=b'PK\x03\x04'


def entries(raw):
    result=[]
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        infos=z.infolist()
    for info in infos:
        off=info.header_offset
        n,extra=struct.unpack_from('<HH',raw,off+26)
        result.append((info,off,off+30+n+extra))
    return result


def central_entry(raw,name):
    cursor=0
    while True:
        cursor=raw.find(CENTRAL,cursor)
        if cursor==-1: raise ValueError('central not found')
        n,e,c=struct.unpack_from('<HHH',raw,cursor+28)
        if raw[cursor+46:cursor+46+n] == name.encode():return cursor
        cursor+=46+n+e+c


class FakedZIPBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='gateq-v04-N-')
        self.root=Path(self.tmp.name)
        self.good=zip_bytes([('Content.txt',b'Alpha')])

    def tearDown(self): self.tmp.cleanup()

    def make(self,raw):
        self.root.joinpath('SYNTHETIC_ONLY.json').write_bytes(j({'fixture_format':'gateq-synthetic-v0.1','synthetic':True}))
        self.root.joinpath('expected.json').write_bytes(j({'zip_sha256':g.digest(raw),'status':'UNVERIFIED'}))
        self.root.joinpath('state.json').write_bytes(j({'schema_version':2,'stage':'v1.55 R2','candidate_status':'CANDIDATE','design_locked':True,'gate_q_locked':False,'runtime_authorized':False,'owner_trust':'UNESTABLISHED','bootstrap_trust':'UNESTABLISHED','source_trust':'UNVERIFIED','open_blockers':sorted(g.BLOCKERS)}))
        self.root.joinpath('candidate.zip').write_bytes(raw)

    def fail(self,raw,expr='ZIP'):
        self.make(raw)
        with self.assertRaisesRegex(g.Reject,expr):g.verify(self.root)

    def ok(self,raw):
        self.make(raw)
        val=g.verify(self.root)
        self.assertEqual(val['status'],'SYNTHETIC_STRUCTURE_PASS_UNVERIFIED')
        self.assertFalse(val['required_check_eligible'])
        self.assertFalse(val['may_authorize_runtime'])

    def test_N1_extra_data_after_EOCD_fails(self):
        self.fail(self.good+b'UNREFERENCED', 'ZIP EOCD')

    def test_N2_local_CRC_disagrees_fails(self):
        v=bytearray(self.good)
        info,off,_=entries(self.good)[0]
        struct.pack_into('<I',v,off+14, info.CRC ^ 1)
        self.fail(bytes(v),'ZIP local/central')

    def test_N3_local_expanded_size_disagrees_fails(self):
        v=bytearray(self.good)
        info,off,_=entries(self.good)[0]
        struct.pack_into('<I',v,off+22, info.file_size+1)
        self.fail(bytes(v),'ZIP local/central')

    def test_N4_missing_descriptor_fails(self):
        v=bytearray(self.good)
        info,off,_=entries(self.good)[0]
        struct.pack_into('<H',v,off+6, info.flag_bits | 0x8)
        cd=central_entry(v,'Content.txt')
        struct.pack_into('<H',v,cd+8, info.flag_bits|0x8)
        self.fail(bytes(v),'ZIP missing/mismatched Data Descriptor')

    def test_N5_valid_standard_zip(self):self.ok(self.good)

    def test_N6_valid_forced_zip64_local(self):
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_DEFLATED) as z:
            with z.open('Content.txt','w',force_zip64=True) as f:f.write(b'Alpha')
            z.writestr('MANIFEST.json',j({'format':'synthetic-manifest-1','files':[{'name':'Content.txt','size':5,'sha256':g.digest(b'Alpha')}]}))
        self.ok(out.getvalue())

    def test_N7_valid_zip64_eocd(self):
        data=bytearray(self.good)
        eocd=data.rfind(EOCD)
        self.assertGreater(eocd,0)
        n=struct.unpack_from('<H',data,eocd+10)[0]
        cdsize=struct.unpack_from('<I',data,eocd+12)[0]
        cdoff=struct.unpack_from('<I',data,eocd+16)[0]
        # Keep central-directory bytes untouched; add valid ZIP64 EOCD + locator.
        record=struct.pack('<IQHHIIQQQQ',g.ZIP64_EOCD,44,45,45,0,0,n,n,cdsize,cdoff)
        locator=struct.pack('<IIQI',g.ZIP64_LOCATOR,0,eocd,1)
        data[eocd:eocd]=record+locator
        eocd+=len(record)+len(locator)
        struct.pack_into('<H',data,eocd+8,0xffff)
        struct.pack_into('<H',data,eocd+10,0xffff)
        struct.pack_into('<I',data,eocd+12,0xffffffff)
        struct.pack_into('<I',data,eocd+16,0xffffffff)
        self.ok(bytes(data))

    def test_N8_valid_descriptor_no_signature(self):
        data=bytearray(self.good)
        cd_first=data.find(CENTRAL)
        self.assertGreater(cd_first,0)
        descs=[]
        # insert from end to start so positions known in final by relocation
        offsets=[]
        with zipfile.ZipFile(io.BytesIO(self.good)) as z:infos=z.infolist()
        for info in infos:
            lo=info.header_offset
            nl,el=struct.unpack_from('<HH',data,lo+26)
            end=lo+30+nl+el+info.compress_size
            offsets.append((lo,end,info))
        for lo,end,info in reversed(offsets):
            desc=struct.pack('<III',info.CRC,info.compress_size,info.file_size)
            data[end:end]=desc
        # Patch local flags by (old offsets + size of earlier inserted trailers)
        for ix,(lo,end,info) in enumerate(offsets):
            loc=lo+12*ix
            struct.pack_into('<H',data,loc+6,info.flag_bits|0x8)
            # local CRC and sizes may be zero if streamed
            struct.pack_into('<III',data,loc+14,0,0,0)
        shift=12*len(offsets)
        current_cd=cd_first+shift
        for ix,(lo,end,info) in enumerate(offsets):
            c=central_entry(data,info.filename)
            struct.pack_into('<H',data,c+8,info.flag_bits|0x8)
            struct.pack_into('<I',data,c+42,lo+12*ix)
        eo=data.rfind(EOCD)
        struct.pack_into('<I',data,eo+16,cd_first+shift)
        self.ok(bytes(data))

    def test_N9_bad_descriptor_crc_fails(self):
        # Derive from a valid non-seekable ZIP with genuine data descriptors.
        class NoSeek(io.BytesIO):
            def seek(self,*a):raise OSError('no seek')
        out=NoSeek()
        with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('Content.txt',b'Alpha')
            z.writestr('MANIFEST.json',j({'format':'synthetic-manifest-1','files':[{'name':'Content.txt','size':5,'sha256':g.digest(b'Alpha')}]}))
        raw=out.getvalue()
        self.ok(raw)
        v=bytearray(raw)
        info,off,start=entries(raw)[0]
        d=start+info.compress_size
        if v[d:d+4]==b'PK\x07\x08': d+=4
        struct.pack_into('<I',v,d,info.CRC^1)
        self.fail(bytes(v),'ZIP missing/mismatched Data Descriptor')

    def test_N10_trailing_junk_before_central_fails(self):
        data=bytearray(self.good)
        eocd=data.rfind(EOCD)
        cd=struct.unpack_from('<I',data,eocd+16)[0]
        data[cd:cd]=b'GAP!'
        eocd+=4
        struct.pack_into('<I',data,eocd+16,cd+4)
        self.fail(bytes(data),'ZIP unreferenced')

    def test_N11_duplicate_central_entry_count_disagrees_fails(self):
        v=bytearray(self.good)
        eo=v.rfind(EOCD)
        struct.pack_into('<H',v,eo+10,3)
        struct.pack_into('<H',v,eo+8,3)
        self.fail(bytes(v),'ZIP entry count mismatch')

    def test_N12_local_timestamp_disagrees_fails(self):
        v=bytearray(self.good)
        _,off,_=entries(self.good)[0]
        mtime=struct.unpack_from('<H',v,off+10)[0]
        struct.pack_into('<H',v,off+10,mtime^1)
        self.fail(bytes(v),'ZIP local/central')

    def test_N13_normal_ZIP_comment_allowed(self):
        v=bytearray(self.good)
        eo=v.rfind(EOCD)
        struct.pack_into('<H',v,eo+20,3)
        v+=b'abc'
        self.ok(bytes(v))

    def test_N14_bad_EOCD_zip64_locator_fails(self):
        v=bytearray(self.good)
        eo=v.rfind(EOCD)
        struct.pack_into('<I',v,eo+12,0xffffffff)
        self.fail(bytes(v),'ZIP')

    def test_N15_stored_empty_file_allowed(self):
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_STORED) as z:
            z.writestr('Zero.txt',b'')
            z.writestr('MANIFEST.json',j({'format':'synthetic-manifest-1','files':[{'name':'Zero.txt','size':0,'sha256':g.digest(b'')}]}))
        self.ok(out.getvalue())

    def test_N16_CLI_structure_failure_JSON(self):
        self.make(self.good+b'EVIL')
        cmd=[sys.executable,str(Path(g.__file__).resolve()),'--mode','synthetic','--fixture-dir',str(self.root)]
        run=subprocess.run(cmd,capture_output=True,text=True)
        self.assertEqual(run.returncode,1)
        self.assertEqual(json.loads(run.stdout)['status'],'FAIL_CLOSED')
        self.assertNotIn('Traceback',run.stderr)

if __name__=='__main__':unittest.main(verbosity=2)
