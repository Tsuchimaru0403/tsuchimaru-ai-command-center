"""Synthetic-only independent case reproduction for the three v0.3 MINOR fixes.

Do not import or run Gate Q itself. All archives are inert disposable fixtures.
"""
import io
import json
import re
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

import gateq_ci_prototype as g
from test_synthetic import j, zip_bytes


def patch_member(raw, name, *, declared_size=None, declared_crc=None, bad_deflate=False):
    """Adjust ZIP local and central metadata, retaining the original deflate stream."""
    data = bytearray(raw)
    off = 0
    hit = None
    while True:
        off = data.find(b'PK\x01\x02', off)
        if off < 0:
            break
        nl, el, cl = struct.unpack_from('<HHH', data, off + 28)
        if data[off + 46:off + 46 + nl] == name.encode('utf-8'):
            hit = off
            break
        off += 46 + nl + el + cl
    if hit is None:
        raise ValueError('central directory entry not found')
    loc = struct.unpack_from('<I', data, hit + 42)[0]
    assert data[loc:loc+4] == b'PK\x03\x04'
    if declared_size is not None:
        struct.pack_into('<I', data, hit + 24, declared_size)
        struct.pack_into('<I', data, loc + 22, declared_size)
    if declared_crc is not None:
        struct.pack_into('<I', data, hit + 16, declared_crc)
        struct.pack_into('<I', data, loc + 14, declared_crc)
    if bad_deflate:
        assert struct.unpack_from('<H', data, hit + 10)[0] == zipfile.ZIP_DEFLATED
        namelen, extralen = struct.unpack_from('<HH', data, loc + 26)
        start = loc + 30 + namelen + extralen
        data[start] = 0xFF  # invalid DEFLATE block type
    return bytes(data)


class V03RegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='gateq-v03-synthetic-')
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def fixture(self, raw):
        (self.root/'SYNTHETIC_ONLY.json').write_bytes(j({'fixture_format':'gateq-synthetic-v0.1','synthetic':True}))
        (self.root/'expected.json').write_bytes(j({'zip_sha256':g.digest(raw),'status':'UNVERIFIED'}))
        (self.root/'state.json').write_bytes(j({'schema_version':2,'stage':'v1.55 R2','candidate_status':'CANDIDATE',
            'design_locked':True,'gate_q_locked':False,'runtime_authorized':False,
            'owner_trust':'UNESTABLISHED','bootstrap_trust':'UNESTABLISHED','source_trust':'UNVERIFIED',
            'open_blockers':sorted(g.BLOCKERS)}))
        (self.root/'candidate.zip').write_bytes(raw)

    def test_01_M01_hidden_deflate_payload_fails(self):
        fake_data = b'A_HIDDEN_PAYLOAD'
        manifest = {'format':'synthetic-manifest-1','files':[
            {'name':'Content.txt','size':1,'sha256':g.digest(b'A')} ]}
        raw = zip_bytes([('Content.txt',fake_data)], manifest)
        raw = patch_member(raw,'Content.txt',declared_size=1, declared_crc=zlib.crc32(b'A'))
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            self.assertEqual(z.read('Content.txt'),b'A')  # reproduce v0.2 failure
        self.fixture(raw)
        with self.assertRaisesRegex(g.Reject,'size/stream boundary mismatch'):
            g.verify(self.root)

    def test_02_M01_hidden_manifest_bytes_fails(self):
        raw = zip_bytes([('Content.txt',b'A')])
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            original = z.read('MANIFEST.json')
        self.assertTrue(original.startswith(b'{'))
        self.fixture(patch_member(raw,'MANIFEST.json',declared_size=1,declared_crc=zlib.crc32(b'{')))
        with self.assertRaisesRegex(g.Reject,'size/stream boundary mismatch'):
            g.verify(self.root)

    def test_03_M02_bad_deflate_produces_fail_closed_JSON(self):
        raw = zip_bytes([('Content.txt',b'A')])
        self.fixture(patch_member(raw,'Content.txt',bad_deflate=True))
        cmd = [sys.executable, str(Path(g.__file__).resolve()), '--fixture-dir',str(self.root),'--mode','synthetic']
        out = subprocess.run(cmd,capture_output=True,text=True,check=False)
        self.assertEqual(out.returncode,1)
        result = json.loads(out.stdout)
        self.assertEqual(result['status'],'FAIL_CLOSED')
        self.assertNotIn('Traceback',out.stderr)

    def test_04_M01_truncated_compressed_stream_fails(self):
        raw = zip_bytes([('Content.txt',b'This is a test'*7)])
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            ci=z.getinfo('Content.txt'); comp=ci.compress_size
        data=bytearray(raw)
        cd=data.find(b'PK\x01\x02'); self.assertGreaterEqual(cd,0)
        loc=struct.unpack_from('<I',data,cd+42)[0]
        struct.pack_into('<I',data,cd+20,comp-1)
        struct.pack_into('<I',data,loc+18,comp-1)
        self.fixture(bytes(data))
        with self.assertRaises(g.Reject): g.verify(self.root)

    def test_05_M01_stored_member_ok(self):
        raw=io.BytesIO()
        with zipfile.ZipFile(raw,'w',compression=zipfile.ZIP_STORED) as z:
            z.writestr('Content.txt',b'A')
            z.writestr('MANIFEST.json',j({'format':'synthetic-manifest-1','files':[
                {'name':'Content.txt','size':1,'sha256':g.digest(b'A')}]}))
        self.fixture(raw.getvalue())
        self.assertEqual(g.verify(self.root)['status'],'SYNTHETIC_STRUCTURE_PASS_UNVERIFIED')

    def test_06_M01_forced_ZIP64_local_header_ok(self):
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_DEFLATED) as z:
            with z.open('Content.txt','w',force_zip64=True) as f:
                f.write(b'A')
            z.writestr('MANIFEST.json',j({'format':'synthetic-manifest-1','files':[
                {'name':'Content.txt','size':1,'sha256':g.digest(b'A')}]}))
        self.fixture(out.getvalue())
        self.assertEqual(g.verify(self.root)['status'],'SYNTHETIC_STRUCTURE_PASS_UNVERIFIED')

    def test_07_M01_CRC_mismatch_is_rejected(self):
        raw=zip_bytes([('Content.txt',b'A')])
        self.fixture(patch_member(raw,'Content.txt',declared_crc=0))
        with self.assertRaisesRegex(g.Reject,'CRC mismatch'):
            g.verify(self.root)

    def test_08_M02_corrupt_manifest_also_fails_closed_JSON(self):
        raw=zip_bytes([('Content.txt',b'A')])
        self.fixture(patch_member(raw,'MANIFEST.json',bad_deflate=True))
        cmd=[sys.executable,str(Path(g.__file__).resolve()),'--fixture-dir',str(self.root),'--mode','synthetic']
        out=subprocess.run(cmd,capture_output=True,text=True,check=False)
        self.assertEqual(out.returncode,1)
        self.assertEqual(json.loads(out.stdout)['status'],'FAIL_CLOSED')
        self.assertNotIn('Traceback',out.stderr)

    def test_09_M01_trailing_bytes_after_deflate_stream_are_rejected(self):
        # Add bytes *inside the declared compressed span* after the DEFLATE
        # end marker, then shift the central directory accordingly.
        raw=zip_bytes([('Content.txt',b'A')])
        data=bytearray(raw)
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            info=z.getinfo('Content.txt')
        loc=info.header_offset
        nl,el=struct.unpack_from('<HH', data,loc+26)
        comp_start=loc+30+nl+el
        comp_end=comp_start+info.compress_size
        data[comp_end:comp_end]=b'JUNK'
        cd=data.find(b'PK\x01\x02',comp_end+4)
        self.assertGreater(cd,0)
        struct.pack_into('<I',data,loc+18,info.compress_size+4)
        struct.pack_into('<I',data,cd+20,info.compress_size+4)
        # The following local header also moves when the compressed span grows.
        next_cd=cd+46+sum(struct.unpack_from('<HHH',data,cd+28))
        self.assertEqual(data[next_cd:next_cd+4],b'PK\x01\x02')
        next_local_offset=struct.unpack_from('<I',data,next_cd+42)[0]
        struct.pack_into('<I',data,next_cd+42,next_local_offset+4)
        eocd=data.rfind(b'PK\x05\x06')
        self.assertGreater(eocd,0)
        old_cd_offset=struct.unpack_from('<I',data,eocd+16)[0]
        struct.pack_into('<I',data,eocd+16,old_cd_offset+4)
        self.fixture(bytes(data))
        with self.assertRaisesRegex(g.Reject,'size/stream boundary mismatch'):
            g.verify(self.root)

    def test_10_M03_workflow_action_references_exact_pins(self):
        workflow=(Path(__file__).parent/'gateq-synthetic-preflight.workflow.DRAFT.yml').read_text()
        uses=re.findall(r'^\s+- uses: (.+?)(?:\s+#.*)?$',workflow,re.MULTILINE)
        self.assertEqual(uses,[
            'actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683',
            'actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065'])
        for use in uses:
            self.assertRegex(use, r'^[\w-]+/[\w-]+@[0-9a-f]{40}$')
        self.assertIn('contents: read',workflow)
        self.assertNotIn('pull_request_target:',workflow)
        self.assertNotIn('secrets.',workflow)
        self.assertIn('NOT-REQUIRED', workflow)

    def test_11_M01_single_zip_snapshot_used(self):
        import inspect
        source=inspect.getsource(g.verify)
        self.assertIn('ZipFile(io.BytesIO(raw))',source)
        self.assertIn('read_verified_member(raw,',source)
        self.assertNotIn('z.read(',source)

if __name__=='__main__':
    unittest.main(verbosity=2)
