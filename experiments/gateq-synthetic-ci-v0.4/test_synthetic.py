"""Adversarial test set. All files generated in disposable OS temporary space."""
import io, json, os, subprocess, sys, tempfile, unittest, zipfile
from pathlib import Path
import gateq_ci_prototype as g

def j(obj): return json.dumps(obj,sort_keys=True,separators=(',',':')).encode()

def zip_bytes(files,manifest=None):
    if manifest is None: manifest={'format':'synthetic-manifest-1','files':[
        {'name':n,'size':len(b),'sha256':g.digest(b)} for n,b in files]}
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for n,b in files:z.writestr(n,b)
        z.writestr('MANIFEST.json',j(manifest))
    return buf.getvalue()

class SyntheticTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='gateq-synthetic-')
        self.root=Path(self.temp.name)
        self.files=[('Controller.ps1',b'# synthetic inert bytes'),('Contract.json',b'{}')]
        self.zip=zip_bytes(self.files)
        self.marker={'fixture_format':'gateq-synthetic-v0.1','synthetic':True}
        self.expected={'zip_sha256':g.digest(self.zip),'status':'UNVERIFIED'}
        self.state={'schema_version':2,'stage':'v1.55 R2','candidate_status':'CANDIDATE',
            'design_locked':True,'gate_q_locked':False,'runtime_authorized':False,
            'owner_trust':'UNESTABLISHED','bootstrap_trust':'UNESTABLISHED',
            'source_trust':'UNVERIFIED','open_blockers':sorted(g.BLOCKERS)}
        self.save()
    def tearDown(self): self.temp.cleanup()
    def save(self):
        for n,body in [('SYNTHETIC_ONLY.json',j(self.marker)),('expected.json',j(self.expected)),
                        ('state.json',j(self.state)),('candidate.zip',self.zip)]:
            (self.root/n).write_bytes(body)
    def bad(self):
        self.save()
        with self.assertRaises(g.Reject):g.verify(self.root)
    def changed_zip(self,files,manifest=None):
        self.zip=zip_bytes(files,manifest)
        self.expected['zip_sha256']=g.digest(self.zip)
        self.bad()
    def test_01_good_synthetic_stays_hold(self):
        r=g.verify(self.root)
        self.assertEqual(r['status'],'SYNTHETIC_STRUCTURE_PASS_UNVERIFIED')
        self.assertFalse(r['canonical'])
        self.assertFalse(r['runtime_authorized'])
    def test_02_does_not_change_inputs(self):
        before={p.name:g.digest(p.read_bytes()) for p in self.root.iterdir()}
        g.verify(self.root)
        after={p.name:g.digest(p.read_bytes()) for p in self.root.iterdir()}
        self.assertEqual(before,after)
    def test_03_marker_not_synthetic(self): self.marker['synthetic']=False;self.bad()
    def test_04_marker_missing(self):
        (self.root/'SYNTHETIC_ONLY.json').unlink()
        with self.assertRaises(g.Reject):g.verify(self.root)
    def test_05_modified_zip(self): self.zip+=b'evil';self.bad()
    def test_06_hash_wrong(self): self.expected['zip_sha256']='0'*64;self.bad()
    def test_07_external_claims_trusted(self): self.expected['status']='VERIFIED';self.bad()
    def test_08_stale_v145(self): self.state['stage']='v1.45';self.bad()
    def test_09_old_state_schema(self): self.state['schema_version']=1;self.bad()
    def test_10_design_lock_false(self): self.state['design_locked']=False;self.bad()
    def test_11_gate_locked_true(self): self.state['gate_q_locked']=True;self.bad()
    def test_12_runtime_approved_true(self): self.state['runtime_authorized']=True;self.bad()
    def test_13_promoted_to_canonical(self): self.state['candidate_status']='CANONICAL';self.bad()
    def test_14_owner_claims_established(self): self.state['owner_trust']='ESTABLISHED';self.bad()
    def test_15_bootstrap_claims_established(self): self.state['bootstrap_trust']='ESTABLISHED';self.bad()
    def test_16_hide_six_blockers(self): self.state['open_blockers']=[];self.bad()
    def test_17_duplicate_state_json_keys(self):
        (self.root/'state.json').write_bytes(b'{"stage":"v1.55 R2","stage":"v1.55 R2"}')
        with self.assertRaises(g.Reject):g.verify(self.root)
    def test_18_fake_manifest_hash(self):
        m={'format':'synthetic-manifest-1','files':[
            {'name':n,'size':len(b),'sha256':'0'*64} for n,b in self.files]}
        self.changed_zip(self.files,m)
    def test_19_fake_manifest_size(self):
        m={'format':'synthetic-manifest-1','files':[
            {'name':n,'size':len(b)+1,'sha256':g.digest(b)} for n,b in self.files]}
        self.changed_zip(self.files,m)
    def test_20_manifest_missing_member(self):
        n,b=self.files[0]
        self.changed_zip(self.files,{'format':'synthetic-manifest-1','files':[
            {'name':n,'size':len(b),'sha256':g.digest(b)}]})
    def test_21_traversal_member(self): self.changed_zip(self.files+[('../bad.txt',b'bad')])
    def test_22_windows_drive_member(self): self.changed_zip(self.files+[('C:bad.txt',b'bad')])
    def test_23_case_alias_member(self): self.changed_zip(self.files+[('controller.ps1',b'alias')])
    def test_24_duplicate_member(self): self.changed_zip(self.files+[self.files[0]])
    def test_25_zip_symlink(self):
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w') as z:
            info=zipfile.ZipInfo('link.txt');info.create_system=3;info.external_attr=0o120777<<16
            z.writestr(info,b'bad')
            z.writestr('MANIFEST.json',j({'format':'synthetic-manifest-1','files':[
                {'name':'link.txt','size':3,'sha256':g.digest(b'bad')}]}))
        self.zip=buf.getvalue();self.expected['zip_sha256']=g.digest(self.zip);self.bad()
    def test_26_invalid_zip(self): self.zip=b'notzip';self.expected['zip_sha256']=g.digest(self.zip);self.bad()
    def test_27_manifest_format_unknown(self):
        m={'format':'nope','files':[{'name':n,'size':len(b),'sha256':g.digest(b)} for n,b in self.files]}
        self.changed_zip(self.files,m)
    def test_28_excessive_file(self): self.changed_zip([('big.txt',os.urandom(300_001))])
    def test_29_synthetic_exit_codes(self):
        args=[sys.executable,str(Path(g.__file__).resolve()),'--fixture-dir',str(self.root),'--mode','synthetic']
        ok=subprocess.run(args,capture_output=True,text=True,check=False)
        self.assertEqual(ok.returncode,0)
        self.assertEqual(json.loads(ok.stdout)['status'],'SYNTHETIC_STRUCTURE_PASS_UNVERIFIED')
        self.expected['zip_sha256']='0'*64;self.save()
        fail=subprocess.run(args,capture_output=True,text=True,check=False)
        self.assertEqual(fail.returncode,1)
        self.assertEqual(json.loads(fail.stdout)['status'],'FAIL_CLOSED')

    def test_30_trusted_mode_always_blocked(self):
        args=[sys.executable,str(Path(g.__file__).resolve()),'--fixture-dir',str(self.root),'--mode','trusted']
        r=subprocess.run(args,capture_output=True,text=True,check=False)
        self.assertEqual(r.returncode,2)
        self.assertEqual(json.loads(r.stdout)['status'],'BLOCKED_UNESTABLISHED_TRUST_ROOT')

    def test_31_missing_mode_cannot_pass(self):
        args=[sys.executable,str(Path(g.__file__).resolve()),'--fixture-dir',str(self.root)]
        r=subprocess.run(args,capture_output=True,text=True,check=False)
        self.assertNotEqual(r.returncode,0)

    def test_32_synthetic_result_never_authorizes(self):
        r=g.verify(self.root)
        self.assertFalse(r['required_check_eligible'])
        self.assertFalse(r['trusted_origin'])
        self.assertFalse(r['may_authorize_runtime'])
        self.assertEqual(r['provenance'],'UNVERIFIED')

    def test_33_replace_disk_zip_during_verification(self):
        # Simulate a path swap immediately after snapshot read. Zip parser must
        # consume exactly the validated initial bytes, never reopen path.
        initial=self.zip
        other=zip_bytes([('Bogus.txt',b'unrelated')])
        original=g.limited
        def swap_after_read(path,max_bytes):
            data=original(path,max_bytes)
            if path.name=='candidate.zip':
                path.write_bytes(other)
            return data
        from unittest.mock import patch
        with patch.object(g,'limited',side_effect=swap_after_read):
            r=g.verify(self.root)
        self.assertEqual(r['status'],'SYNTHETIC_STRUCTURE_PASS_UNVERIFIED')
        self.assertEqual(r['payloads'],2)
        self.assertNotEqual(initial, (self.root/'candidate.zip').read_bytes())
        # Same path with the swapped file must fail on a second verification.
        with self.assertRaises(g.Reject):g.verify(self.root)

    def test_34_consistent_but_untrusted_zip_is_not_canonical(self):
        self.zip=zip_bytes([('Arbitrary.txt',b'any')])
        self.expected['zip_sha256']=g.digest(self.zip)
        self.save()
        r=g.verify(self.root)
        self.assertFalse(r['canonical'])
        self.assertFalse(r['required_check_eligible'])
        self.assertEqual(r['provenance'],'UNVERIFIED')

    def test_35_windows_CON_name(self): self.changed_zip(self.files+[('CON.txt',b'evil')])
    def test_36_windows_PRN_name(self): self.changed_zip(self.files+[('prn.config',b'evil')])
    def test_37_windows_COM9_name(self): self.changed_zip(self.files+[('COM9.log',b'evil')])
    def test_38_windows_LPT1_name(self): self.changed_zip(self.files+[('LPT1.txt',b'evil')])
    def test_39_windows_reserved_superscript(self): self.changed_zip(self.files+[('COM¹.txt',b'evil')])
    def test_40_trailing_period(self): self.changed_zip(self.files+[('hello.',b'evil')])
    def test_41_trailing_space(self): self.changed_zip(self.files+[('hello ',b'evil')])
    def test_42_direction_control(self): self.changed_zip(self.files+[('a\u202etxt',b'evil')])
    def test_43_windows_unsafe_separator(self): self.changed_zip(self.files+[('foo\\bar',b'evil')])
    def test_44_fullwidth_alias(self): self.changed_zip(self.files+[('ＣＯＮ.txt',b'evil')])
    def test_45_device_extensionless(self): self.changed_zip(self.files+[('NUL',b'evil')])
    def test_46_too_long_name(self): self.changed_zip(self.files+[('x'*102+'.txt',b'evil')])
    def test_47_zip_must_be_validated_from_same_raw_snapshot(self):
        import inspect
        source=inspect.getsource(g.verify)
        self.assertIn('ZipFile(io.BytesIO(raw))',source)
        self.assertNotIn('ZipFile(path)',source)

if __name__=='__main__':unittest.main(verbosity=2)
