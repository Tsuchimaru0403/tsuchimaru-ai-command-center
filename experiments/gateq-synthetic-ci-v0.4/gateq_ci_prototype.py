#!/usr/bin/env python3
"""Gate Q synthetic-only package/state preflight. Never runs candidate code."""
import argparse
import hashlib
import io
import json
import re
import stat
import struct
import sys
import unicodedata
import zipfile
import zlib
from pathlib import Path

BLOCKERS = {'bootstrap_provenance','owner_enrollment','canonical_provenance',
            'snapshot_integrity','replay_counter','runtime_recovery'}
SHA64 = re.compile(r'^[0-9a-fA-F]{64}$')
# Deliberately limited to simple ASCII flat names. Nothing in ZIP is extracted.
SAFE_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$')
DEVICE_BASES = frozenset({'CON','PRN','AUX','NUL','CLOCK$'} |
                         {f'COM{i}' for i in range(10)} |
                         {f'LPT{i}' for i in range(10)})

class Reject(Exception): pass

def strict_json(data):
    def pairs(kvs):
        result = {}
        for k,v in kvs:
            if k in result: raise Reject('duplicate JSON key')
            result[k] = v
        return result
    try: return json.loads(data.decode('utf-8'), object_pairs_hook=pairs)
    except (ValueError, UnicodeError) as e: raise Reject(f'invalid JSON: {e}') from e

def limited(path, max_bytes):
    if path.is_symlink() or not path.is_file(): raise Reject('missing/symlink input')
    if path.stat().st_size > max_bytes: raise Reject('oversized input')
    # Bound *actual* bytes too: the pre-read size is not a security guarantee.
    with path.open('rb') as f:
        data = f.read(max_bytes + 1)
    if len(data) > max_bytes: raise Reject('oversized input')
    return data

def digest(data): return hashlib.sha256(data).hexdigest()

def valid_name(name):
    """Flat, portable, ASCII member names only (no Windows devices/aliases)."""
    return (isinstance(name, str) and bool(SAFE_NAME.fullmatch(name))
            and not name.endswith(('.', ' '))
            and name.split('.', 1)[0].upper() not in DEVICE_BASES
            and name == unicodedata.normalize('NFC', name))


MAX_EXPANDED_MEMBER = 300_000


def read_verified_member(raw, item):
    """Read exactly one bounded member from the authenticated ZIP byte snapshot.

    Do not use ZipFile.read(): it may stop after the size declared in the
    central directory without noticing further DEFLATE output. Instead
    consume the complete raw compressed stream, enforce end-of-stream and
    validate uncompressed size and CRC against the ZIP directory.
    """
    if item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise Reject('unsupported ZIP compression')
    pos = item.header_offset
    if pos < 0 or pos + 30 > len(raw):
        raise Reject('invalid local ZIP header')
    (signature, _version, flags, method, _time, _date, _crc, _packed_size,
     _unpacked_size, name_len, extra_len) = struct.unpack_from('<IHHHHHIIIHH', raw, pos)
    if signature != 0x04034B50 or flags != item.flag_bits or method != item.compress_type:
        raise Reject('ZIP local/central header mismatch')
    start = pos + 30 + name_len + extra_len
    if start > len(raw) or start + item.compress_size > len(raw):
        raise Reject('ZIP compressed data out of range')
    local_name = raw[pos + 30:pos + 30 + name_len]
    encoding = 'utf-8' if item.flag_bits & 0x800 else 'cp437'
    if local_name != item.filename.encode(encoding):
        raise Reject('ZIP local/central name mismatch')
    compressed = raw[start:start + item.compress_size]
    if item.compress_type == zipfile.ZIP_STORED:
        body = compressed
    else:
        inflater = zlib.decompressobj(-zlib.MAX_WBITS)
        try:
            # Bounded memory, including when the declared size lies.
            body = inflater.decompress(compressed, MAX_EXPANDED_MEMBER + 1)
        except zlib.error as exc:
            raise Reject('corrupt ZIP: zlib.error') from exc
        if (len(body) > MAX_EXPANDED_MEMBER or len(body) != item.file_size or
                not inflater.eof or inflater.unused_data or inflater.unconsumed_tail):
            raise Reject('ZIP DEFLATE size/stream boundary mismatch')
    if (len(body) > MAX_EXPANDED_MEMBER or len(body) != item.file_size or
            (zlib.crc32(body) & 0xFFFFFFFF) != item.CRC):
        raise Reject('ZIP uncompressed size/CRC mismatch')
    return body


# MAJOR-SYN-01: strict, bounded ZIP container layout verification. This
# intentionally accepts a small conventional subset of ZIP for inert demos;
# it is NOT a general-purpose ZIP unpacker, trust verifier or Gate Q runner.
ZIP_LOCAL = 0x04034B50
ZIP_CENTRAL = 0x02014B50
ZIP_EOCD = 0x06054B50
ZIP64_EOCD = 0x06064B50
ZIP64_LOCATOR = 0x07064B50
ZIP_DESCRIPTOR = 0x08074B50


def zip_extra_fields(data):
    out = {}
    cursor = 0
    while cursor < len(data):
        if cursor + 4 > len(data):
            raise Reject('malformed ZIP extra field')
        kind, count = struct.unpack_from('<HH', data, cursor)
        cursor += 4
        if cursor + count > len(data):
            raise Reject('malformed ZIP extra field')
        if kind in out:
            raise Reject('duplicate ZIP extra field')
        out[kind] = data[cursor:cursor + count]
        cursor += count
    return out


def zip64_values(extra, names):
    blob = extra.get(1)
    if blob is None:
        raise Reject('missing ZIP64 size/offset extra')
    cursor = 0
    values = {}
    for name in names:
        if cursor + 8 > len(blob):
            raise Reject('truncated ZIP64 extra')
        values[name] = struct.unpack_from('<Q', blob, cursor)[0]
        cursor += 8
    # Synthetic profile allows only the ZIP64 dimensions actually indicated
    # by legacy 0xffffffff sentinels; no unclaimed/ambiguous payload fields.
    if cursor != len(blob):
        raise Reject('unclaimed ZIP64 extra bytes')
    return values


def zip_eocd(raw):
    # EOCD must finish at EOF, including its legal comment. No appended bytes.
    candidates = []
    lower = max(0, len(raw) - (22 + 65535))
    for pos in range(len(raw) - 22, lower - 1, -1):
        if raw[pos:pos + 4] != b'PK\x05\x06':
            continue
        if pos + 22 > len(raw):
            continue
        comment_len = struct.unpack_from('<H', raw, pos + 20)[0]
        if pos + 22 + comment_len == len(raw):
            candidates.append(pos)
    if len(candidates) != 1:
        raise Reject('ZIP EOCD missing/ambiguous or trailing bytes')
    pos = candidates[0]
    (_, this_disk, cd_disk, entries_here, entries_total,
     cd_size, cd_offset, _) = struct.unpack_from('<IHHHHIIH', raw, pos)
    if this_disk or cd_disk or entries_here != entries_total:
        raise Reject('unsupported split ZIP archive')
    sentinel = (entries_total == 0xFFFF or cd_size == 0xFFFFFFFF or
                cd_offset == 0xFFFFFFFF)
    if sentinel:
        loc = pos - 20
        if loc < 0 or struct.unpack_from('<I', raw, loc)[0] != ZIP64_LOCATOR:
            raise Reject('missing ZIP64 EOCD locator')
        _, disk64, offset64, total_disks = struct.unpack_from('<IIQI', raw, loc)
        if disk64 != 0 or total_disks != 1 or offset64 + 56 > loc:
            raise Reject('unsupported ZIP64 locator/disk')
        signature, payload_size = struct.unpack_from('<IQ', raw, offset64)
        if signature != ZIP64_EOCD or payload_size < 44 or offset64 + 12 + payload_size != loc:
            raise Reject('bad ZIP64 EOCD boundary')
        ver_made, ver_need, dnum, dcnum, on_disk, all_entries, z_cdsize, z_cdoff = \
            struct.unpack_from('<HHIIQQQQ', raw, offset64 + 12)
        if dnum or dcnum or on_disk != all_entries:
            raise Reject('unsupported ZIP64 disk structure')
        if (entries_total != 0xFFFF and entries_total != all_entries or
            cd_size != 0xFFFFFFFF and cd_size != z_cdsize or
            cd_offset != 0xFFFFFFFF and cd_offset != z_cdoff):
            raise Reject('ZIP64 EOCD/legacy fields mismatch')
        entries_total, cd_size, cd_offset = all_entries, z_cdsize, z_cdoff
        cd_end = offset64
    else:
        # An unclaimed ZIP64 locator/record is not accepted.
        if pos >= 20 and raw[pos - 20:pos - 16] == b'PK\x06\x07':
            raise Reject('unclaimed ZIP64 locator')
        cd_end = pos
    if entries_total < 2 or entries_total > 20:
        raise Reject('invalid ZIP entry count')
    if cd_offset + cd_size != cd_end or cd_offset > cd_end:
        raise Reject('ZIP central directory boundary mismatch')
    return cd_offset, cd_end, entries_total


def validate_zip_container(raw, infos):
    """Reject gaps/overlaps and inconsistent EOCD, central, local, DD and ZIP64."""
    cd_start, cd_end, entry_count = zip_eocd(raw)
    if len(infos) != entry_count:
        raise Reject('ZIP entry count mismatch')
    cursor = cd_start
    layouts = []
    for item in infos:
        if cursor + 46 > cd_end:
            raise Reject('truncated ZIP central header')
        (sig, version_made, ver_needed, flags, method, mtime, mdate, crc,
         compressed, expanded, nlen, xlen, clen, disk, int_attrs,
         ext_attrs, local_pos) = struct.unpack_from('<IHHHHHHIIIHHHHHII', raw, cursor)
        if sig != ZIP_CENTRAL or disk != 0:
            raise Reject('unsupported ZIP central entry/disk')
        finish = cursor + 46 + nlen + xlen + clen
        if finish > cd_end:
            raise Reject('ZIP central entry overflow')
        name_bytes = raw[cursor + 46:cursor + 46 + nlen]
        xdata = raw[cursor + 46 + nlen:cursor + 46 + nlen + xlen]
        extra = zip_extra_fields(xdata)
        needed = []
        if expanded == 0xFFFFFFFF: needed.append('expanded')
        if compressed == 0xFFFFFFFF: needed.append('compressed')
        if local_pos == 0xFFFFFFFF: needed.append('offset')
        if 1 in extra and not needed:
            raise Reject('unclaimed ZIP64 central extra')
        found = zip64_values(extra, needed) if needed else {}
        expanded = found.get('expanded', expanded)
        compressed = found.get('compressed', compressed)
        local_pos = found.get('offset', local_pos)
        encoding = 'utf-8' if flags & 0x800 else 'cp437'
        try:
            central_name = name_bytes.decode(encoding)
        except UnicodeError as exc:
            raise Reject('invalid ZIP central filename encoding') from exc
        if (central_name != item.filename or crc != item.CRC or
            compressed != item.compress_size or expanded != item.file_size or
            local_pos != item.header_offset or flags != item.flag_bits or
            method != item.compress_type):
            raise Reject('ZIP central directory/parsed entries mismatch')
        if flags & ~0x8008:
            raise Reject('unsupported ZIP member flags')
        layouts.append((local_pos, ver_needed, flags, method, mtime, mdate, crc,
                        compressed, expanded, name_bytes))
        cursor = finish
    if cursor != cd_end:
        raise Reject('ZIP central directory trailing/unreferenced bytes')
    layouts.sort(key=lambda x: x[0])
    if layouts[0][0] != 0:
        raise Reject('ZIP unreferenced prefix before first member')
    for ix, (pos, ver_needed, flags, method, mtime, mdate, crc, compressed, expanded,
             name_bytes) in enumerate(layouts):
        boundary = layouts[ix + 1][0] if ix + 1 < len(layouts) else cd_start
        if not (pos >= 0 and pos + 30 <= boundary):
            raise Reject('ZIP overlapping/missing local entry')
        (sig, l_ver, lflags, lmethod, ltime, ldate,
         lcrc, lcompressed, lexpanded, lnlen, lxlen) = \
            struct.unpack_from('<IHHHHHIIIHH', raw, pos)
        if (sig != ZIP_LOCAL or l_ver != ver_needed or lflags != flags or
                lmethod != method or ltime != mtime or ldate != mdate):
            raise Reject('ZIP local/central header mismatch')
        name_start = pos + 30
        data_start = name_start + lnlen + lxlen
        if data_start > boundary or raw[name_start:name_start + lnlen] != name_bytes:
            raise Reject('ZIP local/central filename mismatch')
        lextra = zip_extra_fields(raw[name_start + lnlen:data_start])
        needed = []
        if lexpanded == 0xFFFFFFFF: needed.append('expanded')
        if lcompressed == 0xFFFFFFFF: needed.append('compressed')
        if 1 in lextra and not needed:
            raise Reject('unclaimed ZIP64 local extra')
        actual = zip64_values(lextra, needed) if needed else {}
        l_exp = actual.get('expanded', lexpanded)
        l_cmp = actual.get('compressed', lcompressed)
        if flags & 8:
            if lcrc not in (0, crc) or l_exp not in (0, expanded) or l_cmp not in (0, compressed):
                raise Reject('ZIP local/central descriptor header mismatch')
        else:
            if lcrc != crc or l_exp != expanded or l_cmp != compressed:
                raise Reject('ZIP local/central size/CRC mismatch')
        data_end = data_start + compressed
        if data_end > boundary:
            raise Reject('ZIP compressed data crosses member boundary')
        trailer = raw[data_end:boundary]
        if flags & 8:
            # Data descriptor may omit its signature and may use 32/64-bit sizes.
            valid = False
            for signed in (False, True):
                for width in (4, 8):
                    if width == 4 and (compressed > 0xFFFFFFFF or expanded > 0xFFFFFFFF):
                        continue
                    required = (4 if signed else 0) + 4 + 2 * width
                    if len(trailer) != required:
                        continue
                    ix0 = 4 if signed else 0
                    if signed and struct.unpack_from('<I', trailer)[0] != ZIP_DESCRIPTOR:
                        continue
                    d_crc = struct.unpack_from('<I', trailer, ix0)[0]
                    sizes = struct.unpack_from('<II' if width == 4 else '<QQ', trailer, ix0 + 4)
                    if d_crc == crc and sizes == (compressed, expanded):
                        valid = True
            if not valid:
                raise Reject('ZIP missing/mismatched Data Descriptor')
        elif trailer:
            raise Reject('ZIP unreferenced bytes/overlapping local entries')


def verify(root):
    # Marker check prevents accidentally targeting real files. This is NOT a security boundary.
    marker = strict_json(limited(root/'SYNTHETIC_ONLY.json',2048))
    if marker != {'fixture_format':'gateq-synthetic-v0.1','synthetic':True}:
        raise Reject('only synthetic fixtures allowed')
    expected = strict_json(limited(root/'expected.json',4096))
    if set(expected) != {'zip_sha256','status'} or expected['status'] != 'UNVERIFIED':
        raise Reject('expected context is not explicitly unverified')
    if not isinstance(expected['zip_sha256'],str) or not SHA64.fullmatch(expected['zip_sha256']):
        raise Reject('expected digest malformed')
    state = strict_json(limited(root/'state.json',8192))
    keys = {'schema_version','stage','candidate_status','design_locked','gate_q_locked',
            'runtime_authorized','owner_trust','bootstrap_trust','source_trust','open_blockers'}
    if set(state) != keys: raise Reject('unsupported state schema')
    if not (type(state['schema_version']) is int and state['schema_version']==2 and
            state['stage']=='v1.55 R2' and state['candidate_status']=='CANDIDATE' and
            state['design_locked'] is True and state['gate_q_locked'] is False and
            state['runtime_authorized'] is False and state['owner_trust']=='UNESTABLISHED' and
            state['bootstrap_trust']=='UNESTABLISHED' and state['source_trust']=='UNVERIFIED' and
            type(state['open_blockers']) is list and len(state['open_blockers'])==6 and
            set(state['open_blockers'])==BLOCKERS):
        raise Reject('stale, misleading or prematurely approved state')
    path = root/'candidate.zip'
    raw = limited(path,2_000_000)
    if digest(raw) != expected['zip_sha256'].lower(): raise Reject('ZIP hash mismatch')
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            infos = z.infolist()
            if not 2<=len(infos)<=20: raise Reject('invalid member count')
            validate_zip_container(raw, infos)
            seen=set(); names=set(); total=0
            for item in infos:
                name=item.filename
                folded=unicodedata.normalize('NFKC',name).casefold()
                if not valid_name(name) or folded in seen or item.is_dir():
                    raise Reject('unsafe/duplicate ZIP name')
                if item.create_system==3 and stat.S_ISLNK((item.external_attr>>16)&0xffff):
                    raise Reject('ZIP symlink')
                if item.flag_bits & 1: raise Reject('encrypted member')
                seen.add(folded); names.add(name); total += item.file_size
                if item.file_size>300_000 or total>1_000_000 or item.file_size>1000*max(item.compress_size,1):
                    raise Reject('oversized/compression-risk member')
            if 'MANIFEST.json' not in names: raise Reject('manifest missing')
            manifest = strict_json(read_verified_member(raw, z.getinfo('MANIFEST.json')))
            if set(manifest) != {'format','files'} or manifest['format']!='synthetic-manifest-1':
                raise Reject('unsupported manifest')
            if type(manifest['files']) is not list: raise Reject('manifest files invalid')
            rows={}
            for row in manifest['files']:
                if type(row) is not dict or set(row)!={'name','size','sha256'}: raise Reject('bad manifest row')
                name=row['name']
                if not isinstance(name,str) or not valid_name(name) or name in rows: raise Reject('duplicate manifest row')
                if type(row['size']) is not int or not 0<=row['size']<=300_000: raise Reject('bad size')
                if not isinstance(row['sha256'],str) or not SHA64.fullmatch(row['sha256']): raise Reject('bad member digest')
                rows[name]=row
            if set(rows)!=names-{'MANIFEST.json'}: raise Reject('manifest member set mismatch')
            for name,row in rows.items():
                body=read_verified_member(raw, z.getinfo(name))
                if len(body)!=row['size'] or digest(body)!=row['sha256'].lower():
                    raise Reject('member size/hash mismatch')
    except (zipfile.BadZipFile, RuntimeError, EOFError, OSError, zlib.error) as exc:
        raise Reject(f'corrupt ZIP: {type(exc).__name__}') from exc
    return {'status':'SYNTHETIC_STRUCTURE_PASS_UNVERIFIED','payloads':len(rows),
            'gate_q':'HOLD_NOT_LOCKED','runtime_authorized':False,
            'canonical':False,'blockers':6,'provenance':'UNVERIFIED',
            'required_check_eligible':False,'trusted_origin':False,'may_authorize_runtime':False,
            'meaning':'Only synthetic byte/structure tests; not an authorization, safety audit or attestation.'}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--fixture-dir',type=Path,required=True)
    p.add_argument('--mode',choices=('synthetic','trusted'),required=True,
                   help='synthetic=demo only; trusted=fail closed until external provenance is established')
    args=p.parse_args()
    if args.mode == 'trusted':
        print(json.dumps({'status':'BLOCKED_UNESTABLISHED_TRUST_ROOT',
            'reason':'no independent trusted source or approval mechanism is implemented',
            'gate_q':'HOLD_NOT_LOCKED','required_check_eligible':False})); return 2
    try: print(json.dumps(verify(args.fixture_dir),ensure_ascii=False)); return 0
    except (Reject,ValueError,KeyError,TypeError,OSError,zlib.error) as exc:
        print(json.dumps({'status':'FAIL_CLOSED','reason':str(exc),'gate_q':'HOLD_NOT_LOCKED'})); return 1

if __name__=='__main__': sys.exit(main())
