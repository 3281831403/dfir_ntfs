#!/usr/bin/env python3 -I
"""Validate after.csv against every requirement in the task."""
import csv, sys
sys.path.insert(0, '/home/zq/feedback/uidreczz28aO9Dg9SpW')
from dfir_ntfs import USN, MFT, Attributes

ROOT = '/home/zq/feedback/uidreczz28aO9Dg9SpW'

with open(ROOT + '/work/before.csv', newline='', encoding='utf-8') as f:
    before = list(csv.reader(f))
with open(ROOT + '/work/after.csv', newline='', encoding='utf-8') as f:
    after = list(csv.reader(f))

b_hdr, b_rows = before[0], before[1:]
a_hdr, a_rows = after[0], after[1:]

assert len(b_rows) == len(a_rows) == 271, (len(b_rows), len(a_rows))
assert a_hdr[:8] == b_hdr, 'first 8 header columns changed'
assert a_hdr[8:] == ['Verification verdict', "Current name(s) in the target slot", 'V4 extents (offset:length)']

# 1. Original first 7 columns byte-identical for every row; column 8 only preserved for corroborated rows.
diff7 = [i for i in range(271) if a_rows[i][:7] != b_rows[i][:7]]
assert not diff7, ('first 7 columns changed at rows', diff7[:5])
for i, r in enumerate(a_rows):
    if r[8] == 'corroborated':
        assert r[7] == b_rows[i][7], ('corroborated path differs from old column 8', r[0])
    else:
        assert r[7] == '', ('non-corroborated row has a path', r[0], r[8])
# Old output had 34 non-blank paths; new output keeps exactly the 10 corroborated ones.
assert sum(1 for r in b_rows if r[7] != '') == 34
assert sum(1 for r in a_rows if r[7] != '') == 10

# 2. Verdict distribution.
from collections import Counter
verdicts = Counter(r[8] for r in a_rows)
assert dict(verdicts) == {'corroborated': 10, 'name-conflict': 24, 'target-missing': 230, 'no-name-in-record': 7}, verdicts

# 3. Only corroborated rows carry a path; path equals the old column 8 for them.
for r in a_rows:
    if r[8] == 'corroborated':
        assert r[7] != '', 'corroborated row without path'
    else:
        assert r[7] == '', ('non-corroborated row has a path', r[0], r[8])

# 4. Slot-name column: blank for target-missing; non-blank for name-conflict; blank for v4; blank for corroborated.
for r in a_rows:
    v = r[8]
    if v == 'name-conflict':
        assert r[9] != '', ('name-conflict without slot name', r[0])
    elif v in ('target-missing', 'no-name-in-record', 'corroborated'):
        assert r[9] == '', ('slot name should be blank', r[0], v)

# 5. V4 rows: extents populated with offset:length, others blank.
v4_rows = [r for r in a_rows if r[8] == 'no-name-in-record']
assert len(v4_rows) == 7
for r in v4_rows:
    assert r[10].count(':') == 1 and r[10].count('|') == 0, r[10]
    off, ln = r[10].split(':')
    int(off); int(ln)
for r in a_rows:
    if r[8] != 'no-name-in-record':
        assert r[10] == '', ('extents on non-V4 row', r[0])

# 6. Cross-check V4 extents against the parser API, one by one.
with open(ROOT + '/test_data/usnjrnlj.bin', 'rb') as f:
    v4_api = {}
    for rec in USN.ChangeJournalParser(f).usn_records():
        if type(rec) is USN.USN_RECORD_V4:
            ex = list(rec.extents())
            v4_api[rec.get_usn()] = ' | '.join('{}:{}'.format(o, l) for o, l in ex)
for r in v4_rows:
    assert r[10] == v4_api[int(r[0])], (r[0], r[10], v4_api[int(r[0])])

# 7. Corroborated paths: rebuild independently from record name + parent reference.
mft = MFT.MasterFileTableParser(open(ROOT + '/test_data/unicode.mft', 'rb'))
def fns(rec):
    out = []
    for attr in rec.attributes():
        if type(attr) is MFT.AttributeRecordNonresident:
            continue
        v = attr.value_decoded()
        if type(v) is Attributes.FileName:
            out.append(v)
    return out

with open(ROOT + '/test_data/usnjrnlj.bin', 'rb') as f:
    v23 = [r for r in USN.ChangeJournalParser(f).usn_records() if type(r) is USN.USN_RECORD_V2_OR_V3]
assert len(v23) == 264

independent = {}
for rec in v23:
    n, seq = MFT.DecodeFileRecordSegmentReference(rec.get_file_reference_number())
    pn = MFT.DecodeFileRecordSegmentReference(rec.get_parent_file_reference_number())[0]
    try:
        fr = mft.get_file_record_by_number(n, seq)
    except MFT.MasterFileTableException:
        try:
            fr = mft.get_file_record_by_number(n)
        except MFT.MasterFileTableException:
            independent[rec.get_usn()] = ('target-missing', '')
            continue
    match = None
    names = []
    for fn in fns(fr):
        names.append(fn.get_file_name())
        if fn.get_file_name().upper() == rec.get_file_name().upper() and \
           MFT.DecodeFileRecordSegmentReference(fn.get_parent_directory())[0] == pn:
            match = fn
    if match is None:
        independent[rec.get_usn()] = ('name-conflict', ' | '.join(dict.fromkeys(names)))
    else:
        key = (match.get_file_name(), match.get_parent_directory(), match.get_flags())
        paths = [p for p, a in mft.build_full_paths(fr, True)
                 if (a.get_file_name(), a.get_parent_directory(), a.get_flags()) == key]
        assert paths, ('no rebuilt path for matched attribute', rec.get_usn())
        independent[rec.get_usn()] = ('corroborated', paths[0])

for r in a_rows:
    if r[8] == 'no-name-in-record':
        continue
    iv, ip = independent[int(r[0])]
    assert r[8] == iv, ('verdict mismatch', r[0], r[8], iv)
    if iv == 'corroborated':
        assert r[7] == ip, ('path mismatch', r[0], r[7], ip)
    elif iv == 'name-conflict':
        assert r[9] == ip, ('slot names mismatch', r[0], r[9], ip)

# 8. Name-conflict slot names really are the current names in the target MFT slot (spot-check all 24).
for r in a_rows:
    if r[8] != 'name-conflict':
        continue
    ref = int(r[3])
    n = ref & 0xFFFFFFFFFFFF
    fr = mft.get_file_record_by_number(n)
    expect = ' | '.join(dict.fromkeys(fn.get_file_name() for fn in fns(fr)))
    assert r[9] == expect, ('slot name content mismatch', r[0], r[9], expect)

print('ALL CHECKS PASSED')
print('verdicts:', dict(verdicts))
print('V4 extents:', sorted((r[0], r[10]) for r in v4_rows))
print('corroborated paths:')
for r in a_rows:
    if r[8] == 'corroborated':
        print(' USN=%s %r' % (r[0], r[7]))
