#!/usr/bin/env python3 -I
"""Detail checks to lock down classification edge cases."""
import sys
sys.path.insert(0, '/home/zq/feedback/uidreczz28aO9Dg9SpW')

from dfir_ntfs import USN, MFT, Attributes
import csv

ROOT = '/home/zq/feedback/uidreczz28aO9Dg9SpW'
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

strict_fail_soft_ok = 0
fullref_differs = 0
v4_targets = {}
corro_paths = {}

with open(ROOT + '/test_data/usnjrnlj.bin', 'rb') as f:
    for rec in USN.ChangeJournalParser(f).usn_records():
        is_v4 = type(rec) is USN.USN_RECORD_V4
        fr_ref = rec.get_file_reference_number()
        par_ref = rec.get_parent_file_reference_number()
        n, seq = MFT.DecodeFileRecordSegmentReference(fr_ref)

        strict = None
        try:
            strict = mft.get_file_record_by_number(n, seq)
        except MFT.MasterFileTableException:
            pass
        soft = None
        try:
            soft = mft.get_file_record_by_number(n, None)
        except MFT.MasterFileTableException:
            pass
        if strict is None and soft is not None:
            strict_fail_soft_ok += 1

        if is_v4:
            v4_targets[rec.get_usn()] = (n, [ (a.get_flags(), a.get_file_name()) for a in fns(soft) ] if soft else None)

        if soft is not None and not is_v4:
            rname = rec.get_file_name()
            for a in fns(soft):
                if a.get_file_name().upper() == rname.upper():
                    if a.get_parent_directory() != par_ref:
                        fullref_differs += 1
                    # corroborated candidate: compare rebuilt vs build_full_paths
                    paths = mft.build_full_paths(soft, True)
                    for p, attr in paths:
                        if attr is a:
                            corro_paths[rec.get_usn()] = (p, mft.build_full_paths(soft)[0])

print('strict-fail-but-soft-ok rows:', strict_fail_soft_ok)
print('name match but full 64-bit parent ref differs:', fullref_differs)
print('V4 targets:', v4_targets)
print('rebuilt-attr-path vs build_full_paths[0]:')
for k, v in sorted(corro_paths.items()):
    same = v[0] == v[1]
    print(' USN', k, same, repr(v[0]), repr(v[1]))

# What does the current CSV carry for the 34 resolvable rows and the 10 corroborated?
with open(ROOT + '/work/before.csv', newline='', encoding='utf-8') as f:
    rows = list(csv.reader(f))
hdr, data = rows[0], rows[1:]
blank = sum(1 for r in data if r[7] == '')
withpath = sum(1 for r in data if r[7] != '')
print('before.csv: blank path rows =', blank, 'non-blank =', withpath)
for r in data:
    if r[6] in ('.', '$TxfLog.blf'):
        print(' corro-orig:', r[0], repr(r[6]), repr(r[7]))
