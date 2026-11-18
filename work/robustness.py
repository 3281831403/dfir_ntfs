#!/usr/bin/env python3 -I
"""Robustness tests: corrupt journal and MFT copies, the parser must keep emitting every good row."""
import csv, os, subprocess, sys

ROOT = '/home/zq/feedback/uidreczz28aO9Dg9SpW'
WORK = ROOT + '/work'
PARSER = WORK + '/run_parser.py'
MFT = ROOT + '/test_data/unicode.mft'
JNL = ROOT + '/test_data/usnjrnlj.bin'

def run(mft_path, jnl_path, out_path):
    r = subprocess.run([sys.executable, '-I', PARSER, '--usn', mft_path, jnl_path, out_path],
                       capture_output = True, text = True)
    return r

def rows_of(path):
    with open(path, newline = '', encoding = 'utf-8') as f:
        r = list(csv.reader(f))
    return r[0], r[1:]

base_hdr, base_rows = rows_of(WORK + '/after.csv')

# 1. Journal with garbage injected at an 8-byte-aligned offset inside the file.
jnl = bytearray(open(JNL, 'rb').read())
jnl[4096:4104] = b'\xDE\xAD\xBE\xEF' * 4
open(WORK + '/corrupt_journal_1.bin', 'wb').write(jnl)
r = run(MFT, WORK + '/corrupt_journal_1.bin', WORK + '/out_cj1.csv')
assert r.returncode == 0, r.stderr
_, rows = rows_of(WORK + '/out_cj1.csv')
# Every record the parser can still decode must carry a valid verdict.
assert all(row[8] in ('corroborated', 'name-conflict', 'target-missing', 'no-name-in-record') for row in rows)
print('corrupt journal (garbage block): rows emitted =', len(rows), '(good baseline =', len(base_rows), ')')

# 2. Truncated journal: cut the file in the middle of a record.
buf = open(JNL, 'rb').read()
open(WORK + '/corrupt_journal_2.bin', 'wb').write(buf[: len(buf) - 137])
r = run(MFT, WORK + '/corrupt_journal_2.bin', WORK + '/out_cj2.csv')
assert r.returncode == 0, r.stderr
_, rows = rows_of(WORK + '/out_cj2.csv')
assert len(rows) >= 260, len(rows)
assert all(row[8] in ('corroborated', 'name-conflict', 'target-missing', 'no-name-in-record') for row in rows)
print('truncated journal: rows emitted =', len(rows))

# 3. Corrupt MFT: zero the slot of record 40 (referenced by name-conflict rows).
mft = bytearray(open(MFT, 'rb').read())
# MFT record size is read from the boot sector-like header; unicode.mft uses 1024-byte segments.
mft[40 * 1024 : 41 * 1024] = b'\x00' * 1024
open(WORK + '/corrupt_mft_1.mft', 'wb').write(mft)
r = run(WORK + '/corrupt_mft_1.mft', JNL, WORK + '/out_cm1.csv')
assert r.returncode == 0, r.stderr
hdr, rows = rows_of(WORK + '/out_cm1.csv')
assert len(rows) == len(base_rows) == 271
affected = {row[0] for row in base_rows if row[3] == str(281474976710696)}
for row, orig in zip(rows, base_rows):
    assert row[:7] == orig[:7], 'first 7 columns must stay stable'
    if row[0] in affected:
        assert row[8] == 'target-missing', (row[0], row[8])
        assert row[7] == '' and row[9] == ''
    else:
        assert row[8] == orig[8] and row[7] == orig[7] and row[9] == orig[9]
print('corrupt MFT (slot 40 zeroed): all 271 rows emitted,', len(affected), 'affected rows downgraded to target-missing')

# 4. Corrupt MFT: zero slot 5 (root, used by corroborated rows).
mft = bytearray(open(MFT, 'rb').read())
mft[5 * 1024 : 6 * 1024] = b'\x00' * 1024
open(WORK + '/corrupt_mft_2.mft', 'wb').write(mft)
r = run(WORK + '/corrupt_mft_2.mft', JNL, WORK + '/out_cm2.csv')
assert r.returncode == 0, r.stderr
_, rows = rows_of(WORK + '/out_cm2.csv')
assert len(rows) == 271
assert all(row[8] in ('corroborated', 'name-conflict', 'target-missing', 'no-name-in-record') for row in rows)
print('corrupt MFT (root slot zeroed): all 271 rows emitted, no crash')

# 5. MFT with every data slot zeroed (bootstrap records 0..9 and the root slot 5 kept so the MFT parser itself stays valid).
good = open(MFT, 'rb').read()
mft = bytearray(good)
mft[10 * 1024 :] = b'\x00' * (len(mft) - 10 * 1024)
open(WORK + '/empty.mft', 'wb').write(mft)
r = run(WORK + '/empty.mft', JNL, WORK + '/out_empty.csv')
assert r.returncode == 0, r.stderr
_, rows = rows_of(WORK + '/out_empty.csv')
assert len(rows) == 271
# Only the 6 root-directory ('.') records can still corroborate; their slot was intentionally kept.
assert sum(1 for row in rows if row[8] == 'corroborated') == 6
assert all(row[8] in ('target-missing', 'no-name-in-record', 'corroborated') for row in rows)
assert all(row[9] == '' for row in rows)
v4 = [row for row in rows if row[8] == 'no-name-in-record']
assert len(v4) == 7 and all(row[10] for row in v4)
print('zeroed data slots: 271 rows, 7 V4 still carry extents, 6 root records survive, rest target-missing')

print('ALL ROBUSTNESS CHECKS PASSED')
