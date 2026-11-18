#!/usr/bin/env python3 -I
"""Independent analysis of usnjrnlj.bin against unicode.mft, per the task spec."""
import sys

sys.path.insert(0, '/home/zq/feedback/uidreczz28aO9Dg9SpW')

from dfir_ntfs import USN, MFT, Attributes

MFT_PATH = '/home/zq/feedback/uidreczz28aO9Dg9SpW/test_data/unicode.mft'
JNL_PATH = '/home/zq/feedback/uidreczz28aO9Dg9SpW/test_data/usnjrnlj.bin'

mft = MFT.MasterFileTableParser(open(MFT_PATH, 'rb'))

def fn_attrs(file_record):
    out = []
    for attr in file_record.attributes():
        if type(attr) is MFT.AttributeRecordNonresident:
            continue
        val = attr.value_decoded()
        if type(val) is Attributes.FileName:
            out.append(val)
    return out

def names_of(fr_number):
    """All (namespace, name, parent_ref) names currently at an MFT slot."""
    rec = mft.get_file_record_by_number(fr_number, None, False)
    res = []
    for fn in fn_attrs(rec):
        res.append((fn.get_flags(), fn.get_file_name(), fn.get_parent_directory()))
    return res

counts = {'total': 0, 'v4': 0, 'v23': 0}
v4_no_extents = 0
v4_with_extents = 0
class_counts = {}
rows = []

with open(JNL_PATH, 'rb') as f:
    journal = USN.ChangeJournalParser(f)
    for rec in journal.usn_records():
        counts['total'] += 1
        is_v4 = type(rec) is USN.USN_RECORD_V4
        if is_v4:
            counts['v4'] += 1
        else:
            counts['v23'] += 1

        fr_ref = rec.get_file_reference_number()
        parent_ref = rec.get_parent_file_reference_number()
        fr_number, fr_sequence = MFT.DecodeFileRecordSegmentReference(fr_ref)

        verdict = None
        current_names = []
        extents_info = []

        if is_v4:
            verdict = 'no-name-in-record'
            exts = list(rec.extents())
            n_ext = rec.get_number_of_extents()
            ext_size = rec.get_extent_size()
            if len(exts) == 0:
                v4_no_extents += 1
            else:
                v4_with_extents += 1
            for e in exts:
                extents_info.append(e)
        else:
            rec_name = rec.get_file_name()
            try:
                file_record = mft.get_file_record_by_number(fr_number, fr_sequence)
            except MFT.MasterFileTableException:
                try:
                    file_record = mft.get_file_record_by_number(fr_number, None)
                except MFT.MasterFileTableException:
                    verdict = 'target-missing'
                    file_record = None
            if file_record is not None:
                current_names = []
                matched = False
                for fn in fn_attrs(file_record):
                    nm = fn.get_file_name()
                    current_names.append((fn.get_flags(), nm, fn.get_parent_directory()))
                    name_ok = nm.upper() == rec_name.upper()
                    parent_ok = (fn.get_parent_directory() & 0xFFFFFFFFFFFF) == (parent_ref & 0xFFFFFFFFFFFF)
                    if name_ok and parent_ok:
                        matched = True
                verdict = 'corroborated' if matched else 'name-conflict'

        class_counts[verdict] = class_counts.get(verdict, 0) + 1
        rows.append((rec.get_usn(), is_v4, verdict, fr_number, current_names,
                     rec.get_file_name() if not is_v4 else '', extents_info,
                     rec.get_number_of_extents() if is_v4 else None,
                     rec.get_extent_size() if is_v4 else None,
                     rec.get_remaining_extents() if is_v4 else None))

print('counts:', counts)
print('v4 no extents:', v4_no_extents, 'v4 with extents:', v4_with_extents)
print('classes:', class_counts)

# Detail dump for non-target-missing
for usn, is_v4, verdict, frn, names, recname, exts, nexts, extsz, rem in rows:
    if verdict == 'target-missing':
        continue
    print('USN=%d v4=%s verdict=%s fr=%d rec_name=%r' % (usn, is_v4, verdict, frn, recname))
    for flags, nm, par in names:
        print('   MFT name: flags=%d %r parent_ref=%d' % (flags, nm, par))
    if is_v4:
        print('   extents n=%d size=%d remaining=%s -> %r' % (nexts, extsz, rem, exts))
