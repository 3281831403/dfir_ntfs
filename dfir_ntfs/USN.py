# dfir_ntfs: an NTFS parser for digital forensics & incident response
# (c) Maxim Suhanov
#
# This module implements an interface to work with the update sequence number change journal.

import struct
from .Attributes import DecodeFiletime
from . import MFT
from . import Attributes

# Codes for reasons:
USN_REASON_BASIC_INFO_CHANGE = 0x00008000
USN_REASON_CLOSE = 0x80000000
USN_REASON_COMPRESSION_CHANGE = 0x00020000
USN_REASON_DATA_EXTEND = 0x00000002
USN_REASON_DATA_OVERWRITE = 0x00000001
USN_REASON_DATA_TRUNCATION = 0x00000004
USN_REASON_EA_CHANGE = 0x00000400
USN_REASON_ENCRYPTION_CHANGE = 0x00040000
USN_REASON_FILE_CREATE = 0x00000100
USN_REASON_FILE_DELETE = 0x00000200
USN_REASON_HARD_LINK_CHANGE = 0x00010000
USN_REASON_INDEXABLE_CHANGE = 0x00004000
USN_REASON_INTEGRITY_CHANGE = 0x00800000
USN_REASON_NAMED_DATA_EXTEND = 0x00000020
USN_REASON_NAMED_DATA_OVERWRITE = 0x00000010
USN_REASON_NAMED_DATA_TRUNCATION = 0x00000040
USN_REASON_OBJECT_ID_CHANGE = 0x00080000
USN_REASON_RENAME_NEW_NAME = 0x00002000
USN_REASON_RENAME_OLD_NAME = 0x00001000
USN_REASON_REPARSE_POINT_CHANGE = 0x00100000
USN_REASON_SECURITY_CHANGE = 0x00000800
USN_REASON_STREAM_CHANGE = 0x00200000
USN_REASON_TRANSACTED_CHANGE = 0x00400000

ReasonList = {
	USN_REASON_BASIC_INFO_CHANGE: 'USN_REASON_BASIC_INFO_CHANGE',
	USN_REASON_CLOSE: 'USN_REASON_CLOSE',
	USN_REASON_COMPRESSION_CHANGE: 'USN_REASON_COMPRESSION_CHANGE',
	USN_REASON_DATA_EXTEND: 'USN_REASON_DATA_EXTEND',
	USN_REASON_DATA_OVERWRITE: 'USN_REASON_DATA_OVERWRITE',
	USN_REASON_DATA_TRUNCATION: 'USN_REASON_DATA_TRUNCATION',
	USN_REASON_EA_CHANGE: 'USN_REASON_EA_CHANGE',
	USN_REASON_ENCRYPTION_CHANGE: 'USN_REASON_ENCRYPTION_CHANGE',
	USN_REASON_FILE_CREATE: 'USN_REASON_FILE_CREATE',
	USN_REASON_FILE_DELETE: 'USN_REASON_FILE_DELETE',
	USN_REASON_HARD_LINK_CHANGE: 'USN_REASON_HARD_LINK_CHANGE',
	USN_REASON_INDEXABLE_CHANGE: 'USN_REASON_INDEXABLE_CHANGE',
	USN_REASON_INTEGRITY_CHANGE: 'USN_REASON_INTEGRITY_CHANGE',
	USN_REASON_NAMED_DATA_EXTEND: 'USN_REASON_NAMED_DATA_EXTEND',
	USN_REASON_NAMED_DATA_OVERWRITE: 'USN_REASON_NAMED_DATA_OVERWRITE',
	USN_REASON_NAMED_DATA_TRUNCATION: 'USN_REASON_NAMED_DATA_TRUNCATION',
	USN_REASON_OBJECT_ID_CHANGE: 'USN_REASON_OBJECT_ID_CHANGE',
	USN_REASON_RENAME_NEW_NAME: 'USN_REASON_RENAME_NEW_NAME',
	USN_REASON_RENAME_OLD_NAME: 'USN_REASON_RENAME_OLD_NAME',
	USN_REASON_REPARSE_POINT_CHANGE: 'USN_REASON_REPARSE_POINT_CHANGE',
	USN_REASON_SECURITY_CHANGE: 'USN_REASON_SECURITY_CHANGE',
	USN_REASON_STREAM_CHANGE: 'USN_REASON_STREAM_CHANGE',
	USN_REASON_TRANSACTED_CHANGE: 'USN_REASON_TRANSACTED_CHANGE'
}

# Codes for sources:
USN_SOURCE_AUXILIARY_DATA = 0x00000002
USN_SOURCE_DATA_MANAGEMENT = 0x00000001
USN_SOURCE_REPLICATION_MANAGEMENT = 0x00000004
USN_SOURCE_CLIENT_REPLICATION_MANAGEMENT = 0x00000008

SourceList = {
	USN_SOURCE_AUXILIARY_DATA: 'USN_SOURCE_AUXILIARY_DATA',
	USN_SOURCE_DATA_MANAGEMENT: 'USN_SOURCE_DATA_MANAGEMENT',
	USN_SOURCE_REPLICATION_MANAGEMENT: 'USN_SOURCE_REPLICATION_MANAGEMENT',
	USN_SOURCE_CLIENT_REPLICATION_MANAGEMENT: 'USN_SOURCE_CLIENT_REPLICATION_MANAGEMENT'
}

def ResolveReasonCodes(ReasonCodes):
	"""Resolve reason codes to a string."""

	flags_left = ReasonCodes

	str_list = []
	for flag in sorted(ReasonList.keys()):
		if ReasonCodes & flag > 0:
			str_list.append(ReasonList[flag])
			flags_left -= ReasonCodes & flag

	if flags_left > 0: # Unknown flags are set.
		str_list.append(hex(flags_left))

	return ' | '.join(str_list)

def ResolveSourceCodes(SourceCodes):
	"""Convert source codes to a string."""

	flags_left = SourceCodes

	str_list = []
	for flag in sorted(SourceList.keys()):
		if SourceCodes & flag > 0:
			str_list.append(SourceList[flag])
			flags_left -= SourceCodes & flag

	if flags_left > 0: # Unknown codes are set.
		str_list.append(hex(flags_left))

	return ' | '.join(str_list)

def GetUsnRecord(update_sequence_number_record_buf):
	"""This function returns an update sequence number (USN) change journal record object (USN_RECORD_V2_OR_V3 or USN_RECORD_V4) for a given buffer."""

	if len(update_sequence_number_record_buf) < 8:
		raise ValueError('USN record buffer is too small')

	record_length, major_version, minor_version = struct.unpack('<LHH', update_sequence_number_record_buf[ : 8])
	if record_length < 8:
		raise ValueError('USN record length is too small: {}'.format(record_length))

	usn_record = None

	if major_version == 2:
		usn_record = USN_RECORD_V2_OR_V3(update_sequence_number_record_buf[: record_length], False)

	elif major_version == 3:
		usn_record = USN_RECORD_V2_OR_V3(update_sequence_number_record_buf[: record_length], True)

	elif major_version == 4:
		usn_record = USN_RECORD_V4(update_sequence_number_record_buf[: record_length])

	if usn_record is not None:
		return usn_record

	raise NotImplementedError('USN record version not supported: {}.{}'.format(major_version, minor_version))

class USN_RECORD_V2_OR_V3(object):
	"""This class is used to work with an update sequence number (USN) change journal record, either version 2.x or 3.x."""

	def __init__(self, update_sequence_number_record_buf, is_version_3):
		self.is_version_3 = is_version_3

		if self.is_version_3:
			self.offset_increment = 16
		else:
			self.offset_increment = 0

		self.record_raw = update_sequence_number_record_buf

		if (not self.is_version_3) and len(self.record_raw) < 62:
			raise ValueError('USN record buffer is too small for this version (2.x)')
		elif self.is_version_3 and len(self.record_raw) < 62 + self.offset_increment:
			raise ValueError('USN record buffer is too small for this version (3.x)')

		record_length = self.get_record_length()

		if record_length < 8 or record_length % 8 != 0:
			raise ValueError('USN record length is not aligned to 8 bytes: {}'.format(record_length))

		if record_length > len(self.record_raw):
			raise ValueError('USN record length is too large for this buffer: {} > {}'.format(record_length, len(self.record_raw)))

		major_version = self.get_major_version()
		if self.is_version_3 and major_version != 3:
			raise ValueError('Invalid major version: {} != 3'.format(major_version))

		if (not self.is_version_3) and major_version != 2:
			raise ValueError('Invalid major version: {} != 2'.format(major_version))

	def get_record_length(self):
		"""Get and return the record length."""

		return struct.unpack('<L', self.record_raw[ : 4])[0]

	def get_major_version(self):
		"""Get and return the major version."""

		return struct.unpack('<H', self.record_raw[4 : 6])[0]

	def get_minor_version(self):
		"""Get and return the major version."""

		return struct.unpack('<H', self.record_raw[6 : 8])[0]

	def get_file_reference_number(self):
		"""Get and return the file reference number."""

		if not self.is_version_3:
			return struct.unpack('<Q', self.record_raw[8 : 16])[0]
		else:
			file_reference_lo = struct.unpack('<Q', self.record_raw[8 : 16])[0]
			file_reference_hi = struct.unpack('<Q', self.record_raw[16 : 24])[0]

			return (file_reference_hi << 64) | file_reference_lo

	def get_parent_file_reference_number(self):
		"""Get and return the parent file reference number."""

		if not self.is_version_3:
			return struct.unpack('<Q', self.record_raw[16 : 24])[0]
		else:
			file_reference_lo = struct.unpack('<Q', self.record_raw[24 : 32])[0]
			file_reference_hi = struct.unpack('<Q', self.record_raw[32 : 40])[0]

			return (file_reference_hi << 64) | file_reference_lo

	def get_usn(self):
		"""Get and return the update sequence number (USN) for this record."""

		return struct.unpack('<Q', self.record_raw[24 + self.offset_increment : 32 + self.offset_increment])[0]

	def get_timestamp(self):
		"""Get, decode and return the timestamp for this record."""

		timestamp = struct.unpack('<Q', self.record_raw[32 + self.offset_increment : 40 + self.offset_increment])[0]
		return DecodeFiletime(timestamp)

	def get_reason(self):
		"""Get and return the reason code (as an integer)."""

		return struct.unpack('<L', self.record_raw[40 + self.offset_increment : 44 + self.offset_increment])[0]

	def get_source_info(self):
		"""Get and return the source information (as an integer)."""

		return struct.unpack('<L', self.record_raw[44 + self.offset_increment : 48 + self.offset_increment])[0]

	def get_security_id(self):
		"""Get and return the security ID."""

		return struct.unpack('<L', self.record_raw[48 + self.offset_increment : 52 + self.offset_increment])[0]

	def get_file_attributes(self):
		"""Get and return the file attributes (as an integer)."""

		return struct.unpack('<L', self.record_raw[52 + self.offset_increment : 56 + self.offset_increment])[0]

	def get_file_name_length(self):
		"""Get and return the file name length."""

		return struct.unpack('<H', self.record_raw[56 + self.offset_increment : 58 + self.offset_increment])[0]

	def get_file_name_offset(self):
		"""Get and return the file name offset (in this record)."""

		return struct.unpack('<H', self.record_raw[58 + self.offset_increment : 60 + self.offset_increment])[0]

	def get_file_name(self):
		"""Get, decode and return the file name."""

		file_name_offset = self.get_file_name_offset()
		file_name_length = self.get_file_name_length()

		file_name_raw = self.record_raw[file_name_offset : file_name_offset + file_name_length]
		if len(file_name_raw) != file_name_length:
			raise ValueError('Truncated file name')

		return file_name_raw.decode('utf-16le', errors = 'replace')

	def __str__(self):
		return 'USN_RECORD_V2_OR_V3, version: {}.{}, record length: {}'.format(self.get_major_version(), self.get_minor_version(), self.get_record_length())

class USN_RECORD_V4(object):
	"""This class is used to work with an update sequence number (USN) change journal record, version 4.x."""

	def __init__(self, update_sequence_number_record_buf):
		self.record_raw = update_sequence_number_record_buf

		if len(self.record_raw) < 80:
			raise ValueError('USN recod buffer is too small for this version (4.x)')

		record_length = self.get_record_length()

		if record_length < 8 or record_length % 8 != 0:
			raise ValueError('USN record length is not aligned to 8 bytes: {}'.format(record_length))

		if record_length > len(self.record_raw):
			raise ValueError('USN record length is too large for this buffer: {} > {}'.format(record_length, len(self.record_raw)))

		major_version = self.get_major_version()
		if major_version != 4:
			raise ValueError('Invalid major version: {} != 4'.format(major_version))

	def get_record_length(self):
		"""Get and return the record length."""

		return struct.unpack('<L', self.record_raw[ : 4])[0]

	def get_major_version(self):
		"""Get and return the major version."""

		return struct.unpack('<H', self.record_raw[4 : 6])[0]

	def get_minor_version(self):
		"""Get and return the major version."""

		return struct.unpack('<H', self.record_raw[6 : 8])[0]

	def get_file_reference_number(self):
		"""Get and return the file reference number."""

		file_reference_lo = struct.unpack('<Q', self.record_raw[8 : 16])[0]
		file_reference_hi = struct.unpack('<Q', self.record_raw[16 : 24])[0]

		return (file_reference_hi << 64) | file_reference_lo

	def get_parent_file_reference_number(self):
		"""Get and return the parent file reference number."""

		file_reference_lo = struct.unpack('<Q', self.record_raw[24 : 32])[0]
		file_reference_hi = struct.unpack('<Q', self.record_raw[32 : 40])[0]

		return (file_reference_hi << 64) | file_reference_lo

	def get_usn(self):
		"""Get and return the update sequence number (USN) for this record."""

		return struct.unpack('<Q', self.record_raw[40 : 48])[0]

	def get_reason(self):
		"""Get and return the reason code (as an integer)."""

		return struct.unpack('<L', self.record_raw[48 : 52])[0]

	def get_source_info(self):
		"""Get and return the source information (as an integer)."""

		return struct.unpack('<L', self.record_raw[52 : 56])[0]

	def get_remaining_extents(self):
		"""Get and return the number of remaining extents."""

		return struct.unpack('<L', self.record_raw[56 : 60])[0]

	def get_number_of_extents(self):
		"""Get and return the number of extents in this record."""

		return struct.unpack('<H', self.record_raw[60 : 62])[0]

	def get_extent_size(self):
		"""Get and return the size of each extent in this record."""

		return struct.unpack('<H', self.record_raw[62 : 64])[0]

	def extents(self):
		"""This method yields (offset, length) tuples for extents found in this record. If the extents are not supported, then this method yields raw bytes for each extent."""

		number_of_extents = self.get_number_of_extents()
		extent_size = self.get_extent_size()

		pos_relative = 64

		while number_of_extents > 0:
			extent_raw = self.record_raw[pos_relative : pos_relative + extent_size]
			if len(extent_raw) != extent_size: # This extent is truncated.
				break

			if extent_size == 16:
				offset, length = struct.unpack('<qq', extent_raw)
				yield (offset, length)
			else:
				yield extent_raw

			pos_relative += extent_size
			number_of_extents -= 1

	def __str__(self):
		return 'USN_RECORD_V4, version: {}.{}, record length: {}'.format(self.get_major_version(), self.get_minor_version(), self.get_record_length())

class ChangeJournalParser(object):
	"""This class is used to read and parse a $UsnJrnl:$J file."""

	file_object = None
	"""A file object for a $UsnJrnl:$J file."""

	file_size = None
	"""A size of this $UsnJrnl:$J file."""

	def __init__(self, file_object):
		self.file_object = file_object

		self.file_object.seek(0, 2)
		self.file_size = self.file_object.tell()
		self.file_object.seek(0)

	def usn_records(self):
		"""This method yields USN records (USN_RECORD_V2_OR_V3 or USN_RECORD_V4) found in this $UsnJrnl:$J file."""

		chunk_size = 8192

		pos = 0
		while pos < self.file_size:
			self.file_object.seek(pos)
			buf = self.file_object.read(chunk_size)

			tmp_buf = buf
			if tmp_buf.lstrip(b'\x00') == b'': # Check if this is an empty buffer (this should be fast).
				pos += len(buf)
				continue

			new_pos = pos + len(buf) - len(tmp_buf)
			if new_pos == 0 or new_pos % 8 == 0: # USN records are aligned to 8 bytes.
				new_pos_aligned = new_pos
			else:
				new_pos_aligned = new_pos - new_pos % 8

			pos = new_pos_aligned

			self.file_object.seek(pos)
			buf = self.file_object.read(chunk_size)

			try:
				usn = GetUsnRecord(buf)
			except (ValueError, NotImplementedError):
				# An invalid (or missing) USN record.
				pos += 8
				continue

			yield usn
			pos += usn.get_record_length()

# Verdicts for a change journal record verified against the current $MFT.
VERDICT_CORROBORATED = 'corroborated'
"""A version 2.x/3.x record's name and parent directory reference are both present in the target $MFT slot."""

VERDICT_NAME_CONFLICT = 'name-conflict'
"""The target $MFT slot exists, but no file name in it matches the record (case-insensitively, DOS aliases included)."""

VERDICT_TARGET_MISSING = 'target-missing'
"""The target $MFT slot cannot be read (the file record segment is missing or invalid)."""

VERDICT_NO_NAME = 'no-name-in-record'
"""A version 4.x record: it never carries a file name, so it cannot be corroborated by one."""

def _file_name_attribute_values(mft_parser, file_record):
	"""Return deduplicated $FILE_NAME attribute values of a file record (in the on-disk order)."""

	file_names = []
	seen = set()

	for attribute in file_record.attributes():
		if type(attribute) is MFT.AttributeRecordNonresident:
			continue

		attribute_value = attribute.value_decoded()
		if type(attribute_value) is not Attributes.FileName:
			continue

		key = (attribute_value.get_file_name(), attribute_value.get_parent_directory(), attribute_value.get_flags())
		if key in seen:
			continue

		seen.add(key)
		file_names.append(attribute_value)

	return file_names

def current_slot_names(mft_parser, file_record):
	"""Return the names currently stored in an $MFT slot (all name spaces, DOS aliases included), joined with ' | '."""

	return ' | '.join(attr_file_name.get_file_name() for attr_file_name in _file_name_attribute_values(mft_parser, file_record))

def build_path_for_file_name(mft_parser, file_record, attr_file_name):
	"""Rebuild a full path for a file record, starting from a specific $FILE_NAME attribute value.

	The record's own name and each parent directory reference are resolved against the $MFT;
	cycles, orphan records and non-directory parents are handled like MasterFileTableParser.build_full_paths.
	"""

	path_components = [ attr_file_name.get_file_name() ]
	parent_reference = attr_file_name.get_parent_directory()
	parent_segment_number, parent_sequence_number = MFT.DecodeFileRecordSegmentReference(parent_reference)

	if parent_segment_number == MFT.FILE_NUMBER_ROOT:
		path_components.append('') # Add a root directory.
		path_components.reverse()
		return MFT.PATH_SEPARATOR.join(path_components)

	try:
		parent_file_record = mft_parser.get_file_record_by_number(parent_segment_number, parent_sequence_number, False)
	except MFT.MasterFileTableException:
		path_components.append(MFT.UNKNOWN_PATH_PLACEHOLDER) # An invalid parent file record.
	else:
		if parent_file_record.get_flags() & MFT.FILE_FILE_NAME_INDEX_PRESENT == 0:
			path_components.append(MFT.UNKNOWN_PATH_PLACEHOLDER) # Not a directory.
		else:
			track = set()
			track.add(parent_segment_number)

			current_file_record = parent_file_record
			while True:
				parent_file_names = _file_name_attribute_values(mft_parser, current_file_record)
				if len(parent_file_names) == 0:
					path_components.append(MFT.UNKNOWN_PATH_PLACEHOLDER)
					break

				# Win32 and POSIX name spaces are preferred, take the first attribute value otherwise.
				preferred = parent_file_names[0]
				for candidate in parent_file_names:
					if candidate.get_flags() & Attributes.FILE_NAME_NTFS > 0 or candidate.get_flags() == 0:
						preferred = candidate
						break

				path_components.append(preferred.get_file_name())
				next_parent_reference = preferred.get_parent_directory()
				parent_segment_number, parent_sequence_number = MFT.DecodeFileRecordSegmentReference(next_parent_reference)

				if parent_segment_number in track:
					path_components.append(MFT.UNKNOWN_PATH_PLACEHOLDER) # An invalid path.
					break

				track.add(parent_segment_number)

				try:
					current_file_record = mft_parser.get_file_record_by_number(parent_segment_number, parent_sequence_number, False)
				except MFT.MasterFileTableException:
					path_components.append(MFT.UNKNOWN_PATH_PLACEHOLDER) # An invalid parent file record.
					break

				if parent_segment_number == MFT.FILE_NUMBER_ROOT:
					path_components.append('') # Add a root directory.
					break

				if current_file_record.get_flags() & MFT.FILE_FILE_NAME_INDEX_PRESENT == 0:
					path_components.append(MFT.UNKNOWN_PATH_PLACEHOLDER) # Not a directory.
					break

	path_components.reverse()
	return MFT.PATH_SEPARATOR.join(path_components)

def format_v4_extents(usn_record):
	"""Format extents of a version 4 record as 'offset:length' items joined with ' | ' (unsupported extents are hex-encoded)."""

	extent_items = []

	for extent in usn_record.extents():
		if type(extent) is tuple:
			extent_items.append('{}:{}'.format(extent[0], extent[1]))
		else:
			extent_items.append('0x' + extent.hex().upper())

	return ' | '.join(extent_items)

def verify_record(usn_record, mft_parser):
	"""Verify a single USN change journal record against the current $MFT.

	Return a tuple: (verdict, rebuilt_file_path, current_slot_names, v4_extents).
	The rebuilt file path is non-empty only for 'corroborated' records;
	the current slot names are non-empty only for 'name-conflict' records;
	the V4 extents string is non-empty only for 'no-name-in-record' records.
	"""

	is_v4_record = type(usn_record) is USN_RECORD_V4

	if is_v4_record:
		return (VERDICT_NO_NAME, '', '', format_v4_extents(usn_record))

	fr_number, fr_sequence = MFT.DecodeFileRecordSegmentReference(usn_record.get_file_reference_number())
	parent_fr_number = MFT.DecodeFileRecordSegmentReference(usn_record.get_parent_file_reference_number())[0]

	try:
		file_record = mft_parser.get_file_record_by_number(fr_number, fr_sequence)
	except MFT.MasterFileTableException:
		try: # Retry without an expected sequence number (the slot may have been reused).
			file_record = mft_parser.get_file_record_by_number(fr_number)
		except MFT.MasterFileTableException:
			file_record = None

	if file_record is None:
		return (VERDICT_TARGET_MISSING, '', '', '')

	record_file_name = usn_record.get_file_name()
	matching_file_name = None

	for attr_file_name in _file_name_attribute_values(mft_parser, file_record):
		# Compare case-insensitively; both Win32/POSIX and DOS names are considered.
		same_name = attr_file_name.get_file_name().upper() == record_file_name.upper()
		same_parent = MFT.DecodeFileRecordSegmentReference(attr_file_name.get_parent_directory())[0] == parent_fr_number

		if same_name and same_parent:
			matching_file_name = attr_file_name
			break

	if matching_file_name is None:
		return (VERDICT_NAME_CONFLICT, '', current_slot_names(mft_parser, file_record), '')

	rebuilt_path = build_path_for_file_name(mft_parser, file_record, matching_file_name)
	return (VERDICT_CORROBORATED, rebuilt_path, '', '')
