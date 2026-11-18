#!/usr/bin/env python3 -I
# Wrapper to run ntfs_parser in isolated mode with the package on sys.path.
import sys

sys.path.insert(0, '/home/zq/feedback/uidreczz28aO9Dg9SpW')

sys.argv = ['ntfs_parser'] + sys.argv[1:]
with open('/home/zq/feedback/uidreczz28aO9Dg9SpW/ntfs_parser', 'r') as f:
    code = compile(f.read(), '/home/zq/feedback/uidreczz28aO9Dg9SpW/ntfs_parser', 'exec')
    exec(code, {'__name__': '__main__', '__file__': '/home/zq/feedback/uidreczz28aO9Dg9SpW/ntfs_parser'})
