import binascii
import os
import re
import sys
import time
from datetime import timedelta, datetime
from io import SEEK_END
from typing import List


class LogFile:

    def __init__(self, path: str):
        self._path = path
        self._start_pos = 0
        self._last_pos = self._start_pos

    @property
    def path(self) -> str:
        return self._path

    def reset(self):
        self._start_pos = 0
        self._last_pos = self._start_pos

    def advance(self) -> None:
        if os.path.isfile(self._path):
            with open(self._path) as fd:
                self._start_pos = fd.seek(0, SEEK_END)

    def get_recent(self, advance=True) -> List[str]:
        lines = []
        if os.path.isfile(self._path):
            with open(self._path) as fd:
                fd.seek(self._last_pos, os.SEEK_SET)
                for line in fd:
                    lines.append(line)
                if advance:
                    self._last_pos = fd.tell()
        return lines

    def scan_recent(self, pattern: re, timeout=10, advance=True) -> bool:
        if not os.path.isfile(self.path):
            return False
        with open(self.path) as fd:
            end = datetime.now() + timedelta(seconds=timeout)
            while True:
                fd.seek(self._last_pos, os.SEEK_SET)
                for line in fd:
                    if pattern.match(line):
                        return True
                if datetime.now() > end:
                    raise TimeoutError(f"pattern not found in error log after {timeout} seconds")
                time.sleep(.1)
        return False


class HexDumpScanner:

    def __init__(self, source):
        self._source = source

    def __iter__(self):
        data = b''
        offset = 0
        idx = 0
        for l in self._source:
            if offset == 0:
                m = re.match(r'^\s*0+(\s+-)?((\s+[0-9a-f]{2}){1,16})(\s+.*)$',
                             l, re.IGNORECASE)
                if m:
                    data = binascii.unhexlify(re.sub(r'\s+', '', m.group(2)))
                    offset = 16
                    idx = 1
                    continue
            else:
                m = re.match(r'^\s*([0-9a-f]+)(\s+-)?((\s+[0-9a-f]{2}){1,16})'
                             r'(\s+.*)$', l, re.IGNORECASE)
                if m:
                    loffset = int(m.group(1), 16)
                    if loffset == offset or loffset == idx:
                        data += binascii.unhexlify(re.sub(r'\s+', '',
                                                          m.group(3)))
                        offset += 16
                        idx += 1
                        continue
                    else:
                        sys.stderr.write(f'wrong offset {loffset}, expected {offset} or {idx}\n')
            # not a match
            if len(data) > 0:
                yield data
                data = b''
                offset = 0
        if len(data) > 0:
            yield data

