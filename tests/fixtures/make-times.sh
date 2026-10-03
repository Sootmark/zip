#!/bin/sh
# Regenerates the times-*.zip fixtures (modification times). Made on Debian 13
# with Info-ZIP Zip 3.0, 7-Zip 25.01 and Python 3.13: run from tests/fixtures.
#
# a.txt was modified at 2021-03-04 05:06:07.123456789 UTC, b.txt at
# 1999-12-31 23:59:58 UTC. The archives are made in Europe/Paris (UTC+1 in
# winter), which shows only in the DOS fields: b.txt's DOS time is
# 2000-01-01 00:59:58 (Info-ZIP, Python). 7-Zip applies the zone's offset on
# the day it runs instead: the committed fixture was made in summer (UTC+2),
# so its DOS times are an hour later. Info-ZIP rounds odd seconds up.
set -eu
out=$(pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
rm -f "$out"/times-*.zip

printf 'first\n' > a.txt
printf 'second\n' > b.txt
touch -d '2021-03-04 05:06:07.123456789 UTC' a.txt
touch -d '1999-12-31 23:59:58 UTC' b.txt
export TZ=Europe/Paris

# Info-ZIP: DOS fields and an extended timestamp (0x5455), Unix seconds.
zip -q "$out/times-infozip.zip" a.txt b.txt
# 7-Zip: DOS fields and an NTFS extra field (0x000A), 100 ns FILETIMEs.
7z a -tzip -mtc=on -bso0 "$out/times-7zip-ntfs.zip" a.txt b.txt

python3 - "$out" <<'EOF'
import struct, sys, zipfile
from zipfile import ZipInfo

out = sys.argv[1]

# Python's zipfile: DOS fields only, from the files' local time.
with zipfile.ZipFile(f"{out}/times-python-dos.zip", "w") as z:
    z.write("a.txt")
    z.write("b.txt")

# DOS fields that are not a date (zipfile writes them unchecked), or zero.
with zipfile.ZipFile(f"{out}/times-invalid-dos.zip", "w") as z:
    for name, date_time in [
        ("month-13.txt", (2021, 13, 1, 0, 0, 0)),
        ("february-30.txt", (2021, 2, 30, 12, 0, 0)),
        ("hour-25.txt", (2021, 1, 1, 25, 0, 0)),
        ("zero.txt", (1980, 0, 0, 0, 0, 0)),
    ]:
        z.writestr(ZipInfo(name, date_time), b"x")

# Hostile extra fields, the same in local and central headers. Every entry's
# DOS time is 2020-01-02 03:04:06.
def field(id, body):
    return struct.pack("<HH", id, len(body)) + body

def ut(*seconds):
    return field(0x5455, struct.pack("<B", 1) + b"".join(struct.pack("<I", s) for s in seconds))

def ntfs(*attributes):
    return field(0x000A, b"\0\0\0\0" + b"".join(attributes))

def attribute(tag, body, size=None):
    return struct.pack("<HH", tag, len(body) if size is None else size) + body

def times(mtime):
    return struct.pack("<QQQ", mtime, mtime, mtime)

FILETIME_2020_09_13 = 132_444_736_000_000_000  # Unix 1_600_000_000
with zipfile.ZipFile(f"{out}/times-malformed-extra.zip", "w") as z:
    for name, extra in [
        ("ntfs-truncated-attribute.txt", ntfs(attribute(1, times(FILETIME_2020_09_13)[:8], 24)) + ut(1_600_000_000)),
        ("ntfs-attribute-overrun.txt", ntfs(attribute(1, b"", 0xFFFF))),
        ("ntfs-zero.txt", ntfs(attribute(1, times(0))) + ut(1_600_000_000)),
        ("ntfs-sentinel.txt", ntfs(attribute(1, times(0x7FFF_FFFF_FFFF_FFFF)))),
        ("ntfs-other-tag-first.txt", ntfs(attribute(2, b"abcd"), attribute(1, times(FILETIME_2020_09_13 + 1)))),
        ("ut-then-ntfs.txt", ut(1_700_000_000) + ntfs(attribute(1, times(FILETIME_2020_09_13)))),
        ("ut-without-mtime.txt", field(0x5455, b"\x01")),
        ("ut-flag-clear.txt", field(0x5455, struct.pack("<BI", 2, 1_600_000_000))),
        ("ut-zero.txt", ut(0)),
        ("duplicate-ut.txt", ut(1_600_000_000) + ut(1_700_000_000)),
        ("trailing-bytes.txt", ut(1_600_000_000) + b"\x0a\x00\x18"),
    ]:
        info = ZipInfo(name, (2020, 1, 2, 3, 4, 6))
        info.extra = extra
        z.writestr(info, b"x")
EOF
