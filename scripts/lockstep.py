#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Structural gate for an EN/ZH mirrored pair of Markdown files.

Both files existing is not lockstep. A translation drifts by losing a
subsection, dropping a table row, or renumbering findings -- and every one of
those is invisible to a reader who only opens one language. So compare the two
documents as *structures* rather than as prose:

  * the full sequence of heading levels, in order (not just the count)
  * the number of fenced code blocks
  * the number of table rows, excluding separator rows
  * the sequence of finding IDs, if the document uses them
  * the multiset of inline code literals

Code literals are compared as a multiset, not in order: Chinese reorders the
terms in a sentence freely, but a command, path or identifier that appears in
one mirror and not the other means it was translated -- which makes it
uncopyable.

Prose length is deliberately not compared: Chinese runs shorter than English
for the same content, so a byte-ratio check would fire on every healthy pair.

Usage:
    scripts/lockstep.py EN.md ZH.md [--id-pattern 'F\\d+'] [--quiet]

Exit code 0 = GREEN, 1 = RED.
"""

import argparse
import collections
import re
import sys

HEADING = re.compile(r"^(#{1,6})\s")
SEPARATOR_ROW = re.compile(r"^\s*\|[\s:\-|]+\|\s*$")
INLINE_CODE = re.compile(r"`([^`]+)`")


def scan(path):
    """Return (heading levels, fence count, table rows, inline-code counter)."""
    heads, fences, rows, in_fence = [], 0, 0, False
    literals = collections.Counter()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("```"):
                fences += 1
                in_fence = not in_fence
                continue
            if in_fence:
                # Fenced blocks may carry translated comments -- house style.
                continue
            literals.update(INLINE_CODE.findall(line))
            m = HEADING.match(line)
            if m:
                heads.append(len(m.group(1)))
            elif line.lstrip().startswith("|") and line.rstrip().endswith("|"):
                if not SEPARATOR_ROW.match(line):
                    rows += 1
    return heads, fences, rows, literals


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("en")
    ap.add_argument("zh")
    ap.add_argument("--id-pattern", default="",
                    help="regex for finding IDs whose order must match; "
                         "empty (the default) disables the check")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    en_h, en_f, en_r, en_c = scan(args.en)
    zh_h, zh_f, zh_r, zh_c = scan(args.zh)
    ok, out = True, []

    out.append("headings    EN=%d  ZH=%d" % (len(en_h), len(zh_h)))
    if en_h == zh_h:
        out.append("  level sequence: IDENTICAL")
    else:
        ok = False
        for i, (a, b) in enumerate(zip(en_h, zh_h)):
            if a != b:
                out.append("  MISMATCH at heading #%d: EN=h%d ZH=h%d" % (i, a, b))
                break
        else:
            longer = "EN" if len(en_h) > len(zh_h) else "ZH"
            out.append("  MISMATCH: %s has %d extra heading(s) at the end"
                       % (longer, abs(len(en_h) - len(zh_h))))

    out.append("code fences EN=%d  ZH=%d  %s"
               % (en_f // 2, zh_f // 2, "OK" if en_f == zh_f else "MISMATCH"))
    ok &= en_f == zh_f
    out.append("table rows  EN=%d  ZH=%d  %s"
               % (en_r, zh_r, "OK" if en_r == zh_r else "MISMATCH"))
    ok &= en_r == zh_r

    if not args.id_pattern:
        out.append("finding IDs not applicable to this document")
    else:
        pat = re.compile(args.id_pattern)
        fe = pat.findall(open(args.en, encoding="utf-8").read())
        fz = pat.findall(open(args.zh, encoding="utf-8").read())
        out.append("finding IDs EN=%d  ZH=%d  %s"
                   % (len(fe), len(fz), "OK" if fe == fz else "MISMATCH"))
        if fe != fz:
            ok = False
            for i, (a, b) in enumerate(zip(fe, fz)):
                if a != b:
                    out.append("  first divergence at occurrence #%d: EN=%s ZH=%s"
                               % (i, a, b))
                    break

    only_en, only_zh = en_c - zh_c, zh_c - en_c
    out.append("code spans  EN=%d  ZH=%d  %s"
               % (sum(en_c.values()), sum(zh_c.values()),
                  "OK" if not (only_en or only_zh) else "MISMATCH"))
    if only_en or only_zh:
        ok = False
        for lit, n in list(only_en.items())[:8]:
            out.append("  only in EN (x%d): `%s`" % (n, lit))
        for lit, n in list(only_zh.items())[:8]:
            out.append("  only in ZH (x%d): `%s`" % (n, lit))

    if not args.quiet:
        print("%s  <->  %s" % (args.en, args.zh))
        print("\n".join(out))
        print("\nLOCKSTEP: %s" % ("GREEN" if ok else "RED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
