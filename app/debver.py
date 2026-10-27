"""Debian version order (policy 5.6.12, epoch first) and the version-line rule shared by the reopen watch, the judge's evidence and the Verifier.
A fixed version in another release only says something about bookworm when it is on bookworm's line: the same source package (every
tracker row is per source package) and the same epoch. An epoch bump means Debian switched upstream lines (another fork, or back to an
older series), so 1:1.8.7-1 is not 'newer' than 1.10.3-3 in any useful sense even though Debian's order says it is."""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in ('core', 'exam'):
    if os.path.join(ROOT, p) not in sys.path: sys.path.insert(0, os.path.join(ROOT, p))
from build_item_facts import vcmp   # noqa: E402  (the same comparison the exam builder uses)


def epoch(v):
    return int(v.split(':', 1)[0]) if ':' in v else 0


def same_line(fixed, bookworm):
    return bool(bookworm) and all(epoch(fixed) == epoch(b) for b in bookworm)


def fix_newer(fixed, bookworm):
    """True when the fixed version is on bookworm's line and newer than every bookworm version (so bookworm still lacks it)."""
    return same_line(fixed, bookworm) and all(vcmp(fixed, b) > 0 for b in bookworm)


if __name__ == '__main__':
    assert not same_line('1:1.8.7-1', ['1.10.3-3']) and not fix_newer('1:1.8.7-1', ['1.10.3-3'])
    assert fix_newer('1.10.3-4', ['1.10.3-3']) and not fix_newer('1.10.3-3', ['1.10.3-3+deb12u1']) and fix_newer('2:1.0-1', ['2:0.9-1'])
    print('ok')
