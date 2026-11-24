"""Print the error lines of an app's logs with everything identifying masked:
for a beta run, whose public log must name no node, address or key.

scrub.py <names file> <file>...
                     lines mentioning an error, failure or exception, with
                     addresses, names, links, ids, keys, non-ASCII text and
                     every word of the raw config's entry names (<names file>,
                     one per line) masked; at most 40 lines of 200 characters
"""
import re
import sys

WANT = re.compile(r'error|fail|exception|panic|refused|denied|in use|timeout|cannot|unable', re.I)
MASKS = [
    (re.compile(r'[a-z][a-z0-9+.-]*://\S+', re.I), '<url>'),
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '<ipv4>'),
    (re.compile(r'\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\b', re.I), '<ipv6>'),
    (re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.I), '<uuid>'),
    (re.compile(r'\b[0-9a-f]{16,}\b', re.I), '<hex>'),
    (re.compile(r'[A-Za-z0-9+/_-]{20,}={0,2}'), '<token>'),
    (re.compile(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', re.I), '<name>'),
    (re.compile(r'[^\x00-\x7f]+'), '<text>'),
]
# Every word of the entry names (a place, a front): masked wherever it shows.
words = set()
try:
    for name in open(sys.argv[1], errors='replace'):
        words.update(w for w in re.findall(r'[A-Za-z][A-Za-z0-9-]{2,}', name))
except OSError:
    pass
if words:
    MASKS.insert(0, (re.compile(r'\b(?:' + '|'.join(map(re.escape, sorted(words, key=len, reverse=True))) + r')\b', re.I), '<entry>'))
out = []
for path in sys.argv[2:]:
    try:
        lines = open(path, errors='replace').read().splitlines()
    except OSError:
        continue
    for line in lines:
        if not WANT.search(line):
            continue
        for pattern, mask in MASKS:
            line = pattern.sub(mask, line)
        out.append(line[:200])
for line in out[-40:]:
    print(line)
