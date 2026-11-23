"""Find an element in an Android UI dump (uiautomator) and print its centre.

ui.py <dump.xml> text <regex>      first element whose text or content-desc matches
ui.py <dump.xml> id <resource-id>  first element with that resource-id
ui.py <dump.xml> texts             every non-empty text, one per line

Exit 1 when nothing matches. Reads only the dump; prints coordinates or texts.
"""
import re
import sys
import xml.etree.ElementTree as ET


def centre(bounds):
    x1, y1, x2, y2 = map(int, re.findall(r'\d+', bounds))
    return f'{(x1 + x2) // 2} {(y1 + y2) // 2}'


tree = ET.parse(sys.argv[1])
mode = sys.argv[2]
nodes = list(tree.iter('node'))
if mode == 'texts':
    for n in nodes:
        for key in ('text', 'content-desc'):
            if n.get(key):
                print(n.get(key))
    sys.exit(0)
want = sys.argv[3]
for n in nodes:
    if mode == 'id' and n.get('resource-id') == want:
        print(centre(n.get('bounds')))
        sys.exit(0)
    if mode == 'text' and any(re.search(want, n.get(k) or '') for k in ('text', 'content-desc')):
        print(centre(n.get('bounds')))
        sys.exit(0)
sys.exit(1)
