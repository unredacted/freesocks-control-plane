"""Find an element in an Android UI dump (uiautomator) and print its centre.

ui.py <dump.xml> text <regex>      first element whose text or content-desc matches
ui.py <dump.xml> label <regex>     first element whose visible text matches
                                   (not its content-desc: an icon's description
                                   can share a button's label)
ui.py <dump.xml> id <resource-id>  first element with that resource-id
ui.py <dump.xml> texts             every non-empty text, one per line
ui.py <dump.xml> row <regex> <desc>  the button described <desc> in the row
                                   whose text matches <regex>

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
if mode == 'row':
    def box(n):
        return list(map(int, re.findall(r'\d+', n.get('bounds'))))
    rows = [n for n in nodes if re.search(want, n.get('text') or '')]
    if not rows:
        sys.exit(1)
    _, y1, _, y2 = box(rows[0])
    for n in nodes:
        if n.get('content-desc') == sys.argv[4]:
            _, b1, _, b2 = box(n)
            if y1 - 8 <= (b1 + b2) // 2 <= y2 + 8:
                print(centre(n.get('bounds')))
                sys.exit(0)
    sys.exit(1)
for n in nodes:
    if mode == 'id' and n.get('resource-id') == want:
        print(centre(n.get('bounds')))
        sys.exit(0)
    if mode == 'label' and re.search(want, n.get('text') or ''):
        print(centre(n.get('bounds')))
        sys.exit(0)
    if mode == 'text' and any(re.search(want, n.get(k) or '') for k in ('text', 'content-desc')):
        print(centre(n.get('bounds')))
        sys.exit(0)
sys.exit(1)
