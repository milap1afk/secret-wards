import re, sys, html
src = open(sys.argv[1], encoding='utf-8').read().split('\n')
def inl(t):
    t = html.escape(t, quote=False)
    t = re.sub(r'`([^`]+)`', r'<code>\1</code>', t)
    t = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', t)
    t = re.sub(r'(?<![*\w])\*([^*]+)\*(?!\*)', r'<i>\1</i>', t)
    return t
out = []; i = 0
while i < len(src):
    l = src[i]
    if l.startswith('```'):
        j = i + 1; buf = []
        while not src[j].startswith('```'): buf.append(html.escape(src[j])); j += 1
        out.append('<pre>' + '\n'.join(buf) + '</pre>'); i = j + 1; continue
    if l.startswith('# '): out.append(f'<h1>{inl(l[2:])}</h1>')
    elif l.startswith('## '): out.append(f'<h2>{inl(l[3:])}</h2>')
    elif l.startswith('- '):
        items = []
        while i < len(src) and src[i].startswith('- '): items.append(f'<li>{inl(src[i][2:])}</li>'); i += 1
        out.append('<ul>' + ''.join(items) + '</ul>'); continue
    elif l.startswith('|'):
        rows = []
        while i < len(src) and src[i].startswith('|'):
            cells = [c.strip() for c in src[i].strip().strip('|').split('|')]
            if not all(re.fullmatch(r':?-+:?', c) for c in cells): rows.append(cells)
            i += 1
        h = ''.join(f'<th>{inl(c)}</th>' for c in rows[0])
        b = ''.join('<tr>' + ''.join(f'<td>{inl(c)}</td>' for c in r) + '</tr>' for r in rows[1:])
        out.append(f'<table><thead><tr>{h}</tr></thead><tbody>{b}</tbody></table>'); continue
    elif l.strip(): out.append(f'<p>{inl(l)}</p>')
    i += 1
css = """@page{size:A4;margin:13mm 14mm}body{font:9.6pt/1.38 -apple-system,Helvetica,Arial,sans-serif;color:#111}
h1{font-size:15pt;margin:0 0 4px}h2{font-size:11.5pt;margin:10px 0 3px;border-bottom:1px solid #999;padding-bottom:1px}
p{margin:3px 0}ul{margin:3px 0;padding-left:16px}li{margin:2px 0}code{font:8.6pt Menlo,monospace;background:#f2f2f2;padding:0 2px}
pre{font:8.3pt/1.25 Menlo,monospace;background:#f5f5f5;padding:6px;margin:4px 0}
table{border-collapse:collapse;width:100%;font-size:8.6pt;margin:4px 0}th,td{border:1px solid #bbb;padding:2px 4px;text-align:left;vertical-align:top}th{background:#eee}tr{break-inside:avoid}h2{break-after:avoid}"""
print(f'<!doctype html><html><head><meta charset="utf-8"><title>Secret Wards brief</title><style>{css}</style></head><body>{"".join(out)}</body></html>')
