"""Token retention (over-redaction detector): share of non-PII input tokens still present per unit."""
import collections, json, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent)); sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from score import load_unit_text, norm
dev, out = Path(sys.argv[1] if len(sys.argv) > 1 else 'kit/dev'), Path(sys.argv[2] if len(sys.argv) > 2 else 'o_dev')
truth = json.loads((dev / 'truth' / 'truth.json').read_text())
rep = json.loads((out / 'report.json').read_text())
by_out = {f['output']: f for f in rep['files'] if f.get('output')}
tot = kept = 0; lost = collections.Counter()
for rel, f in truth['files'].items():
    e = by_out.get('sanitized/' + rel) or next((x for x in rep['files'] if x['input_sha256'] == f['sha256'] and x.get('output')), None)
    if not e: continue
    for loc, un in f['units'].items():
        if loc.startswith('@'): continue
        tin = load_unit_text(dev / 'input' / rel, f['format'], loc); tout = load_unit_text(out / e['output'], f['format'], loc)
        if tin is None or tout is None: continue
        pii = set()
        for en in un['entities']:
            pii |= set(re.findall(r'\w+', norm(en['surface'])))
        for x in un.get('exclude', []):
            pii |= set(re.findall(r'\w+', norm(x)))
        ti = [t for t in re.findall(r'[^\W\d_]{2,}', norm(tin)) if t not in pii]
        to = collections.Counter(re.findall(r'[^\W\d_]{2,}', norm(tout)))
        for t in ti:
            tot += 1
            if to[t] > 0: to[t] -= 1; kept += 1
            else: lost[t] += 1
print(f'token retention {kept / tot:.4f}  ({tot - kept} of {tot} lost)')
print('most lost:', lost.most_common(25))
