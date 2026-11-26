import json,collections,sys
t=json.load(open(sys.argv[2] if len(sys.argv)>2 else 'kit/dev/truth/truth.json'))
out=sys.argv[1] if len(sys.argv)>1 else 'out'
rep=json.load(open(out+'/report.json'))
sha2out={f['input_sha256']:f['output'] for f in rep['files']}
recs={}
for l in open(out+'/records.jsonl'):
    r=json.loads(l); recs[(r['file'],r['loc'])]=r['patient']
pt_units=collections.defaultdict(list)
for rel,f in t['files'].items():
    o=sha2out.get(f['sha256'])
    for loc,u in f['units'].items():
        if loc.startswith('@') or u['link']!='required': continue
        pt_units[u['patient']].append((recs.get((o,loc)),rel,loc))
for pt,us in sorted(pt_units.items()):
    c=collections.Counter(p for p,_,_ in us)
    if len(c)>1:
        main=c.most_common(1)[0][0]
        print(pt, t['patients'][pt]['traps'], dict(c))
        for p,rel,loc in us:
            if p!=main: print('    ',p,rel,loc)
