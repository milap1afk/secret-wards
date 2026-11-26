import sys
sys.path.insert(0, '.')
from wards.detect import Detector
d = Detector()
for p in sys.argv[1:]:
    t = open(p, encoding='utf-8').read()
    print('=====', p)
    for s in d.detect(t):
        if s.kind in ('DATE', 'AGE'): continue
        print(f'{s.kind:14} {s.role:9} {t[s.start:s.end]!r:45} {s.meta.get("src","") or s.value[:12]}')
