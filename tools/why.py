"""Explain linkage for one input record: python3 tools/why.py <file> <loc>  (debug only, practice data)"""
import sys
from pathlib import Path
sys.path.insert(0, '.')
from wards.pipeline import Pipeline
from wards.link import Linker
pl = Pipeline(Path('kit/dev/input'), Path('/tmp/none'))
pl.ingest(); pl.resolve_date_orders(); pl.build_units(); pl.harvest()
lk = Linker(pl.evidence); assign = lk.run()
by = {(u.file, u.loc): u for u in pl.units}
u = by[(sys.argv[1], sys.argv[2])]
def show(ev):
    d = {k: v for k, v in ev.__dict__.items() if v and k not in ('rid',)}
    print('  ', d)
print('TARGET'); show(u.ev)
root = assign.get(u.ev.rid)
print('cluster root', root)
# records sharing any id/phone/name
keys = u.ev.uhids | u.ev.phones | u.ev.aadhaar
for o in pl.units:
    if o is u: continue
    if (o.ev.uhids | o.ev.phones | o.ev.aadhaar) & keys or (sys.argv[3:] and sys.argv[3] in str(o.ev.names)):
        print('RELATED', o.file, o.loc, 'root', assign.get(o.ev.rid)); show(o.ev)
