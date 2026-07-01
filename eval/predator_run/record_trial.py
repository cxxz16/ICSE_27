import sys, glob, os, re, shutil

cve, trial, vtype, trialout, rec_root, tte_ms, status, fuzz_el, budget = sys.argv[1:10]
recdir = os.path.join(rec_root, cve, f"trial{trial}")
os.makedirs(recdir, exist_ok=True)

def field2(b):
    p = b.split(',')
    return p[1] if len(p) > 1 and p[1].isdigit() else ''

def decode(path):
    d = open(path, 'rb').read()
    segs = d.split(b'\x00')
    names = ['cookie', 'GET(urlquery)', 'POST', 'headers']
    out = [f"file: {os.path.basename(path)}", f"total: {len(d)}B", f"has_canary(290363): {b'290363' in d}", ""]
    for i, n in enumerate(names):
        s = segs[i] if i < len(segs) else b''
        out.append(f"[{i}] {n} ({len(s)}B): {s.decode('latin-1')!r}")
    return "\n".join(out) + "\n"

crashes = [f for f in glob.glob(trialout + '/**/crashes/id:*', recursive=True) if 'README' not in f]

eff, eff_meta = None, ''
if vtype == 'sqli':
    if crashes:
        eff = sorted(crashes, key=lambda p: os.path.basename(p))[0]
        eff_meta = f"first_crash ({os.path.basename(eff)})"
else:
    best = None
    for f in glob.glob(trialout + '/**/queue/id:*', recursive=True):
        b = os.path.basename(f); ms = field2(b); dm = re.search(r'dist:(\d+)', b)
        if not ms or not dm:
            continue
        k = (int(dm.group(1)), int(ms))
        if best is None or k < best[0]:
            best = (k, f)
    if best:
        eff = best[1]
        eff_meta = f"reach_sink dist:{best[0][0]} ({os.path.basename(eff)})"

if eff and os.path.exists(eff):
    shutil.copy(eff, os.path.join(recdir, 'effective_input.bin'))
    open(os.path.join(recdir, 'effective_input.txt'), 'w').write(f"meta: {eff_meta}\n\n" + decode(eff))

if crashes:
    cdir = os.path.join(recdir, 'crashes'); os.makedirs(cdir, exist_ok=True)
    for c in crashes:
        safe = os.path.basename(c).replace(':', '_').replace(',', '_')
        shutil.copy(c, os.path.join(cdir, safe))
        open(os.path.join(cdir, safe + '.decoded.txt'), 'w').write(decode(c))

xss_hits = 0
for f in glob.glob(trialout + '/**/*.xss', recursive=True):
    try:
        xss_hits += open(f, encoding='latin-1').read().count('290363')
    except OSError:
        pass

tte_h = round(int(tte_ms) / 3600000, 4) if tte_ms and tte_ms.isdigit() else ''
with open(os.path.join(recdir, 'record.txt'), 'w') as f:
    f.write(
        f"cve = {cve}\ntrial = {trial}\nvuln_type = {vtype}\nstatus = {status}\n"
        f"TTE_ms = {tte_ms}\nTTE_h = {tte_h}\n"
        f"fuzz_elapsed_s = {fuzz_el}\nbudget_s = {budget}\n"
        f"effective_input = {eff_meta}\ncrash_count = {len(crashes)}\nxss_reflect_hits = {xss_hits}\n"
    )
print(f"recorded -> {recdir}")
