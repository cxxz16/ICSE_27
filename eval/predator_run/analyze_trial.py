import sys, glob, os, re

T = sys.argv[1].rstrip('/')

def field2_ms(basename):
    parts = basename.split(',')
    return parts[1] if len(parts) > 1 and parts[1].isdigit() else ''

crashes = [f for f in glob.glob(T + '/**/crashes/id:*', recursive=True) if 'README' not in f]
crash_tte = ''
if crashes:
    c0 = sorted(crashes, key=lambda p: os.path.basename(p))[0]
    crash_tte = field2_ms(os.path.basename(c0))

best = None
for f in glob.glob(T + '/**/queue/id:*', recursive=True):
    b = os.path.basename(f)
    ms = field2_ms(b)
    if not ms:
        continue
    dm = re.search(r'dist:(\d+)', b)
    if not dm:
        continue
    key = (int(dm.group(1)), int(ms))
    if best is None or key < best:
        best = key
reach_tte = str(best[1]) if best else ''
reach_dist = str(best[0]) if best else ''

xss_hits = 0
for f in glob.glob(T + '/**/*.xss', recursive=True):
    try:
        xss_hits += open(f, encoding='latin-1').read().count('290363')
    except OSError:
        pass

print(f"{len(crashes)}\t{crash_tte}\t{reach_tte}\t{reach_dist}\t{xss_hits}")
