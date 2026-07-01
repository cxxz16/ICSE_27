import sys, csv, re
sys.path.insert(0,'/home/user/research/Predator')
from VIPER.framework_routing.schema import detect_framework, load_schema
from VIPER.framework_routing import extract_routes
from VIPER.framework_routing.pipeline_bridge import resolve_entry_url, _build_cpg_caller_resolver
from VIPER.framework_routing.reverse_lookup import lookup
from pathlib import Path

REPO='/home/user/research/Predator'
rows={r['cve_id']:r for r in csv.DictReader(open(f'{REPO}/VIPER/eval/cve_index.csv'))}

CASES=['CVE-2025-67082',
       'CVE-2025-5155','CVE-2025-6094','CVE-2025-7568','CVE-2025-10251','CVE-2025-56630',
       'CVE-2018-16353','CVE-2018-16354',
       'CVE-2025-25775',
       'CVE-2025-4699','CVE-2026-7506',
       'CVE-2025-13121',
       'CVE-2023-2693','CVE-2023-2694','CVE-2023-2695','CVE-2023-2696','CVE-2023-2697','CVE-2023-2770','CVE-2023-2771']

def gt_path(url):
    p=re.sub(r'^https?://[^/]+','',url)
    return p

def derived_path(u):
    return re.sub(r'^https?://[^/]+','',u)

results=[]
for cve in CASES:
    r=rows[cve]; app=r['app']; root=r['project_root_host']; sf=r['sink_file']; sl=int(r['sink_line'])
    fw=detect_framework(root)
    slug=f"{app}-{r.get('version','')}"
    wdp=Path(f"{REPO}/working/tchecker-results/eval-{slug}")
    wd=str(wdp) if (wdp/'call_graph.csv').exists() else None
    gt=gt_path(r.get('entry_url',''))
    fr=resolve_entry_url(sink_file_abs=sf,sink_line=sl,project_root=root,webroot_url='',working_dir=wd)
    dv=derived_path(fr.entry_url) if fr else 'NULL'
    gt_noq=gt.split('?')[0].rstrip('/')
    dv_noq=dv.split('?')[0].rstrip('/')
    exact = gt_noq.endswith(dv_noq) and dv_noq!=''
    inset=False
    if not exact and fw and wd:
        sc=load_schema(f'{REPO}/VIPER/framework_routing/knowledge/{fw}.yaml')
        rts=extract_routes(root,sc)
        rel=str(Path(sf).resolve().relative_to(Path(root).resolve()))
        cg=_build_cpg_caller_resolver(wdp,Path(root),framework=fw)
        cs=lookup(rel,sl,rts,base_url='',call_graph_resolver=cg)
        paths={derived_path(c.materialized_url).split('?')[0].rstrip('/') for c in cs}
        inset=any(gt_noq.endswith(p) and p for p in paths)
    status='EXACT' if exact else ('IN-SET' if inset else 'NO')
    results.append((cve,app,fw,gt,dv,status))

print(f"{'case':16s} {'program':16s} {'framework':12s} {'match':7s}")
for cve,app,fw,gt,dv,st in results:
    print(f"{cve:16s} {app:16s} {str(fw):12s} {st}")
    print(f"    GT : {gt}")
    print(f"    out: {dv}")
import json
json.dump([{'cve':c,'app':a,'fw':f,'gt':g,'derived':d,'match':s} for c,a,f,g,d,s in results],
          open(f'/tmp/claude-999/-home-xinchu-research-Predator/48401a92-7aa7-4c43-8f32-cc8ff1f501fe/scratchpad/verify_list.json','w'),indent=2,ensure_ascii=False)
