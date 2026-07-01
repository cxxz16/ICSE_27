import sys, csv, os
sys.path.insert(0,'/home/user/research/Predator')
from VIPER.framework_routing.schema import detect_framework
from VIPER.framework_routing.pipeline_bridge import resolve_entry_url
from pathlib import Path

REPO='/home/user/research/Predator'
ids=['2025-4699','2026-7506','2023-2693','2023-2694','2023-2695','2023-2696','2023-2697',
     '2023-2770','2023-2771','2024-31821','2025-25775','2025-5155','2025-6094','2025-7568',
     '2025-10251','2025-56630','2018-16353','2018-16354','2025-13121','2019-11512','2020-29437']
rows={r['cve_id']:r for r in csv.DictReader(open(f'{REPO}/VIPER/eval/cve_index.csv'))}

print(f"{'cve':16s} {'app':16s} {'detect':12s} {'hit':9s} entry")
print('-'*108)
hit=0
for i in ids:
    r=rows['CVE-'+i]; app=r['app']; root=r['project_root_host']
    sf=r['sink_file']; sl=int(r['sink_line']); port=r.get('container_port','')
    fw=detect_framework(root)
    slug=f"{app}-{r.get('version','')}"
    wd=Path(f"{REPO}/working/tchecker-results/eval-{slug}")
    wd=str(wd) if (wd/'call_graph.csv').exists() else None
    fr=resolve_entry_url(sink_file_abs=sf,sink_line=sl,project_root=root,
                         webroot_url=f"http://localhost:{port}",working_dir=wd)
    if fr:
        hit+=1
        out=f"{fr.hit_kind:8s} {fr.http_method} {fr.entry_url}" + (f"  (+{fr.candidate_count-1} more)" if fr.candidate_count>1 else "")
    else:
        out="NULL"
    print(f"{r['cve_id']:16s} {app:16s} {str(fw):12s} {'':9s}{out}")
print(f"\nhits: {hit}/21")
