import sys, csv, os
sys.path.insert(0,'/home/user/research/Predator')
from VIPER.framework_routing.schema import detect_framework, load_schema
from VIPER.framework_routing import extract_routes
from VIPER.framework_routing.pipeline_bridge import resolve_entry_url

ids=['2025-4699','2026-7506','2023-2693','2023-2694','2023-2695','2023-2696','2023-2697',
     '2023-2770','2023-2771','2024-31821','2025-25775','2025-5155','2025-6094','2025-7568',
     '2025-10251','2025-56630','2018-16353','2018-16354','2025-13121','2019-11512','2020-29437']
rows={r['cve_id']:r for r in csv.DictReader(open('/home/user/research/Predator/VIPER/eval/cve_index.csv'))}

KN='/home/user/research/Predator/VIPER/framework_routing/knowledge'
print(f"{'cve':16s} {'app':16s} {'detect':13s} {'result / NULL attribution'}")
print('-'*112)
for i in ids:
    r=rows['CVE-'+i]
    app=r['app']; root=r['project_root_host']; sf=r['sink_file']; sl=int(r['sink_line']); port=r.get('container_port','')
    web=f"http://localhost:{port}"
    fw=detect_framework(root)
    fr=resolve_entry_url(sink_file_abs=sf,sink_line=sl,project_root=root,webroot_url=web,working_dir=None)
    if fr:
        out=f"HIT  {fr.http_method} {fr.entry_url}  [{fr.hit_kind}]"
    else:
        reason=f"NULL"
        try:
            if fw and fw not in ('flat_php',None):
                sc=load_schema(f'{KN}/{fw}.yaml'); rts=extract_routes(root,sc)
                shortf=sf.split('/')[-1]
                in_tbl=any(rt.handler_locator.file and shortf in rt.handler_locator.file for rt in rts)
                layer=('controller' if '/controller' in sf.lower() or 'controller' in shortf.lower()
                       else 'model' if 'model' in sf.lower() or shortf.lower().endswith('_m.php') or '_model' in shortf.lower()
                       else 'other')
                reason=f"NULL  routes={len(rts)} sink_file_in_table={in_tbl} layer={layer}"
            else:
                reason=f"NULL  (detect={fw})"
        except Exception as e:
            reason=f"NULL  (diag err {e})"
        out=reason
    print(f"{r['cve_id']:16s} {app:16s} {str(fw):13s} {out}")
