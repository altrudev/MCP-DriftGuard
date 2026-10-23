#!/usr/bin/env python3
import json,os,pathlib,subprocess,time
out=pathlib.Path('evidence/readiness-20261023/native-vps');out.mkdir(parents=True,exist_ok=True)
commands=[('conformance',['python3','scripts/conformance_suite.py','--output',str(out/'conformance.json')]),('race',['go','test','-race','./...']),('vet',['go','vet','./...']),('build_current',['go','build','-trimpath','-o',str(out/'mcpdrift-current'),'./cmd/mcpdrift']),('real_conduit',['python3','scripts/probe_local_mcp.py','--endpoint','http://127.0.0.1:8765/mcp','--binary',str(out/'mcpdrift-current'),'--output',str(out/'conduit.json')])]
results=[]
for name,argv in commands:
 started=time.time(); p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=1100);(out/(name+'.stdout.log')).write_text(p.stdout);(out/(name+'.stderr.log')).write_text(p.stderr)
 results.append({'name':name,'exit':p.returncode,'elapsed_seconds':round(time.time()-started,2)});print(f'{name}: {p.returncode}',flush=True)
(out/'summary.json').write_text(json.dumps(results,indent=2)+'\n')
raise SystemExit(0 if all(x['exit']==0 for x in results) else 1)
