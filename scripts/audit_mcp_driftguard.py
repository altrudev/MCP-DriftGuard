#!/usr/bin/env python3
"""Run local suites, retaining failures and bounded logs. No telemetry or enrollment.
All temporary build/runtime output goes beneath --output; use /dev/shm.
The SDK acceptance needs Go 1.26; core remains Go 1.23+.
"""
import argparse,hashlib,json,os,subprocess,time
from pathlib import Path
root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description="Local operational suites; unavailable infrastructure remains nonzero evidence.")
parser.add_argument('--output',required=True)
parser.add_argument('--scope',choices=('all','mcp'),default='all',
                    help='mcp excludes optional Guardian/Rust suites and runs only MCP Python checks')
args=parser.parse_args()
out=Path(args.output).resolve();out.mkdir(parents=True,exist_ok=True)
for name in ('tmp','go','rust'):(out/name).mkdir(exist_ok=True)
env=dict(os.environ,TMPDIR=str(out/'tmp'),GOTMPDIR=str(out/'tmp'),GOCACHE=str(out/'go'),CARGO_TARGET_DIR=str(out/'rust'),PYTHONDONTWRITEBYTECODE='1',GOPROXY='off',GOSUMDB='off')
suites=[
('conformance',['python3','scripts/conformance_suite.py','--output',str(out/'conformance-final.json')]),
('go_core_race',['go','test','-race','./cmd/mcpdrift','./internal/baseline','./internal/canonical','./internal/diff','./internal/report','./internal/mcpserver']),
('go_stdio_security',['go','test','-race','./internal/observe','-run','Test(Stdio|Sandbox|RejectEndpointURLCredentialsBeforeNetwork|OAuthIssuerApprovalIsExactOrigin|GuardedDialRejects)']),
('go_observe_pure',['go','test','-race','./internal/observe','-run','Test(StdioTool|StdioSchema|StdioSandboxRejects|RejectEndpointURLCredentialsBeforeNetwork|OAuthIssuerApprovalIsExactOrigin|GuardedDialRejects)']),
('go_vet',['go','vet','./...']),
('sdk_e2e',['python3','scripts/test_mcp_server.py']),
('python',['python3','-m','unittest','discover','-s','scripts','-p','test_*.py']),
('release_mutations',['python3','scripts/test_release_integrity.py']),
('artifact_mutations',['python3','scripts/test_verify_artifacts.py']),
('historical_mutations',['python3','scripts/historical_mutation.py']),
('codex_host',['python3','scripts/test_codex_clean_config.py']),
('rust',['cargo','test','--manifest-path','broker/Cargo.toml','--locked','--offline']),
('python_with_rust',['python3','-m','unittest','discover','-s','scripts','-p','test_*.py']),
('rust_clippy',['cargo','clippy','--manifest-path','broker/Cargo.toml','--locked','--offline','--all-targets','--','-D','warnings']),
('rust_fmt',['cargo','fmt','--manifest-path','broker/Cargo.toml','--','--check']),
('cross_build',['python3','scripts/build_artifacts.py',str(out/'candidates')]),
('verify_candidates',['python3','scripts/verify_artifacts.py',str(out/'candidates')]),
('fuzz_canonical',['go','test','./internal/canonical','-run','^$','-fuzz','Fuzz','-fuzztime=200000x','-parallel=2']),
]
if args.scope == 'mcp':
 suites = [(name, cmd) for name, cmd in suites if name not in
           ('python', 'rust', 'python_with_rust', 'rust_clippy', 'rust_fmt')]
 suites.append(('mcp_python', ['python3', '-m', 'unittest', 'discover', '-s', 'scripts',
                              '-p', 'test_probe_local_mcp.py']))
report={'working_tree_dirty':bool(subprocess.check_output(['git','status','--porcelain','--untracked-files=no'],cwd=root,text=True).strip()),'started_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'base_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'suites':{}}
report['scope'] = args.scope
for name,cmd in suites:
 start=time.monotonic()
 suite_env=dict(env)
 if name=='python_with_rust':suite_env['FG_RUST_BINARIES']=str(out/'rust/debug')
 with (out/(name+'.log')).open('wb') as log:
  try: p=subprocess.run(cmd,cwd=root,env=suite_env,stdout=log,stderr=subprocess.STDOUT,timeout=240);status=p.returncode
  except subprocess.TimeoutExpired:status=124
 data=(out/(name+'.log')).read_bytes()
 report['suites'][name]={'command':cmd,'exit':status,'seconds':round(time.monotonic()-start,2),'log_sha256':hashlib.sha256(data).hexdigest()}
 (out/'results.json').write_text(json.dumps(report,indent=2)+'\n')
 print(name,status,flush=True)

report["passed"] = all(result["exit"] == 0 for result in report["suites"].values())
(out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
raise SystemExit(0 if report["passed"] else 1)
