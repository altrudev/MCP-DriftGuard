#!/usr/bin/env python3
"""Verify historical regression tests detect deliberately reintroduced defects.
Runs mutations only in disposable source copies. Never edits the working tree.
"""
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
CASES=[
 ("B0_B2_JSON_CANONICAL","internal/diff/diff.go",
  "return ae == nil && be == nil && bytes.Equal(ac, bc)",
  "return ae == nil && be == nil && len(ac) >= 0 && len(bc) >= 0 && bytes.Equal(a, b)",
  "./internal/diff","TestSemanticallyIdenticalJSONIsNotDrift"),
 ("B6_SIGNED_DOWNGRADE","internal/baseline/baseline.go",
  'if len(publicKey) > 0 && a.Signature == nil {',
  'if false && len(publicKey) > 0 && a.Signature == nil {',
  "./internal/baseline","TestVerificationKeyRejectsUnsignedBaseline"),
 ("B5_ANNOTATION_ESCALATION","internal/diff/diff.go",
  "if annotationAuthorityExpanded(x.Annotations, y.Annotations) {",
  "if false && annotationAuthorityExpanded(x.Annotations, y.Annotations) {",
  "./internal/diff","TestFederationB5AnnotationAuthorityExpansion"),
 ("B3_SCHEMA_WIDENING","internal/diff/diff.go",
  "if !widen {",
  "if false && !widen {",
  "./internal/diff","TestFederationB3OptionalPropertyWidening"),
 ("OAUTH_ISSUER_APPROVAL","internal/observe/security.go",
  'if !sameOrigin(endpoint, asu) && !approvedAuthorizationIssuer(asu) {',
  'if false && !sameOrigin(endpoint, asu) && !approvedAuthorizationIssuer(asu) {',
  "./internal/observe","TestCrossOriginOAuthIssuerRequiresExplicitApproval"),
 ("STDIO_GROUP_KILL","internal/observe/process_linux.go",
  '_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)',
  '_ = syscall.Kill(-cmd.Process.Pid, syscall.Signal(0))',
  "python_stdio","linux_descendant_killed"),
 ("B7_BEARER_POST","internal/observe/modern.go",
  'req.Header.Set("Authorization", "Bearer "+token)',
  'req.Header.Set("X-Disabled-Authorization", "Bearer "+token)',
  "./internal/observe","TestBearerTokenForwardedToMCPRPCOnly"),
 ("B4B_PARAPHRASE","internal/diff/diff.go",
  'out = append(out, Change{Medium, "description",',
  'out = append(out, Change{Low, "description",',
  "./internal/diff","TestFederationB4bParaphrasedAuthorityInstruction"),
]
def go_mutation_detected(completed, test):
    output = completed.stdout + completed.stderr
    # A test panic caused by unavailable infrastructure is not a regression
    # assertion detecting the injected defect.
    return (completed.returncode != 0 and "--- FAIL: " + test in completed.stdout
            and "panic:" not in output and "operation not permitted" not in output)

def main():
    env = dict(os.environ)
    env["GOFLAGS"] = (env.get("GOFLAGS", "") + " -buildvcs=false").strip()
    revision=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    output={"format":"mcpdrift-historical-mutation/v1","revision":revision,"cases":[]}
    for name,path,needle,replacement,pkg,test in CASES:
        with tempfile.TemporaryDirectory(prefix="mcpdrift-mutation-") as temp:
            target=Path(temp)
            archive=subprocess.run(["git","archive","--format=tar",revision],cwd=ROOT,
                                   capture_output=True,check=True).stdout
            with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
                for item in bundle:
                    destination=(target/item.name).resolve()
                    if not destination.is_relative_to(target.resolve()):
                        raise ValueError("unsafe archived path")
                bundle.extractall(target,filter="data")
            source=target/path
            original=source.read_text()
            count=original.count(needle)
            if count!=1:
                output["cases"].append({"case":name,"passed":False,"reason":"mutation anchor count "+str(count)})
                continue
            source.write_text(original.replace(needle,replacement,1))
            if pkg=="python_stdio":
                completed=subprocess.run(["python3","skills/mcp-driftguard/test_stdio_transport.py"],
                                         cwd=target,env=env,capture_output=True,text=True,timeout=95)
                detectable=(completed.returncode != 0 and
                            ("linux_descendant_killed" in (completed.stdout+completed.stderr) or
                             ("subprocess.TimeoutExpired" in completed.stderr and
                              "--hang-with-child" in completed.stderr and
                              "timed out after 35 seconds" in completed.stderr)))
            else:
                completed=subprocess.run(["go","test",pkg,"-run","^"+test+"$","-count=1"],
                                         cwd=target,env=env,capture_output=True,text=True,timeout=90)
                detectable=go_mutation_detected(completed,test)
            output["cases"].append({"case":name,"passed":detectable,
                                    "test_exit":completed.returncode,
                                    "failure_excerpt":(completed.stdout+completed.stderr)[-450:]})
        print(name,"DETECTED" if output["cases"][-1]["passed"] else "NOT DETECTED",flush=True)
    output["passed"]=len(output["cases"])==len(CASES) and all(x["passed"] for x in output["cases"])
    print(json.dumps(output,indent=2,sort_keys=True))
    return 0 if output["passed"] else 1
if __name__=="__main__":
    raise SystemExit(main())
