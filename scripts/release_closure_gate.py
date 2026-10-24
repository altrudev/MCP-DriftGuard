#!/usr/bin/env python3
"""Fail release claims unless an explicit issue inventory was reviewed.

Invoke with a GitHub-issued JSON issue export and reviewed disposition file.
No network access or implicit inference of completion.
"""
import argparse
import json
import sys

p=argparse.ArgumentParser()
p.add_argument('--issues',required=True,help='GitHub issues JSON array')
p.add_argument('--dispositions',required=True,help='JSON mapping issue numbers to status and evidence')
a=p.parse_args()
issues=json.load(open(a.issues,encoding='utf-8'))
dispositions=json.load(open(a.dispositions,encoding='utf-8'))
errors=[]
reviewed=0
seen=set()
for issue in issues:
    if 'pull_request' in issue: continue
    reviewed+=1
    number=str(issue['number'])
    if number in seen or issue.get('state') not in ('open','closed'):
        errors.append('#'+number+' duplicate or invalid issue state')
    seen.add(number)
    entry=dispositions.get(number)
    if not isinstance(entry,dict) or entry.get('status') not in ('verified','deferred','blocked') or not isinstance(entry.get('evidence'),str) or not entry['evidence'].strip():
        errors.append('#'+number+' lacks reviewed disposition and evidence')
    elif issue.get('state')=='open' and entry['status']=='verified':
        errors.append('#'+number+' still open but marked verified; reconcile tracker')
if not reviewed: errors.append('empty issue inventory cannot establish closure')
if errors:
    print('RELEASE CLOSURE BLOCKED:\n'+'\n'.join(errors),file=sys.stderr)
    sys.exit(1)
print('Issue disposition inventory PASS (not a code certification)')
