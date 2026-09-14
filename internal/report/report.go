package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/altrudev/MCP-DriftGuard/internal/canonical"
	mdiff "github.com/altrudev/MCP-DriftGuard/internal/diff"
)

func Snapshot(w io.Writer, s canonical.Snapshot, format string) error {
	if format == "json" {
		b,err:=json.MarshalIndent(s,"","  ")
		if err!=nil{return err}
		_,err=fmt.Fprintln(w,string(b))
		return err
	}
	h,err:=canonical.Hash(s)
	if err!=nil{return err}
	_,err=fmt.Fprintf(w,"MCP DriftGuard\nEndpoint: %s\nServer: %s %s\nProtocol: %s\nTools: %d  Resources: %d  Prompts: %d\nFingerprint: %s\n",s.Endpoint,s.Server.Name,s.Server.Version,s.Server.ProtocolVersion,len(s.Tools),len(s.Resources),len(s.Prompts),h)
	return err
}

func Diff(w io.Writer, r mdiff.Result, format string) error {
	if format=="json" {
		b,err:=json.MarshalIndent(r,"","  ")
		if err!=nil{return err}
		_,err=fmt.Fprintln(w,string(b))
		return err
	}
	verdict:="PASS"
	if !r.Match { if r.Score>=35 { verdict="FAIL" } else { verdict="REVIEW" } }
	if _,err:=fmt.Fprintf(w,"MCP DriftGuard\nVerdict: %s\nRisk: %s (%d/100)\n",verdict,r.Risk,r.Score); err!=nil{return err}
	for _,c:=range r.Changes { if _,err:=fmt.Fprintf(w,"%-8s %-13s %-8s %s — %s\n",c.Severity,c.Category,c.Kind,c.Path,c.Message); err!=nil{return err} }
	return nil
}
