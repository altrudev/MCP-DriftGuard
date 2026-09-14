package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/altrudev/MCP-DriftGuard/internal/canonical"
)

const defaultProtocolVersion = "2025-06-18"

type Client struct { HTTP *http.Client }

func New() *Client { return &Client{HTTP:&http.Client{Timeout:15*time.Second}} }

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type initResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ServerInfo      struct {
		Name string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
}

func (c *Client) Inspect(ctx context.Context, endpoint string) (canonical.Snapshot, error) {
	u, err := url.Parse(endpoint)
	if err != nil { return canonical.Snapshot{}, err }
	if u.Scheme!="http" && u.Scheme!="https" { return canonical.Snapshot{}, errors.New("endpoint must use http or https") }
	s := canonical.Snapshot{Format:"mcpdrift-snapshot/v1", ObservedAt:time.Now().UTC().Format(time.RFC3339), Endpoint:endpoint, Transport:canonical.Transport{Scheme:u.Scheme,Host:u.Host}}
	initPayload:=map[string]any{"jsonrpc":"2.0","id":1,"method":"initialize","params":map[string]any{"protocolVersion":defaultProtocolVersion,"capabilities":map[string]any{},"clientInfo":map[string]any{"name":"mcpdrift","version":"0.1.0"}}}
	resp, session, proto, err := c.rpc(ctx, endpoint, "", initPayload)
	if err != nil { return s, err }
	s.Transport.HTTPProtocol = proto
	if resp.Error != nil { return s, fmt.Errorf("initialize failed: %d %s", resp.Error.Code, resp.Error.Message) }
	var ir initResult
	if err := json.Unmarshal(resp.Result,&ir); err != nil { return s, fmt.Errorf("decode initialize result: %w",err) }
	s.Server=canonical.Server{Name:ir.ServerInfo.Name,Version:ir.ServerInfo.Version,ProtocolVersion:ir.ProtocolVersion}
	s.Capabilities=ir.Capabilities
	_ = c.notify(ctx, endpoint, session, map[string]any{"jsonrpc":"2.0","method":"notifications/initialized"})

	if hasCap(ir.Capabilities,"tools") {
		if r,e:=c.call(ctx,endpoint,session,2,"tools/list",map[string]any{}); e==nil {
			var v struct{Tools []struct{Name,Description string; InputSchema,Annotations json.RawMessage} `json:"tools"`}
			if json.Unmarshal(r.Result,&v)==nil { for _,x:=range v.Tools { s.Tools=append(s.Tools,canonical.Tool{Name:x.Name,Description:x.Description,InputSchema:x.InputSchema,Annotations:x.Annotations}) } }
		}
	}
	if hasCap(ir.Capabilities,"resources") {
		if r,e:=c.call(ctx,endpoint,session,3,"resources/list",map[string]any{}); e==nil {
			var v struct{Resources []struct{URI,Name,Description,MimeType string} `json:"resources"`}
			if json.Unmarshal(r.Result,&v)==nil { for _,x:=range v.Resources { s.Resources=append(s.Resources,canonical.Resource{URI:x.URI,Name:x.Name,Description:x.Description,MIMEType:x.MimeType}) } }
		}
	}
	if hasCap(ir.Capabilities,"prompts") {
		if r,e:=c.call(ctx,endpoint,session,4,"prompts/list",map[string]any{}); e==nil {
			var v struct{Prompts []struct{Name,Description string; Arguments json.RawMessage} `json:"prompts"`}
			if json.Unmarshal(r.Result,&v)==nil { for _,x:=range v.Prompts { s.Prompts=append(s.Prompts,canonical.Prompt{Name:x.Name,Description:x.Description,Arguments:x.Arguments}) } }
		}
	}
	if u.Scheme=="https" {
		if ti,err:=tlsInfo(u.Hostname(),u.Port()); err==nil { s.Transport.TLSSubject=ti.subject; s.Transport.TLSIssuer=ti.issuer; s.Transport.TLSNotAfter=ti.notAfter }
	}
	return s,nil
}

func hasCap(m map[string]any,k string) bool { _,ok:=m[k]; return ok }

func (c *Client) call(ctx context.Context, endpoint, session string,id int,method string,params any)(rpcResponse,error){
	r,_,_,err := c.rpc(ctx,endpoint,session,map[string]any{"jsonrpc":"2.0","id":id,"method":method,"params":params})
	return r,err
}

func (c *Client) rpc(ctx context.Context,endpoint,session string,payload any)(rpcResponse,string,string,error){
	b,_:=json.Marshal(payload)
	req,err:=http.NewRequestWithContext(ctx,http.MethodPost,endpoint,bytes.NewReader(b))
	if err!=nil{return rpcResponse{},"","",err}
	req.Header.Set("Content-Type","application/json")
	req.Header.Set("Accept","application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version",defaultProtocolVersion)
	if session!=""{req.Header.Set("Mcp-Session-Id",session)}
	res,err:=c.HTTP.Do(req)
	if err!=nil{return rpcResponse{},"","",err}
	defer res.Body.Close()
	if res.StatusCode<200||res.StatusCode>=300 {
		body,_:=io.ReadAll(io.LimitReader(res.Body,8192))
		return rpcResponse{},"",res.Proto,fmt.Errorf("HTTP %d from MCP endpoint: %s",res.StatusCode,strings.TrimSpace(string(body)))
	}
	raw,err:=readRPCBody(res.Body,res.Header.Get("Content-Type"))
	if err!=nil{return rpcResponse{},"",res.Proto,err}
	var rr rpcResponse
	if err:=json.Unmarshal(raw,&rr);err!=nil{return rr,"",res.Proto,err}
	return rr,res.Header.Get("Mcp-Session-Id"),res.Proto,nil
}

func (c *Client) notify(ctx context.Context,endpoint,session string,payload any) error {
	b,_:=json.Marshal(payload)
	req,err:=http.NewRequestWithContext(ctx,http.MethodPost,endpoint,bytes.NewReader(b))
	if err!=nil{return err}
	req.Header.Set("Content-Type","application/json")
	req.Header.Set("Accept","application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version",defaultProtocolVersion)
	if session!=""{req.Header.Set("Mcp-Session-Id",session)}
	res,err:=c.HTTP.Do(req)
	if err!=nil{return err}
	defer res.Body.Close()
	if res.StatusCode<200||res.StatusCode>=300{return fmt.Errorf("initialized notification HTTP %d",res.StatusCode)}
	return nil
}

func readRPCBody(r io.Reader,contentType string)([]byte,error){
	if strings.Contains(strings.ToLower(contentType),"text/event-stream") {
		sc:=bufio.NewScanner(r)
		for sc.Scan(){ line:=sc.Text(); if strings.HasPrefix(line,"data:"){ return []byte(strings.TrimSpace(strings.TrimPrefix(line,"data:"))),nil } }
		if err:=sc.Err();err!=nil{return nil,err}
		return nil,errors.New("SSE response contained no data event")
	}
	return io.ReadAll(io.LimitReader(r,4<<20))
}

type certInfo struct{subject,issuer,notAfter string}

func tlsInfo(host,port string)(certInfo,error){
	if port==""{port="443"}
	conn,err:=tls.DialWithDialer(&net.Dialer{Timeout:10*time.Second},"tcp",host+":"+port,&tls.Config{ServerName:host,MinVersion:tls.VersionTLS12})
	if err!=nil{return certInfo{},err}
	defer conn.Close()
	if len(conn.ConnectionState().PeerCertificates)==0{return certInfo{},errors.New("no peer certificate")}
	c:=conn.ConnectionState().PeerCertificates[0]
	return certInfo{c.Subject.String(),c.Issuer.String(),c.NotAfter.UTC().Format(time.RFC3339)},nil
}
