package canonical

import "testing"

func TestHashOrderIndependentForTools(t *testing.T){
	a:=Snapshot{Format:"mcpdrift-snapshot/v1",Endpoint:"https://x/mcp",Tools:[]Tool{{Name:"b"},{Name:"a"}}}
	b:=Snapshot{Format:"mcpdrift-snapshot/v1",Endpoint:"https://x/mcp",Tools:[]Tool{{Name:"a"},{Name:"b"}}}
	ha,_:=Hash(a); hb,_:=Hash(b)
	if ha!=hb{t.Fatalf("hash differs: %s != %s",ha,hb)}
}

func TestObservedAtExcludedFromHash(t *testing.T){
	a:=Snapshot{Format:"mcpdrift-snapshot/v1",ObservedAt:"one",Endpoint:"https://x/mcp"}
	b:=a;b.ObservedAt="two"
	ha,_:=Hash(a);hb,_:=Hash(b)
	if ha!=hb{t.Fatal("observation time changed identity hash")}
}
