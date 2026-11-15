package evidence
import("encoding/json";"os";"path/filepath";"testing";"externalcontrollayer.ai/ecl-1/go/crosscheck/strict")
func TestPublicReviewParentChildContext(t *testing.T){
 raw,e:=os.ReadFile(filepath.Join("..","..","..","tests","fixtures","repair-causal-context.json"));if e!=nil{t.Fatal(e)}
 var cases []struct{Name string `json:"name"`;Records json.RawMessage `json:"records"`;Status string `json:"status"`;Required []string `json:"required_findings"`};if e=json.Unmarshal(raw,&cases);e!=nil{t.Fatal(e)}
 for _,c:=range cases{t.Run(c.Name,func(t *testing.T){values,e:=strict.Parse(c.Records);if e!=nil{t.Fatal(e)};r,e:=AnalyzeGraph(values.([]any),nil,1000,128,[]string{"object_id"},true);if e!=nil{t.Fatal(e)};if r.Status!=c.Status{t.Fatalf("status %s want %s; %+v",r.Status,c.Status,r.Findings)};for _,code:=range c.Required{found:=false;for _,f:=range r.Findings{if f.RuleID==code{found=true}};if !found{t.Errorf("missing %s in %+v",code,r.Findings)}};if c.Status!="indeterminate"&&len(r.Findings)!=0{t.Errorf("unexpected %+v",r.Findings)}})}
}
