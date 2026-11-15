package semantic_test

import (
    "bytes"
    "encoding/json"
    "reflect"
    "sort"
    "testing"
    "externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
    "externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
    "externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
)

func TestSchemaDispatchAndNamespaceBoundaries(t *testing.T) {
    var cases []struct {
        Name string `json:"name"`
        Value any `json:"value"`
        Schema *string `json:"schema"`
        SchemaValid bool `json:"expected_schema"`
        Rules []string `json:"expected_rules"`
    }
    dec := json.NewDecoder(bytes.NewReader(vectors.Read(t,"tests/fixtures/schema-boundaries.json")));dec.UseNumber()
    if err:=dec.Decode(&cases);err!=nil { t.Fatal(err) }
    for _,c:=range cases { t.Run(c.Name,func(t *testing.T) {
        if c.Schema!=nil { errors,err:=schema.ECL().Errors(*c.Schema,c.Value,1);if err!=nil || (len(errors)==0)!=c.SchemaValid { t.Fatalf("schema: %v %v",errors,err) } }
        found,err:=semantic.Validate(c.Value,semantic.Registered());if err!=nil {t.Fatal(err)}
        seen:=map[string]bool{};rules:=[]string{}
        for _,f:=range found { if !seen[f.RuleID] {rules=append(rules,f.RuleID);seen[f.RuleID]=true} };sort.Strings(rules)
        if !reflect.DeepEqual(rules,c.Rules) { t.Fatalf("rules %v, want %v",rules,c.Rules) }
    }) }
}

func TestSemanticNonobjectsUseRegisteredSchemaRefusal(t *testing.T) {
    for _,v:=range []any{nil,true,"text",[]any{},map[string]any{"records": []any{}}} {
        found,err:=semantic.Validate(v,semantic.Registered())
        if err!=nil || len(found)!=1 || found[0].RuleID!=semantic.SchemaInvalid {t.Fatalf("%T: %v %v",v,found,err)}
    }
}
