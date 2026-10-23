package main

import (
 "bytes"
 "compress/gzip"
 "errors"
 "io"
 "net/http"
 "net/url"
 "os"
 "strings"
 "testing"
)
func testScrubber(t *testing.T)*scrubber{
 t.Helper()
 s,err:=newScrubber([]string{"You@Example.com","555-0100"},"REDACTED")
 if err!=nil{t.Fatal(err)}
 return s
}
func TestScrubMetadataAndEncodedSecrets(t *testing.T){
 s:=testScrubber(t)
 r,_:=http.NewRequest("POST","https://host.test/a/you@example.com?q=You%40Example.com",strings.NewReader("hello You@Example.com"))
 r.Header.Set("User-Agent","bot You@Example.com")
 hits,cleanup,err:=s.scrubRequest(r,1<<20)
 if err!=nil{t.Fatal(err)}
 defer cleanup()
 payload,_:=io.ReadAll(r.Body)
 if strings.Contains(strings.ToLower(r.URL.String()+r.Header.Get("User-Agent")+string(payload)),"you@example.com"){t.Fatal("unredacted secret")}
 if r.URL.RawQuery!="q=REDACTED"{t.Fatalf("query: %s",r.URL.RawQuery)}
 if r.ContentLength!=int64(len(payload)){t.Fatalf("wrong content-length: %d",r.ContentLength)}
 if len(hits)<4{t.Fatalf("unexpected hits: %v",hits)}
}
func TestStreamCrossBoundaryAndLargeBodies(t *testing.T){
 s:=testScrubber(t)
 input:=strings.Repeat("x",scanChunk-4)+"You@Example.com"+strings.Repeat("z",5<<20)+"555-0100"
 var output bytes.Buffer
 var hits []string
 n,err:=s.copy(&output,strings.NewReader(input),"body",&hits,0)
 if err!=nil{t.Fatal(err)}
 if n!=int64(len(input)){t.Fatalf("consumed %d",n)}
 if strings.Contains(output.String(),"You@Example.com")||strings.Contains(output.String(),"555-0100"){t.Fatal("secret leaked from streamed payload")}
 if len(hits)!=2{t.Fatalf("expected 2 redactions, got %d",len(hits))}
}
func TestLargeBodyNeverPassesUnscrubbed(t *testing.T){
 s:=testScrubber(t)
 input:=strings.Repeat("z",5<<20)+"You@Example.com"
 req,_:=http.NewRequest("POST","http://example.org/upload",strings.NewReader(input))
 hits,cleanup,err:=s.scrubRequest(req,0)
 if err!=nil{t.Fatal(err)}
 defer cleanup()
 b,err:=io.ReadAll(req.Body)
 if err!=nil{t.Fatal(err)}
 if bytes.Contains(b,[]byte("You@Example.com")){t.Fatal("large body secret escaped")}
 if len(hits)!=1{t.Fatalf("hits: %v",hits)}
}
func TestOversizeBodyBlocked(t *testing.T){
 s:=testScrubber(t)
 req,_:=http.NewRequest("POST","http://example.org/upload",strings.NewReader(strings.Repeat("x",1025)))
 _,_,err:=s.scrubRequest(req,1024)
 if !errors.Is(err,errBodyTooLarge){t.Fatalf("expected body limit, got %v",err)}
}
func TestGzipBodyInspectedAndRemainsValid(t *testing.T){
 s:=testScrubber(t)
 var compressed bytes.Buffer
 zw:=gzip.NewWriter(&compressed)
 zw.Write([]byte(strings.Repeat("hello ",5000)+"You@Example.com"))
 zw.Close()
 req,_:=http.NewRequest("POST","http://example.org/upload",bytes.NewReader(compressed.Bytes()))
 req.Header.Set("Content-Encoding","gzip")
 hits,cleanup,err:=s.scrubRequest(req,1<<20)
 if err!=nil{t.Fatal(err)}
 defer cleanup()
 zr,err:=gzip.NewReader(req.Body)
 if err!=nil{t.Fatal(err)}
 b,err:=io.ReadAll(zr)
 if err!=nil{t.Fatal(err)}
 if bytes.Contains(b,[]byte("You@Example.com"))||!bytes.Contains(b,[]byte("REDACTED")){t.Fatal("gzip not redacted")}
 if len(hits)!=1{t.Fatalf("hits: %v",hits)}
}
func TestCompressedBombLimit(t *testing.T){
 s:=testScrubber(t)
 var buf bytes.Buffer
 z:=gzip.NewWriter(&buf)
 z.Write(bytes.Repeat([]byte("x"),1<<20))
 z.Close()
 req,_:=http.NewRequest("POST","http://example.org",bytes.NewReader(buf.Bytes()))
 req.Header.Set("Content-Encoding","gzip")
 _,_,err:=s.scrubRequest(req,1000)
 if !errors.Is(err,errBodyTooLarge){t.Fatalf("expected decompressed size failure: %v",err)}
}
func TestUnsupportedEncodingAndAuthorityFailClosed(t *testing.T){
 s:=testScrubber(t)
 req,_:=http.NewRequest("POST","http://example.org",strings.NewReader("hello"))
 req.Header.Set("Content-Encoding","br")
 _,_,err:=s.scrubRequest(req,0)
 if !errors.Is(err,errEncoding){t.Fatalf("got %v",err)}
 req2,_:=http.NewRequest("GET","http://you@example.com/path",nil)
 _,_,err=s.scrubRequest(req2,0)
 if !errors.Is(err,errAuthority){t.Fatalf("got %v",err)}
}
func TestReplaceWhenSecretIsReplacement(t *testing.T){
 if _,err:=newScrubber([]string{"redacted"},"REDACTED");err==nil{t.Fatal("unsafe replacement should fail")}
 s,err:=newScrubber([]string{"aaa"},"a")
 if err!=nil{t.Fatal(err)}
 var hits []string
 out:=s.string("aaaaaa","test",&hits)
 if out!="aa"{t.Fatalf("got %q",out)}
}
func TestUnicodeCasefoldDoesNotMisalignOffsets(t *testing.T){
 s,err:=newScrubber([]string{"ÄBC"},"REDACTED")
 if err!=nil{t.Fatal(err)}
 var hits []string
 out:=s.string("xäbc and ÄBC","test",&hits)
 if out!="xREDACTED and REDACTED"{t.Fatalf("got %q",out)}
}
func TestCACorruptionNeverSilentlyRotates(t *testing.T){
 dir:=t.TempDir()
 ca,err:=loadOrCreateCA(dir)
 if err!=nil{t.Fatal(err)}
 if _,err:=ca.leafFor("example.org");err!=nil{t.Fatal(err)}
 if _,err:=loadOrCreateCA(dir);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(dir+"/ca.pem",[]byte("corrupt"),0600);err!=nil{t.Fatal(err)}
 if _,err:=loadOrCreateCA(dir);err==nil{t.Fatal("must not rotate corrupted CA")}
}
func TestWithEnvRemovesProxyBypass(t *testing.T){
 got:=withEnv([]string{"NO_PROXY=example.org","https_proxy=http://bad:80","PATH=/bin"},proxyEnv("127.0.0.1:1234","/tmp/ca.pem"))
 merged:=strings.Join(got,"\n")
 if strings.Contains(merged,"example.org")||strings.Contains(merged,"http://bad"){t.Fatal("old proxy settings preserved")}
}
func TestCAAndSecretURLParsing(t *testing.T){
 if !sameAuthority("EXAMPLE.org:443","example.org","443"){t.Fatal("authority normalization")}
 if sameAuthority("example.org:8080","example.org:443","443"){t.Fatal("port mismatch not detected")}
 if _,err:=url.Parse("http://localhost:8787");err!=nil{t.Fatal(err)}
}


func TestAuditHitsBounded(t *testing.T){
 s,err:=newScrubber([]string{"z"},"X")
 if err!=nil{t.Fatal(err)}
 var hits []string
 var output bytes.Buffer
 _,err=s.copy(&output,strings.NewReader(strings.Repeat("z",500000)),"body",&hits,0)
 if err!=nil{t.Fatal(err)}
 if len(hits)!=maxAuditHits{t.Fatalf("audit unbounded: %d",len(hits))}
 if output.Len()!=500000{t.Fatal("replacement length changed unexpectedly")}
}
func TestUnicodeExpandedCaseFoldAcrossChunk(t *testing.T){
 s,err:=newScrubber([]string{"k"},"X")
 if err!=nil{t.Fatal(err)}
 var hits []string
 var output bytes.Buffer
 input:=strings.Repeat("x",scanChunk-1)+"K"
 _,err=s.copy(&output,strings.NewReader(input),"body",&hits,0)
 if err!=nil{t.Fatal(err)}
 if strings.Contains(output.String(),"K"){t.Fatal("Unicode folded secret crossed a chunk boundary")}
}
