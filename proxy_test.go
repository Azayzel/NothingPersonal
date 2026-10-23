package main

import (
 "bytes"
 "crypto/tls"
 "crypto/x509"
 "io"
 "net"
 "net/http"
 "net/http/httptest"
 "net/url"
 "strings"
 "testing"
)
func startProxy(t *testing.T,upstreamCert *x509.Certificate)(*proxy,string){
 t.Helper()
 s:=testScrubber(t)
 c:=&config{caDir:t.TempDir(),maxBodyMiB:32}
 p,err:=makeProxy(s,c)
 if err!=nil{t.Fatal(err)}
 if upstreamCert!=nil{
  roots:=x509.NewCertPool()
  roots.AddCert(upstreamCert)
  p.tr.TLSClientConfig.RootCAs=roots
 }
 ln,err:=net.Listen("tcp","127.0.0.1:0")
 if err!=nil{t.Fatal(err)}
 srv:=newServer(p)
 go srv.Serve(ln)
 t.Cleanup(func(){srv.Close();p.tr.CloseIdleConnections()})
 return p,"http://"+ln.Addr().String()
}
func TestHTTPProxyRedactsWire(t *testing.T){
 origin:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  b,_:=io.ReadAll(r.Body)
  w.Write([]byte(r.Header.Get("User-Agent")+"|"+r.URL.RawQuery+"|"+string(b)))
 }))
 defer origin.Close()
 _,proxyURL:=startProxy(t,nil)
 u,_:=url.Parse(proxyURL)
 client:=&http.Client{Transport:&http.Transport{Proxy:http.ProxyURL(u)}}
 req,_:=http.NewRequest("POST",origin.URL+"/foo?q=You%40Example.com",strings.NewReader("some You@Example.com"))
 req.Header.Set("User-Agent","You@Example.com")
 res,err:=client.Do(req)
 if err!=nil{t.Fatal(err)}
 defer res.Body.Close()
 payload,_:=io.ReadAll(res.Body)
 if res.StatusCode!=200{t.Fatalf("status %d: %s",res.StatusCode,payload)}
 if bytes.Contains(bytes.ToLower(payload),[]byte("you@example.com")){t.Fatalf("escaped: %s",payload)}
}
func TestHTTPSMITMRedactsWire(t *testing.T){
 origin:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  b,_:=io.ReadAll(r.Body)
  w.Write([]byte(r.Header.Get("User-Agent")+"|"+string(b)))
 }))
 defer origin.Close()
 p,proxyURL:=startProxy(t,origin.Certificate())
 caPool:=x509.NewCertPool()
 caPool.AddCert(p.ca.cert)
 u,_:=url.Parse(proxyURL)
 client:=&http.Client{Transport:&http.Transport{
  Proxy:http.ProxyURL(u),
  TLSClientConfig:&tls.Config{RootCAs:caPool},
 }}
 req,_:=http.NewRequest("POST",origin.URL+"/api",strings.NewReader("You@Example.com"))
 req.Header.Set("User-Agent","You@Example.com")
 res,err:=client.Do(req)
 if err!=nil{t.Fatal(err)}
 defer res.Body.Close()
 payload,_:=io.ReadAll(res.Body)
 if res.StatusCode!=200{t.Fatalf("status %d: %s",res.StatusCode,payload)}
 if bytes.Contains(bytes.ToLower(payload),[]byte("you@example.com")){t.Fatalf("escaped: %s",payload)}
 if strings.Count(string(payload),"REDACTED")!=2{t.Fatalf("unexpected: %q",payload)}
}
func TestHTTPUpgradeRejected(t *testing.T){
 _,proxyURL:=startProxy(t,nil)
 res,err:=http.Get(proxyURL)
 if err!=nil{t.Fatal(err)}
 res.Body.Close()
 if res.Header.Get(probeHeader)!="0.4.0"{t.Fatalf("missing probe: %v",res.Header)}
 origin:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(200)}))
 defer origin.Close()
 u,_:=url.Parse(proxyURL)
 client:=&http.Client{Transport:&http.Transport{Proxy:http.ProxyURL(u)}}
 req,_:=http.NewRequest("GET",origin.URL,nil)
 req.Header.Set("Upgrade","websocket")
 res,err=client.Do(req)
 if err!=nil{t.Fatal(err)}
 res.Body.Close()
 if res.StatusCode!=403{t.Fatalf("got %d",res.StatusCode)}
}
