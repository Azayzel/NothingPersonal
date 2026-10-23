package main

import (
 "bufio"
 "context"
 "crypto/tls"
 "crypto/x509"
 "errors"
 "fmt"
 "io"
 "log"
 "net"
 "net/http"
 "net/url"
 "os"
 "path/filepath"
 "strings"
 "time"
)

const probeHeader="X-Nothing-Personal"

type proxy struct {
 sc *scrubber
 ca *certAuthority
 tr *http.Transport
 noMITM map[string]bool
 quiet bool
 caPath string
 maxBody int64
}
func(p *proxy)logHits(method,host string,hits []string){
 if len(hits)!=0{log.Printf("REDACT %-7s %s [%s]",method,host,joinedHits(hits))}else if !p.quiet{log.Printf("clean  %-7s %s",method,host)}
}
func(p *proxy)ServeHTTP(w http.ResponseWriter,r *http.Request){
 if r.Method==http.MethodConnect{p.handleConnect(w,r);return}
 if !r.URL.IsAbs(){
  w.Header().Set(probeHeader,version)
  if r.Method!=http.MethodGet{http.Error(w,"method not allowed",http.StatusMethodNotAllowed);return}
  if r.URL.Path=="/ca.pem"{http.ServeFile(w,r,p.caPath);return}
  if r.URL.Path!="/"{http.NotFound(w,r);return}
  fmt.Fprintf(w,"NothingPersonal %s (local proxy)\n",version)
  return
 }
 if r.URL.Scheme!="http"{http.Error(w,"only HTTP proxy requests are supported",400);return}
 if !sameAuthority(r.Host,r.URL.Host,"80"){http.Error(w,"authority mismatch",400);return}
 if isUpgrade(r){http.Error(w,"upgraded connections cannot be scrubbed",403);return}
 out:=r.Clone(r.Context())
 out.RequestURI=""
 hits,cleanup,err:=p.sc.scrubRequest(out,p.maxBody)
 if err!=nil{
  http.Error(w,publicScrubError(err),scrubStatus(err))
  log.Printf("BLOCK %s %s: %v",r.Method,r.Host,err)
  return
 }
 defer cleanup()
 p.logHits(out.Method,out.URL.Host,hits)
 resp,err:=p.tr.RoundTrip(out)
 if err!=nil{http.Error(w,"upstream connection failed",http.StatusBadGateway);return}
 defer resp.Body.Close()
 copyResponse(w,resp)
}
func isUpgrade(r *http.Request)bool{
 return r.Header.Get("Upgrade")!="" || strings.Contains(strings.ToLower(r.Header.Get("Connection")),"upgrade")
}
func publicScrubError(err error)string{
 switch{
 case errors.Is(err,errBodyTooLarge):return "request exceeds inspection limit"
 case errors.Is(err,errEncoding):return "request encoding not supported for inspection"
 case errors.Is(err,errAuthority):return "request authority contains a protected value"
 case errors.Is(err,errSigned):return "cannot rewrite signed request"
 default:return "request inspection failed"
 }
}
func scrubStatus(err error)int{
 if errors.Is(err,errBodyTooLarge){return http.StatusRequestEntityTooLarge}
 if errors.Is(err,errEncoding){return http.StatusUnsupportedMediaType}
 return http.StatusUnprocessableEntity
}
func sameAuthority(a,b,defaultPort string)bool{
 parse:=func(s string)(string,string){
  host,port,err:=net.SplitHostPort(s)
  if err!=nil{return strings.ToLower(strings.TrimSuffix(s,".")),defaultPort}
  return strings.ToLower(strings.TrimSuffix(host,".")),port
 }
 ah,ap:=parse(a);bh,bp:=parse(b)
 return ah==bh && ap==bp
}
func copyResponse(w http.ResponseWriter,resp *http.Response){
 for k,vs:=range resp.Header{
  if hopHeader(k){continue}
  for _,v:=range vs{w.Header().Add(k,v)}
 }
 w.WriteHeader(resp.StatusCode)
 buf:=make([]byte,32<<10)
 fl,_:=w.(http.Flusher)
 for{
  n,err:=resp.Body.Read(buf)
  if n>0{
   if _,werr:=w.Write(buf[:n]);werr!=nil{return}
   if fl!=nil{fl.Flush()}
  }
  if err!=nil{return}
 }
}
func hopHeader(key string)bool{
 switch http.CanonicalHeaderKey(key){
 case "Connection","Proxy-Connection","Keep-Alive","Proxy-Authenticate","Proxy-Authorization","Te","Trailer","Transfer-Encoding","Upgrade":return true
 }
 return false
}
type readBufferedConn struct{net.Conn;r *bufio.Reader}
func(c readBufferedConn)Read(b []byte)(int,error){return c.r.Read(b)}

func(p *proxy)handleConnect(w http.ResponseWriter,r *http.Request){
 host,port,err:=net.SplitHostPort(r.Host)
 if err!=nil{host=r.Host;port="443"}
 if host=="" || port=="" || strings.ContainsAny(host," /\\") || p.sc.contains(r.Host){
  http.Error(w,"invalid CONNECT authority",400);return
 }
 destination:=net.JoinHostPort(host,port)
 hj,ok:=w.(http.Hijacker)
 if !ok{http.Error(w,"hijacking unsupported",500);return}
 tunnel:=p.noMITM[strings.ToLower(host)]
 var upstream net.Conn
 if tunnel{
  upstream,err=net.DialTimeout("tcp",destination,15*time.Second)
  if err!=nil{http.Error(w,"tunnel connection failed",502);return}
 }
 conn,rw,err:=hj.Hijack()
 if err!=nil{if upstream!=nil{upstream.Close()};return}
 defer conn.Close()
 if _,err=io.WriteString(conn,"HTTP/1.1 200 Connection Established\r\n\r\n");err!=nil{
  if upstream!=nil{upstream.Close()}
  return
 }
 buffered:=readBufferedConn{Conn:conn,r:rw.Reader}
 if tunnel{
  defer upstream.Close()
  log.Printf("UNINSPECTED tunnel %s (-no-mitm explicitly enabled)",destination)
  done:=make(chan struct{},2)
  go func(){io.Copy(upstream,buffered);if c,ok:=upstream.(*net.TCPConn);ok{c.CloseWrite()};done<-struct{}{}}()
  go func(){io.Copy(conn,upstream);done<-struct{}{}}()
  <-done
  return
 }
 tlsConn:=tls.Server(buffered,&tls.Config{
  MinVersion:tls.VersionTLS12,
  NextProtos:[]string{"http/1.1"},
  GetCertificate:func(hello *tls.ClientHelloInfo)(*tls.Certificate,error){
   if hello.ServerName!="" && !strings.EqualFold(strings.TrimSuffix(hello.ServerName,"."),strings.TrimSuffix(host,".")){
    return nil,errors.New("SNI differs from CONNECT destination")
   }
   return p.ca.leafFor(host)
  },
 })
 if err=tlsConn.Handshake();err!=nil{log.Printf("TLS handshake rejected for %s: %v",destination,err);return}
 defer tlsConn.Close()
 reader:=bufio.NewReader(tlsConn)
 for{
  request,rerr:=http.ReadRequest(reader)
  if rerr!=nil{return}
  if !sameAuthority(request.Host,destination,"443"){
   io.WriteString(tlsConn,"HTTP/1.1 421 Misdirected Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
   request.Body.Close()
   return
  }
  if isUpgrade(request){
   io.WriteString(tlsConn,"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
   request.Body.Close()
   return
  }
  request.URL.Scheme="https"
  request.URL.Host=destination
  request.RequestURI=""
  request=request.WithContext(context.Background())
  hits,cleanup,serr:=p.sc.scrubRequest(request,p.maxBody)
  if serr!=nil{
   status:=scrubStatus(serr)
   fmt.Fprintf(tlsConn,"HTTP/1.1 %d Blocked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",status)
   log.Printf("BLOCK %s %s: %v",request.Method,destination,serr)
   return
  }
  p.logHits(request.Method,destination,hits)
  response,terr:=p.tr.RoundTrip(request)
  cleanup()
  if terr!=nil{
   io.WriteString(tlsConn,"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
   return
  }
  closeAfter:=request.Close||response.Close
  err=response.Write(tlsConn)
  response.Body.Close()
  if err!=nil || closeAfter{return}
 }
}
func makeProxy(sc *scrubber,c *config)(*proxy,error){
 if err:=c.resolveCADir();err!=nil{return nil,err}
 ca,err:=loadOrCreateCA(c.caDir)
 if err!=nil{return nil,fmt.Errorf("CA setup: %w",err)}
 var upstream func(*http.Request)(*url.URL,error)
 if c.upstreamProxy!=""{
  u,err:=url.Parse(c.upstreamProxy)
  if err!=nil || u.Host=="" || (u.Scheme!="http"&&u.Scheme!="https"){
   return nil,errors.New("-upstream-proxy must be an http(s) URL")
  }
  upstream=http.ProxyURL(u)
 }
 roots,err:=x509.SystemCertPool()
 if err!=nil || roots==nil{roots=x509.NewCertPool()}
 if extra:=os.Getenv("NOP_UPSTREAM_CA");extra!=""{
  b,err:=os.ReadFile(extra)
  if err!=nil{return nil,fmt.Errorf("NOP_UPSTREAM_CA: %w",err)}
  if !roots.AppendCertsFromPEM(b){return nil,errors.New("NOP_UPSTREAM_CA contains no certificates")}
 }
 noMITM:=map[string]bool{}
 for _,h:=range strings.Split(c.noMITM,","){
  h=strings.ToLower(strings.TrimSpace(h))
  if h!=""{noMITM[h]=true}
 }
 return &proxy{
  sc:sc,ca:ca,noMITM:noMITM,quiet:c.quiet,maxBody:c.maxBodyMiB<<20,
  caPath:filepath.Join(c.caDir,caCertFile),
  tr:&http.Transport{
   Proxy:upstream,
   TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12,RootCAs:roots},
   ForceAttemptHTTP2:false,
   MaxIdleConns:32,
   MaxIdleConnsPerHost:8,
   ResponseHeaderTimeout:120*time.Second,
   TLSHandshakeTimeout:15*time.Second,
  },
 },nil
}
