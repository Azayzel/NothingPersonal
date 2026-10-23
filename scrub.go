package main

import (
 "bytes"
 "compress/gzip"
 "errors"
 "fmt"
 "io"
 "net/http"
 "net/url"
 "os"
 "regexp"
 "sort"
 "strings"
)

const scanChunk = 64 << 10
const maxAuditHits = 1024

type scrubber struct {
 pattern *regexp.Regexp
 maxPattern int
 replacement []byte
}

func newScrubber(secrets []string, replacement string) (*scrubber,error) {
 seen:=make(map[string]bool)
 var variants []string
 add:=func(s string)error{
  if s=="" {return nil}
  if len(s)>scanChunk {return errors.New("secret exceeds 64 KiB")}
  k:=strings.ToLower(s)
  if !seen[k] {seen[k]=true;variants=append(variants,s)}
  return nil
 }
 for _,secret:=range secrets {
  if secret=="" {continue}
  for _,v:=range []string{secret,url.QueryEscape(secret),url.PathEscape(secret)} {
   if err:=add(v);err!=nil{return nil,err}
  }
 }
 if len(variants)==0{return nil,errors.New("no nonempty secrets configured")}
 sort.Slice(variants,func(i,j int)bool{return len(variants[i])>len(variants[j])})
 quoted:=make([]string,len(variants))
 maxLen:=0
 for i,v:=range variants {
  quoted[i]=regexp.QuoteMeta(v)
  if len(v)>maxLen{maxLen=len(v)}
 }
 pat,err:=regexp.Compile("(?i:"+strings.Join(quoted,"|")+")")
 if err!=nil{return nil,fmt.Errorf("compile secret patterns: %w",err)}
 if replacement!="" && pat.MatchString(replacement){return nil,errors.New("replacement contains a configured secret")}
 return &scrubber{pattern:pat,maxPattern:maxLen*4,replacement:[]byte(replacement)},nil
}
func recordHit(hits *[]string,where string){
 if len(*hits)<maxAuditHits{*hits=append(*hits,where)}
}
func (s *scrubber) contains(v string)bool{return s.pattern.MatchString(v)}
func (s *scrubber) string(v,where string,hits *[]string)string{return string(s.replace([]byte(v),where,hits))}
func (s *scrubber) replace(data []byte,where string,hits *[]string)[]byte {
 return s.pattern.ReplaceAllFunc(data,func(_ []byte)[]byte{
  recordHit(hits,where)
  return s.replacement
 })
}
// writeSafe flushes only complete matches, retaining enough lookbehind to
// catch a secret split across arbitrary Read boundaries.
func (s *scrubber) writeSafe(dst io.Writer,buf []byte,safe int,where string,hits *[]string)(int,error){
 consumed:=0
 for consumed<safe {
  loc:=s.pattern.FindIndex(buf[consumed:])
  if loc==nil || consumed+loc[0]>=safe {break}
  start,end:=consumed+loc[0],consumed+loc[1]
  if _,err:=dst.Write(buf[consumed:start]);err!=nil{return 0,err}
  if _,err:=dst.Write(s.replacement);err!=nil{return 0,err}
  recordHit(hits,where)
  consumed=end
 }
 if consumed<safe{
  if _,err:=dst.Write(buf[consumed:safe]);err!=nil{return 0,err}
  consumed=safe
 }
 return consumed,nil
}
func (s *scrubber) copy(dst io.Writer,src io.Reader,where string,hits *[]string,maxBytes int64)(int64,error){
 chunk:=make([]byte,scanChunk)
 pending:=make([]byte,0,scanChunk+s.maxPattern)
 var readTotal int64
 for {
  n,err:=src.Read(chunk)
  if n>0{
   readTotal+=int64(n)
   if maxBytes>0 && readTotal>maxBytes{return readTotal,errBodyTooLarge}
   pending=append(pending,chunk[:n]...)
   safe:=len(pending)-s.maxPattern+1
   if safe>0{
    used,werr:=s.writeSafe(dst,pending,safe,where,hits)
    if werr!=nil{return readTotal,werr}
    pending=append(pending[:0],pending[used:]...)
   }
  }
  if err==io.EOF{break}
  if err!=nil{return readTotal,err}
  if n==0{return readTotal,errors.New("reader made no progress")}
 }
 _,err:=s.writeSafe(dst,pending,len(pending),where,hits)
 return readTotal,err
}
var errBodyTooLarge=errors.New("request body exceeds configured inspection limit")
var errEncoding=errors.New("unsupported request content encoding")
var errAuthority=errors.New("request authority contains a configured secret")
var errSigned=errors.New("cannot safely modify a request with an integrity signature")

func (s *scrubber) scrubHeaders(h http.Header,where string,hits *[]string){
 for key,values:=range h{
  for i,value:=range values{values[i]=s.string(value,where+" "+key,hits)}
 }
}
// The request is staged only after its full inspection succeeds. The temp
// file stores ONLY redacted bytes. Caller cleans it up after RoundTrip.
func (s *scrubber) scrubRequest(req *http.Request,maxBody int64)(hits []string,cleanup func(),err error){
 cleanup=func(){}
 if s.contains(req.Host) || (req.URL!=nil && (s.contains(req.URL.Host) || (req.URL.User!=nil && s.contains(req.URL.User.String()+"@"+req.URL.Host)))) {
  return nil,cleanup,errAuthority
 }
 if req.URL!=nil{
  u:=req.URL
  u.Path=s.string(u.Path,"url path",&hits)
  u.RawPath=""
  u.RawQuery=s.string(u.RawQuery,"url query",&hits)
  u.Fragment=s.string(u.Fragment,"url fragment",&hits)
  if u.User!=nil{
   name:=s.string(u.User.Username(),"url userinfo",&hits)
   if pw,ok:=u.User.Password();ok{u.User=url.UserPassword(name,s.string(pw,"url userinfo",&hits))}else{u.User=url.User(name)}
  }
 }
 s.scrubHeaders(req.Header,"header",&hits)
 req.Header.Del("Proxy-Authorization")
 req.Header.Del("Proxy-Connection")
 if req.Body==nil || req.Body==http.NoBody{
  s.scrubHeaders(req.Trailer,"trailer",&hits)
  return hits,cleanup,nil
 }
 encoding:=strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Encoding")))
 if encoding!="" && encoding!="identity" && encoding!="gzip"{return hits,cleanup,errEncoding}
 original:=req.Body
 defer original.Close()
 temp,err:=os.CreateTemp("","nop-redacted-*")
 if err!=nil{return hits,cleanup,err}
 cleanup=func(){temp.Close();os.Remove(temp.Name())}
 cleanupTemp:=cleanup
 ok:=false
 defer func(){if !ok{cleanupTemp()}}()
 var decoded io.Reader=original
 if encoding=="gzip"{
  zr,zerr:=gzip.NewReader(original)
  if zerr!=nil{return hits,func(){},zerr}
  defer zr.Close()
  decoded=zr
 }
 var dst io.Writer=temp
 if encoding=="gzip"{
  zw:=gzip.NewWriter(temp)
  dst=zw
  _,err=s.copy(dst,decoded,"body",&hits,maxBody)
  cerr:=zw.Close()
  if err==nil{err=cerr}
 }else{
  _,err=s.copy(dst,decoded,"body",&hits,maxBody)
 }
 if err!=nil{return hits,func(){},err}
 s.scrubHeaders(req.Trailer,"trailer",&hits)
 modifiedBody:=false
 for _,h:=range hits{if h=="body"{modifiedBody=true;break}}
 if modifiedBody || encoding=="gzip"{
  for _,key:=range []string{"Content-MD5","Content-Digest","Digest","Repr-Digest","X-Amz-Content-Sha256"}{
   if req.Header.Get(key)!=""{return hits,func(){},errSigned}
  }
  if strings.HasPrefix(strings.ToUpper(req.Header.Get("Authorization")),"AWS4-HMAC-SHA256"){return hits,func(){},errSigned}
 }
 size,err:=temp.Seek(0,io.SeekEnd)
 if err!=nil{return hits,func(){},err}
 if _,err:=temp.Seek(0,io.SeekStart);err!=nil{return hits,func(){},err}
 req.Body=temp
 req.ContentLength=size
 req.TransferEncoding=nil
 req.Header.Del("Content-Length")
 req.Header.Del("Transfer-Encoding")
 req.GetBody=nil
 ok=true
 return hits,cleanup,nil
}
func joinedHits(hits []string)string{
 if len(hits)==0{return ""}
 counts:=map[string]int{}
 for _,h:=range hits{counts[h]++}
 keys:=make([]string,0,len(counts))
 for k:=range counts{keys=append(keys,k)}
 sort.Strings(keys)
 var b bytes.Buffer
 for i,k:=range keys{
  if i!=0{b.WriteString(", ")}
  b.WriteString(k)
  if counts[k]>1{fmt.Fprintf(&b," x%d",counts[k])}
 }
 if len(hits)==maxAuditHits{b.WriteString(" (at least 1024 hits; audit count capped)")}
 return b.String()
}
