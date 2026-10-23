// NothingPersonal (nop) is a local, best-effort HTTP(S) request redaction proxy.
// It is not a firewall: applications can bypass it by opening direct sockets.
package main

import (
 "context"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "log"
 "net"
 "net/http"
 "os"
 "os/exec"
 "os/signal"
 "path/filepath"
 "runtime"
 "strings"
 "syscall"
 "time"
)

const version="0.4.0"
const defaultListen="127.0.0.1:8787"

type stringList []string
func(s *stringList)String()string{return fmt.Sprint([]string(*s))}
func(s *stringList)Set(v string)error{*s=append(*s,v);return nil}
type config struct{
 listen,caDir,replacement,redactFile,noMITM,upstreamProxy string
 redact stringList
 auto,quiet bool
 maxBodyMiB int64
}
func flags(fs *flag.FlagSet)*config{
 c:=&config{}
 fs.StringVar(&c.listen,"listen",defaultListen,"local listening address (run defaults to an ephemeral port)")
 fs.StringVar(&c.caDir,"ca-dir","","local CA directory (default ~/.nop)")
 fs.StringVar(&c.replacement,"replacement","REDACTED","replacement string")
 fs.Var(&c.redact,"redact","literal secret; repeatable (prefer -redact-file)")
 fs.StringVar(&c.redactFile,"redact-file","","private file containing one secret per line")
 fs.BoolVar(&c.auto,"auto",true,"discover account email in ~/.claude.json")
 fs.BoolVar(&c.quiet,"quiet",false,"log only blocks/redactions/tunnels")
 fs.StringVar(&c.noMITM,"no-mitm","","explicit UNSCRUBBED CONNECT tunnel hosts, comma-separated")
 fs.StringVar(&c.upstreamProxy,"upstream-proxy","","optional HTTP(S) upstream proxy URL")
 fs.Int64Var(&c.maxBodyMiB,"max-body-mib",1024,"maximum decoded request body in MiB; 0 = unlimited (disk usage risk)")
 return c
}
func(c *config)resolveCADir()error{
 if c.caDir!=""{return nil}
 home,err:=os.UserHomeDir()
 if err!=nil{return err}
 c.caDir=filepath.Join(home,".nop")
 return nil
}
func autoSecrets()[]string{
 home,err:=os.UserHomeDir()
 if err!=nil{return nil}
 b,err:=os.ReadFile(filepath.Join(home,".claude.json"))
 if err!=nil{return nil}
 var cfg struct{OAuthAccount struct{EmailAddress string}}
 if json.Unmarshal(b,&cfg)!=nil{return nil}
 if cfg.OAuthAccount.EmailAddress==""{return nil}
 log.Print("Auto-detected Claude account email (value not logged)")
 return []string{cfg.OAuthAccount.EmailAddress}
}
func(c *config)secrets()([]string,error){
 secrets:=append([]string{},c.redact...)
 if c.auto{secrets=append(secrets,autoSecrets()...)}
 if c.redactFile!=""{
  fi,err:=os.Stat(c.redactFile)
  if err!=nil{return nil,err}
  if !fi.Mode().IsRegular(){return nil,errors.New("redact-file is not a regular file")}
  if runtime.GOOS!="windows" && fi.Mode().Perm()&0077!=0{
   return nil,errors.New("redact-file must have permissions 0600")
  }
  data,err:=os.ReadFile(c.redactFile)
  if err!=nil{return nil,err}
  for _,s:=range strings.Split(string(data),"\n"){
   s=strings.TrimSpace(s)
   if s!="" && !strings.HasPrefix(s,"#"){secrets=append(secrets,s)}
  }
 }
 if len(secrets)==0{return nil,errors.New("no secrets: use -redact, -redact-file, or sign into Claude Code")}
 return secrets,nil
}
func(c *config)build()(*proxy,error){
 if c.maxBodyMiB<0 || c.maxBodyMiB>int64(^uint64(0)>>1)>>20{
  return nil,errors.New("invalid -max-body-mib")
 }
 secrets,err:=c.secrets()
 if err!=nil{return nil,err}
 sc,err:=newScrubber(secrets,c.replacement)
 if err!=nil{return nil,err}
 return makeProxy(sc,c)
}
func listener(addr string)(net.Listener,error){
 host,_,err:=net.SplitHostPort(addr)
 if err!=nil{return nil,err}
 ips,err:=net.LookupIP(host)
 if err!=nil{return nil,err}
 for _,ip:=range ips{
  if !ip.IsLoopback(){return nil,errors.New("refusing non-loopback listener")}
 }
 if len(ips)==0{return nil,errors.New("listener did not resolve")}
 return net.Listen("tcp",addr)
}
func newServer(p *proxy)*http.Server{
 return &http.Server{Handler:p,ReadHeaderTimeout:10*time.Second,IdleTimeout:90*time.Second}
}
func proxyEnv(addr,caPath string)map[string]string{
 proxyURL:="http://"+addr
 return map[string]string{
  "HTTP_PROXY":proxyURL,"http_proxy":proxyURL,"HTTPS_PROXY":proxyURL,"https_proxy":proxyURL,
  "NO_PROXY":"","no_proxy":"",
  "NODE_EXTRA_CA_CERTS":caPath,
  "CURL_CA_BUNDLE":caPath,
  "REQUESTS_CA_BUNDLE":caPath,
  "SSL_CERT_FILE":caPath,
 }
}
func withEnv(existing []string,overrides map[string]string)[]string{
 out:=make([]string,0,len(existing)+len(overrides))
 for _,kv:=range existing{
  name,_,ok:=strings.Cut(kv,"=")
  if !ok{continue}
  drop:=false
  for key:=range overrides{
   if strings.EqualFold(name,key){drop=true;break}
  }
  if !drop{out=append(out,kv)}
 }
 for k,v:=range overrides{out=append(out,k+"="+v)}
 return out
}
func runCmd(args []string)int{
 fs:=flag.NewFlagSet("nop run",flag.ContinueOnError)
 c:=flags(fs)
 fs.Usage=func(){fmt.Fprintln(os.Stderr,"usage: nop run [flags] -- <command> [args...]");fs.PrintDefaults()}
 if err:=fs.Parse(args);err!=nil{return 2}
 cmdArgs:=fs.Args()
 if len(cmdArgs)>0 && cmdArgs[0]=="--"{cmdArgs=cmdArgs[1:]}
 if len(cmdArgs)==0{fs.Usage();return 2}
 // Never reuse an unknown proxy: its secret list may not match this session.
 // Ephemeral loopback ports permit protected concurrent sessions.
 if c.listen==defaultListen{c.listen="127.0.0.1:0"}
 p,err:=c.build()
 if err!=nil{log.Printf("guard: refusing unprotected launch: %v",err);return 1}
 ln,err:=listener(c.listen)
 if err!=nil{log.Printf("guard: refusing unprotected launch: %v",err);return 1}
 srv:=newServer(p)
 done:=make(chan error,1)
 go func(){done<-srv.Serve(ln)}()
 defer func(){
  ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
  defer cancel()
  srv.Shutdown(ctx)
  p.tr.CloseIdleConnections()
 }()
 addr:=ln.Addr().String()
 log.Printf("guard: protected proxy running on %s",addr)
 command:=exec.Command(cmdArgs[0],cmdArgs[1:]...)
 command.Stdin=os.Stdin;command.Stdout=os.Stdout;command.Stderr=os.Stderr
 command.Env=withEnv(os.Environ(),proxyEnv(addr,p.caPath))
 if err:=command.Start();err!=nil{log.Printf("guard: exec failed: %v",err);return 127}
 sigs:=make(chan os.Signal,1)
 signal.Notify(sigs,os.Interrupt,syscall.SIGTERM)
 defer signal.Stop(sigs)
 finished:=make(chan error,1)
 go func(){finished<-command.Wait()}()
 select{
 case err:=<-finished:
  if err==nil{return 0}
  var ee *exec.ExitError
  if errors.As(err,&ee){return ee.ExitCode()}
  log.Printf("guard: child error: %v",err)
  return 1
 case sig:=<-sigs:
  if command.Process!=nil{command.Process.Signal(sig)}
  err:=<-finished
  if err==nil{return 0}
  var ee *exec.ExitError
  if errors.As(err,&ee){return ee.ExitCode()}
  return 130
 case err:=<-done:
  log.Printf("guard: protection stopped: %v",err)
  if command.Process!=nil{command.Process.Kill()}
  <-finished
  return 1
 }
}
func printEnv(c *config,ps bool)error{
 if err:=c.resolveCADir();err!=nil{return err}
 addr:=c.listen
 if strings.HasPrefix(addr,":"){addr="127.0.0.1"+addr}
 values:=proxyEnv(addr,filepath.Join(c.caDir,caCertFile))
 for _,k:=range []string{
  "HTTP_PROXY","http_proxy","HTTPS_PROXY","https_proxy",
  "NO_PROXY","no_proxy","NODE_EXTRA_CA_CERTS","CURL_CA_BUNDLE",
  "REQUESTS_CA_BUNDLE","SSL_CERT_FILE",
 }{
  v:=values[k]
  if ps{
   v=strings.ReplaceAll(v,"'","''")
   fmt.Printf("$env:%s = '%s'\n",k,v)
  }else{
   v=strings.ReplaceAll(v,"'","'\\''")
   fmt.Printf("export %s='%s'\n",k,v)
  }
 }
 return nil
}
func main(){
 log.SetFlags(log.Ltime)
 if len(os.Args)>1 && os.Args[1]=="run"{os.Exit(runCmd(os.Args[2:]))}
 fs:=flag.NewFlagSet("nop",flag.ExitOnError)
 c:=flags(fs)
 envOut:=fs.Bool("env",false,"print proxy environment exports without starting the proxy")
 powerShell:=fs.Bool("powershell",false,"with -env: emit PowerShell syntax")
 showVersion:=fs.Bool("version",false,"print version")
 fs.Parse(os.Args[1:])
 if *showVersion{fmt.Println("NothingPersonal",version);return}
 if *envOut{if err:=printEnv(c,*powerShell);err!=nil{log.Fatal(err)};return}
 p,err:=c.build()
 if err!=nil{log.Fatal(err)}
 ln,err:=listener(c.listen)
 if err!=nil{log.Fatal(err)}
 srv:=newServer(p)
 log.Printf("NothingPersonal %s listening on %s; CA %s",version,ln.Addr(),p.caPath)
 log.Print("WARNING: proxy variables are cooperative, NOT an egress firewall. Unsupported encodings/upgrades are blocked.")
 sigs:=make(chan os.Signal,1)
 signal.Notify(sigs,os.Interrupt,syscall.SIGTERM)
 go func(){
  <-sigs
  ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
  defer cancel()
  srv.Shutdown(ctx)
 }()
 if err:=srv.Serve(ln);err!=nil && !errors.Is(err,http.ErrServerClosed){log.Fatal(err)}
 p.tr.CloseIdleConnections()
 io.WriteString(os.Stderr,"nop stopped\n")
}
