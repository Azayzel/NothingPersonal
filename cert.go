package main

import (
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/tls"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/pem"
 "errors"
 "fmt"
 "math/big"
 "net"
 "os"
 "path/filepath"
 "runtime"
 "strings"
 "sync"
 "time"
)
const caCertFile="ca.pem"
const caKeyFile="ca.key"

type certAuthority struct{
 cert *x509.Certificate
 key *ecdsa.PrivateKey
 mu sync.Mutex
 leaves map[string]*tls.Certificate
}
func randomSerial()(*big.Int,error){return rand.Int(rand.Reader,new(big.Int).Lsh(big.NewInt(1),127))}
func loadOrCreateCA(dir string)(*certAuthority,error){
 if err:=os.MkdirAll(dir,0700);err!=nil{return nil,err}
 certPath,keyPath:=filepath.Join(dir,caCertFile),filepath.Join(dir,caKeyFile)
 for _,path:=range []string{certPath,keyPath}{
  if fi,err:=os.Lstat(path);err==nil{
   if !fi.Mode().IsRegular(){return nil,fmt.Errorf("CA path is not a regular file: %s",path)}
   if path==keyPath && runtime.GOOS!="windows" && fi.Mode().Perm()&0077!=0{
    return nil,fmt.Errorf("insecure CA key permissions on %s; chmod 600",path)
   }
  }else if !errors.Is(err,os.ErrNotExist){return nil,err}
 }
 certPEM,cerr:=os.ReadFile(certPath)
 keyPEM,kerr:=os.ReadFile(keyPath)
 if cerr==nil && kerr==nil{
  cb,_:=pem.Decode(certPEM)
  kb,_:=pem.Decode(keyPEM)
  if cb==nil || kb==nil{return nil,errors.New("CA files malformed; repair manually, do not silently rotate")}
  cert,err:=x509.ParseCertificate(cb.Bytes)
  if err!=nil{return nil,err}
  key,err:=x509.ParseECPrivateKey(kb.Bytes)
  if err!=nil{return nil,err}
  if !cert.IsCA || time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) || !key.PublicKey.Equal(cert.PublicKey) {
   return nil,errors.New("CA pair invalid or expired; manually rotate the CA")
  }
  return &certAuthority{cert:cert,key:key,leaves:map[string]*tls.Certificate{}},nil
 }
 if !errors.Is(cerr,os.ErrNotExist) || !errors.Is(kerr,os.ErrNotExist){
  return nil,errors.New("incomplete or unreadable CA pair; correct files manually")
 }
 key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
 if err!=nil{return nil,err}
 serial,err:=randomSerial();if err!=nil{return nil,err}
 now:=time.Now()
 tmpl:=x509.Certificate{
  SerialNumber:serial,Subject:pkix.Name{CommonName:"NothingPersonal local CA",Organization:[]string{"NothingPersonal"}},
  NotBefore:now.Add(-time.Hour),NotAfter:now.AddDate(10,0,0),
  KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature,
  BasicConstraintsValid:true,IsCA:true,MaxPathLenZero:true,
 }
 der,err:=x509.CreateCertificate(rand.Reader,&tmpl,&tmpl,&key.PublicKey,key)
 if err!=nil{return nil,err}
 keyDER,err:=x509.MarshalECPrivateKey(key);if err!=nil{return nil,err}
 kf,err:=os.OpenFile(keyPath,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{return nil,err}
 if _,err=kf.Write(pem.EncodeToMemory(&pem.Block{Type:"EC PRIVATE KEY",Bytes:keyDER}));err!=nil{
  kf.Close();os.Remove(keyPath);return nil,err
 }
 if err=kf.Close();err!=nil{os.Remove(keyPath);return nil,err}
 cf,err:=os.OpenFile(certPath,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{return nil,err}
 if _,err=cf.Write(pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}));err!=nil{
  cf.Close();os.Remove(certPath);return nil,err
 }
 if err=cf.Close();err!=nil{os.Remove(certPath);return nil,err}
 cert,err:=x509.ParseCertificate(der)
 if err!=nil{return nil,err}
 return &certAuthority{cert:cert,key:key,leaves:map[string]*tls.Certificate{}},nil
}
func (ca *certAuthority)leafFor(name string)(*tls.Certificate,error){
 name=strings.TrimSuffix(strings.ToLower(name),".")
 ca.mu.Lock();defer ca.mu.Unlock()
 if c:=ca.leaves[name];c!=nil && c.Leaf!=nil && time.Until(c.Leaf.NotAfter)>time.Hour{return c,nil}
 serial,err:=randomSerial();if err!=nil{return nil,err}
 key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{return nil,err}
 now:=time.Now()
 tmpl:=x509.Certificate{
  SerialNumber:serial,Subject:pkix.Name{CommonName:name},NotBefore:now.Add(-time.Hour),NotAfter:now.Add(30*24*time.Hour),
  KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
 }
 if ip:=net.ParseIP(name);ip!=nil{tmpl.IPAddresses=[]net.IP{ip}}else{tmpl.DNSNames=[]string{name}}
 der,err:=x509.CreateCertificate(rand.Reader,&tmpl,ca.cert,&key.PublicKey,ca.key)
 if err!=nil{return nil,err}
 leaf,err:=x509.ParseCertificate(der)
 if err!=nil{return nil,err}
 c:=&tls.Certificate{Certificate:[][]byte{der,ca.cert.Raw},PrivateKey:key,Leaf:leaf}
 if len(ca.leaves)>=256{clear(ca.leaves)}
 ca.leaves[name]=c
 return c,nil
}
