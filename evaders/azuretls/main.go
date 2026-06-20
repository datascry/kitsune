// evaders/azuretls — drive azuretls-client (Go TLS/JA3 + HTTP/2 forger) through the edge.
// Forges a Chrome TLS handshake but a plain HTTP request profile — exercises the network-coherence tells.

package main
import (
	"crypto/tls"; "encoding/json"; "fmt"; "io"; "net/http"; "net/url"; "os"
	"github.com/Noooste/azuretls-client"
)
func main() {
	edge := os.Getenv("KITSUNE_EDGE"); if edge==""{edge="https://edge:8443/"}
	det := os.Getenv("KITSUNE_DETECTOR"); if det==""{det="http://detector:8080"}
	s := azuretls.NewSession(); s.InsecureSkipVerify = true
	if _, err := s.Get(edge); err != nil { fmt.Println("GET_ERR", err); return }
	u, _ := url.Parse(edge); sid := ""
	for _, c := range s.CookieJar.Cookies(u) { if c.Name=="ks_sid" { sid=c.Value } }
	if sid==""{ fmt.Println("NO_SID"); return }
	cl := &http.Client{Transport:&http.Transport{TLSClientConfig:&tls.Config{InsecureSkipVerify:true}}}
	r, err := cl.Get(det+"/verdict/"+sid); if err!=nil{ fmt.Println("VERDICT_ERR",err); return }
	body,_ := io.ReadAll(r.Body); var v map[string]interface{}; json.Unmarshal(body,&v)
	v["mode"]="azuretls"; b,_ := json.Marshal(v); fmt.Println("__KS__"+string(b))
}
