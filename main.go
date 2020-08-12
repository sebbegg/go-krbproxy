package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/sebbegg/go-krbproxy/krbproxy"
	"gopkg.in/elazarl/goproxy.v1"
)

func main() {

	spnegoAuth, err := krbproxy.NewSpnegoAuth()
	if err != nil {
		fmt.Println("Could not initialize spnego context:", err)
		return
	}

	setSpnegoHeader := func(req *http.Request) {
		fmt.Println("setting header")
		spnegoAuth.SetSPNEGOHeader(req, "Proxy-Authorization")
	}

	proxyURL := "http://localhost:3128"
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	proxy.Tr.Proxy = func(req *http.Request) (*url.URL, error) {
		return url.Parse(proxyURL)
	}
	proxy.ConnectDial = proxy.NewConnectDialToProxyWithHandler(proxyURL, setSpnegoHeader)
	proxy.OnRequest().Do(goproxy.FuncReqHandler(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		setSpnegoHeader(req)
		return req, nil
	}))

	log.Fatal(http.ListenAndServe(":8000", proxy))
}
