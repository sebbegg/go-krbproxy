package krbproxy

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	krb5spnego "github.com/jcmturner/gokrb5/v8/spnego"
)

type SpnegoAuth struct {
	client   *client.Client
	ccache   *credentials.CCache
	krb5conf *config.Config
}

func getConfig() (*config.Config, error) {

	confName := os.Getenv("KRB5_CONFIG")
	if confName == "" {
		confName = "/etc/krb5.conf"
	}

	data, err := ioutil.ReadFile(confName)
	if err != nil {
		fmt.Println("Could not read or find ", confName, err)
		return config.New(), nil
	}

	return config.NewFromString(string(data))
}

func NewSpnegoAuth() (*SpnegoAuth, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}

	ccpath := "/tmp/krb5cc_" + u.Uid

	ccname := os.Getenv("KRB5CCNAME")
	if len(ccname) > 0 {
		if strings.HasPrefix(ccname, "FILE:") {
			ccpath = strings.SplitN(ccname, ":", 2)[1]
		} else {
			ccpath = ccname
		}
	}

	ccache, err := credentials.LoadCCache(ccpath)
	if err != nil {
		return nil, err
	}

	config, err := getConfig()
	if err != nil {
		return nil, err
	}

	cl, err := client.NewFromCCache(ccache, config)
	if err != nil {
		return nil, err
	}

	fmt.Println("Using ccpath = ", ccpath)

	return &SpnegoAuth{
		ccache:   ccache,
		client:   cl,
		krb5conf: config,
	}, nil
}

func (s *SpnegoAuth) SetSPNEGOHeader(request *http.Request, header string) error {

	// remember currently set value
	previousHeader, headerWasSet := request.Header[krb5spnego.HTTPHeaderAuthRequest]
	err := krb5spnego.SetSPNEGOHeader(s.client, request, "")

	if err != nil {
		fmt.Println(err)
		return err
	}

	request.Header[header] = request.Header[krb5spnego.HTTPHeaderAuthRequest]
	if headerWasSet {
		request.Header[krb5spnego.HTTPHeaderAuthRequest] = previousHeader
	} else {
		request.Header.Del(krb5spnego.HTTPHeaderAuthRequest)
	}
	fmt.Println("Set header: %v: %v", header, request.Header[header])
	return nil
}
