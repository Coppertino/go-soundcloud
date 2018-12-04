// Package soundcloud provides a minimialist soundcloud API wrapper.
package soundcloud

import (
	"encoding/json"
	"github.com/pkg/errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

var (
	ErrNoRedirects = errors.New("no redirects")
	baseUrl        = "https://api.soundcloud.com"
	client         = &http.Client{CheckRedirect: noRedirects}
)

func noRedirects(_ *http.Request, _ []*http.Request) error {
	return ErrNoRedirects
}

type Api struct {
	ClientId     string
	ClientSecret string
	AccessToken  string
	RefreshToken string
}

func (api *Api) Authenticated() bool {
	return api.AccessToken != ""
}

// -- Implementation of request --

func buildGetRequest(urlStr string, params url.Values) (*http.Request, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	// If we are getting, then we can't merge query params
	if params != nil {
		if u.RawQuery != "" {
			return nil, errors.New("cannot merge query params in urlStr and params")
		}
		u.RawQuery = params.Encode()
	}

	u.Path += ".json"
	return http.NewRequest("GET", u.String(), nil)
}

func buildNonGetRequest(method, urlStr string, params url.Values) (*http.Request, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	// If we are getting, then we can't merge query params
	if u.RawQuery != "" {
		if params != nil {
			return nil, errors.New("cannot merge query params in urlStr and params")
		}
		params = u.Query()
		u.RawQuery = ""
	}

	if u.Path != "/oauth2/token" {
		u.Path += ".json"
	}
	return http.NewRequest(method, u.String(), strings.NewReader(params.Encode()))
}

func (api *Api) extendParams(p url.Values, auth ...bool) (url.Values, error) {
	if p == nil {
		p = url.Values{}
	}

	if len(auth) > 0 && auth[0] {
		if api.AccessToken != "" {
			p.Set("oauth_token", api.AccessToken)
		} else {
			return p, errors.New("access token required to use this endpoint")
		}
	} else {
		p.Set("client_id", api.ClientId)
	}
	return p, nil
}

func (api *Api) get(path string, params url.Values, r interface{}, auth ...bool) error {
	params, err := api.extendParams(params, auth...)
	if err != nil {
		return err
	}

	req, err := buildGetRequest(urlify(path), params)
	if err != nil {
		return err
	}
	return api.do(req, r)
}

func (api *Api) post(path string, params url.Values, r interface{}, auth ...bool) error {
	return api.nonGet("POST", path, params, r)
}

func (api *Api) put(path string, params url.Values, r interface{}, auth ...bool) error {
	return api.nonGet("PUT", path, params, r)
}

func (api *Api) delete(path string, params url.Values, r interface{}, auth ...bool) error {
	return api.nonGet("DELETE", path, params, r)
}

func (api *Api) nonGet(method, path string, params url.Values, r interface{}, auth ...bool) error {
	params, err := api.extendParams(params, auth...)
	if err != nil {
		return err
	}

	req, err := buildNonGetRequest(method, urlify(path), params)
	if err != nil {
		return err
	}
	return api.do(req, r)
}

func (api *Api) do(req *http.Request, r interface{}) error {
	resp, err := client.Do(req)
	if urlErr, ok := err.(*url.Error); ok && urlErr.Err == ErrNoRedirects {
		err = nil
	} else if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode > 399 {
		return newApiError(req, resp)
	}

	if err := decodeResponse(resp.Body, r); err != nil {
		return newApiErrorStack(err, req, resp)
	}
	return nil
}

func decodeResponse(body io.Reader, to interface{}) error {
	err := json.NewDecoder(body).Decode(to)

	if err != nil {
		return errors.Wrap(err, "soundcloud: error decoding body")
	}
	return nil
}

func urlify(path string) string {
	return baseUrl + path
}

func ensureParams(v url.Values) url.Values {
	if v == nil {
		return url.Values{}
	}
	return v
}
