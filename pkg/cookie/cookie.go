package cookie

import (
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
)

type AuthCookie struct {
	Data   string `json:"data"`
	OrgCID string `json:"org_custom_id"`
}

type SecureCookie struct {
	s       *securecookie.SecureCookie
	expires int
}

// SetExpires in seconds
func (c *SecureCookie) SetExpires(expiry int) {
	c.expires = expiry
	c.s.MaxAge(expiry)
}

func New(hashKey, blockKey []byte) *SecureCookie {
	c := &SecureCookie{}
	c.expires = 3700
	c.s = securecookie.New(hashKey, blockKey)
	c.s.MaxAge(c.expires)
	return c
}

func (c *SecureCookie) SetAuthCookie(w http.ResponseWriter, data string, orgCID string) error {
	value := &AuthCookie{Data: data, OrgCID: orgCID}
	encoded, err := c.s.Encode("linkai_auth", value)
	if err != nil {
		return err
	}
	cookie := &http.Cookie{
		Name:     "linkai_auth",
		Value:    encoded,
		Path:     "/app/",
		Expires:  time.Now().Add(time.Second * time.Duration(c.expires)),
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	return nil
}

func (c *SecureCookie) GetAuthCookie(cookie *http.Cookie) (*AuthCookie, bool, error) {
	value := &AuthCookie{}
	if err := c.s.Decode("linkai_auth", cookie.Value, &value); err != nil {
		return nil, false, err
	}

	if value.Data == "" {
		return nil, false, errors.New("invalid cookie")
	}
	return value, true, nil
}
