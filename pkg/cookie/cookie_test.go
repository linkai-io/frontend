package cookie_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/linkai-io/frontend/pkg/cookie"
)

var (
	testHashKey  = []byte("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz012345678911")
	testBlockKey = []byte("abcdefghijklmnopqrstuvwxyz012345")
)

func TestCookie(t *testing.T) {
	c := cookie.New(testHashKey, testBlockKey)
	data := "1234"
	orgCID := "orgcid"
	subID := int32(9999)

	setHandler := func(w http.ResponseWriter, r *http.Request) {
		c.SetAuthCookie(w, data, orgCID, subID)
		fmt.Fprintf(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://auth/set", nil)
	w := httptest.NewRecorder()
	setHandler(w, req)
	cookie := w.Header().Get("Set-Cookie")
	if cookie == "" {
		t.Fatalf("failed to get cookie")
	}

	getHandler := func(w http.ResponseWriter, r *http.Request) {
		requestCookie, err := r.Cookie("linkai_auth")
		if err != nil {
			t.Fatalf("failed to read cookie from request: %v\n", err)
		}

		cookie, valid, err := c.GetAuthCookie(requestCookie)
		if err != nil {
			t.Fatalf("failed to get valid cookie %s\n", err)
		}
		if !valid {
			t.Fatalf("cookie values not set")
		}
		if cookie.Data != data {
			t.Fatalf("expected %v got %v\n", data, cookie.Data)
		}
		if cookie.SubscriptionID != subID {
			t.Fatalf("expected %v got %v\n", cookie.SubscriptionID, subID)
		}
	}
	req = httptest.NewRequest("GET", "http://auth/get", nil)
	req.Header.Set("Cookie", cookie)
	w = httptest.NewRecorder()
	getHandler(w, req)
}

func TestExpiredTestCookie(t *testing.T) {
	c := cookie.New(testHashKey, testBlockKey)
	c.SetExpires(1)
	data := "1234"
	orgCID := "orgCID"
	subID := int32(9999)

	setHandler := func(w http.ResponseWriter, r *http.Request) {
		c.SetAuthCookie(w, data, orgCID, subID)
		fmt.Fprintf(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://auth/set", nil)
	w := httptest.NewRecorder()
	setHandler(w, req)
	cookie := w.Header().Get("Set-Cookie")
	if cookie == "" {
		t.Fatalf("failed to get cookie")
	}

	t.Logf("sleeping...")
	time.Sleep(2 * time.Second)
	t.Logf("sleeping done...")

	getHandler := func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("linkai_auth")
		if err != nil {
			t.Fatalf("failed to read cookie from request: %v\n", err)
		}

		_, valid, err := c.GetAuthCookie(cookie)
		if err == nil || valid == true {
			t.Fatalf("error cookie was not expired!\n")
		}
	}
	req = httptest.NewRequest("GET", "http://auth/get", nil)
	t.Logf("%s\n", cookie)
	req.Header.Set("Cookie", cookie)
	w = httptest.NewRecorder()
	getHandler(w, req)
}
