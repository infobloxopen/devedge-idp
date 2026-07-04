package idp

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// newDeviceTestHandler builds a login handler over a fresh storage that has one
// device authorization stored (client=example, the given user code), and returns
// the handler plus the storage so a test can approve and then inspect state.
func newDeviceTestHandler(t *testing.T, userCode string) (http.Handler, *Storage) {
	t.Helper()
	storage, err := NewStorage(seedClients())
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	// A static issuer keeps the handler's issuer interceptor host-independent.
	provider, err := newProvider("http://idp.dev.test", storage, slog.Default())
	if err != nil {
		t.Fatalf("newProvider: %v", err)
	}
	if err := storage.StoreDeviceAuthorization(context.Background(), exampleClientID,
		"device-code-1", userCode, time.Now().Add(5*time.Minute), []string{"openid"}); err != nil {
		t.Fatalf("StoreDeviceAuthorization: %v", err)
	}
	return newLoginHandler(storage, provider), storage
}

func getLogin(t *testing.T, h http.Handler, query url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://idp.dev.test/login?"+query.Encode(), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestDeviceApproval_Headless proves the device-approval path completes a device
// authorization for a chosen identity headlessly: after GET
// /login?user_code=…&identity=alice the stored state is Done with Subject=alice.
func TestDeviceApproval_Headless(t *testing.T) {
	const userCode = "BCDF-GHJK"
	h, storage := newDeviceTestHandler(t, userCode)

	rec := getLogin(t, h, url.Values{queryUserCode: {userCode}, queryIdentity: {"alice"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("approval status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	st, err := storage.GetDeviceAuthorizationByUserCode(context.Background(), userCode)
	if err != nil {
		t.Fatalf("GetDeviceAuthorizationByUserCode: %v", err)
	}
	if !st.Done {
		t.Errorf("device state Done = false, want true")
	}
	if st.Subject != "alice" {
		t.Errorf("device state Subject = %q, want alice", st.Subject)
	}
}

// TestDeviceApproval_InteractivePicker proves that without an identity the path
// renders a picker listing the built-in identities and echoing the user_code.
func TestDeviceApproval_InteractivePicker(t *testing.T) {
	const userCode = "BCDF-GHJK"
	h, storage := newDeviceTestHandler(t, userCode)

	rec := getLogin(t, h, url.Values{queryUserCode: {userCode}})
	if rec.Code != http.StatusOK {
		t.Fatalf("picker status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{userCode, "alice", "bob", "carol"} {
		if !strings.Contains(body, want) {
			t.Errorf("device picker missing %q\n%s", want, body)
		}
	}
	// The picker must not have approved anything yet.
	st, _ := storage.GetDeviceAuthorizationByUserCode(context.Background(), userCode)
	if st.Done {
		t.Error("rendering the picker must not complete the device authorization")
	}
}

// TestDeviceApproval_FailClosed proves the path fails closed on an unknown
// identity and on an unknown user_code.
func TestDeviceApproval_FailClosed(t *testing.T) {
	const userCode = "BCDF-GHJK"
	h, _ := newDeviceTestHandler(t, userCode)

	unknownID := getLogin(t, h, url.Values{queryUserCode: {userCode}, queryIdentity: {"nobody"}})
	if unknownID.Code != http.StatusBadRequest {
		t.Errorf("unknown identity: status = %d, want 400", unknownID.Code)
	}
	unknownCode := getLogin(t, h, url.Values{queryUserCode: {"NOPE-NOPE"}, queryIdentity: {"alice"}})
	if unknownCode.Code != http.StatusBadRequest {
		t.Errorf("unknown user_code: status = %d, want 400", unknownCode.Code)
	}
	// Drain bodies so the recorder buffers are not flagged unread by linters.
	_, _ = io.Copy(io.Discard, unknownID.Body)
	_, _ = io.Copy(io.Discard, unknownCode.Body)
}
