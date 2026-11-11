package server

import "testing"

func TestCookieName(t *testing.T) {
	if got := CookieName("127.0.0.1:47651"); got != "od_admin_127_0_0_1_47651" {
		t.Fatalf("CookieName = %q", got)
	}
}
