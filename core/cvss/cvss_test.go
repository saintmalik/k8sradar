package cvss

import "testing"

func TestRemoteExploitable(t *testing.T) {
	if !RemoteExploitable("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") {
		t.Fatal("expected remote exploitable")
	}
	if RemoteExploitable("AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") {
		t.Fatal("local attack vector should not be remote")
	}
	if RemoteExploitable("AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H") {
		t.Fatal("high privileges should not count as no auth")
	}
}

func TestSeverity(t *testing.T) {
	if Severity(9.8) != "Critical" {
		t.Fatalf("got %s", Severity(9.8))
	}
	if Severity(7.5) != "High" {
		t.Fatalf("got %s", Severity(7.5))
	}
}
