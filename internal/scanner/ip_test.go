package scanner

import "testing"

func TestParseTargetsCIDR(t *testing.T) {
	got, err := ParseTargets("192.168.1.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"192.168.1.1", "192.168.1.2"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestParseTargetsCIDR32(t *testing.T) {
	got, err := ParseTargets("10.0.0.7/32")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "10.0.0.7" {
		t.Fatalf("got %v", got)
	}
}

func TestParseTargetsRangesAndLists(t *testing.T) {
	got, err := ParseTargets("192.168.1.1-3, 8.8.8.8;10.0.0.1-10.0.0.2 8.8.8.8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3", "8.8.8.8", "10.0.0.1", "10.0.0.2"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestParseTargetsErrors(t *testing.T) {
	for _, in := range []string{"", "   ", "192.168.1.0/33", "192.168.1.10-1", "300.1.1.1", "192.168.1.0/8"} {
		if _, err := ParseTargets(in); err == nil {
			t.Fatalf("expected error for %q", in)
		}
	}
}

func TestParsePorts(t *testing.T) {
	got := ParsePorts("22, 80;443 0 70000 abc")
	want := []int{22, 80, 443}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestVendorFromMac(t *testing.T) {
	SetOUIData([]byte(`{"AABBCC":"Test Vendor"}`))
	t.Cleanup(func() { SetOUIData(nil) })

	if v := VendorFromMac("aa:bb:cc:dd:ee:ff"); v != "Test Vendor" {
		t.Fatalf("got %q", v)
	}
	if v := VendorFromMac("AA-BB-CC-DD-EE-FF"); v != "Test Vendor" {
		t.Fatalf("got %q", v)
	}
	if v := VendorFromMac(""); v != "" {
		t.Fatalf("got %q", v)
	}
}
