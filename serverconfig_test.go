package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The service and `packhound passwd` share the file: neither may lose the
// other's change.
func TestConfigStoreSeesOtherWriters(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	svc, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.update(func(c *serverConfig) error { c.SNMP.Community = "abc"; return nil }); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond) // a distinct modification time
	other, _ := loadConfig(p)
	if err := other.update(func(c *serverConfig) error { return setUserPassword(c, "admin", "password123") }); err != nil {
		t.Fatal(err)
	}
	if !checkPassword(svc.get(), "admin", "password123") {
		t.Fatal("the service did not see the new login")
	}
	if err := svc.update(func(c *serverConfig) error { c.Running = true; return nil }); err != nil {
		t.Fatal(err)
	}
	final, _ := loadConfig(p)
	c := final.get()
	if !c.Running || c.SNMP.Community != "abc" || !checkPassword(c, "admin", "password123") {
		t.Fatalf("a change was lost: %+v", c)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("config file mode %v", st.Mode().Perm())
	}
}
