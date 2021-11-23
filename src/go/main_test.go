package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

// these only show basic testing
// of course there should be more test cases even for MapOpen function and for rest of the functions
// but for now I think it's good enough

func TestMapOpenUrandom(t *testing.T) {
	path := "/dev/urandom"

	defer func() { recover() }()

	OpenMap(path)

	//
	t.Errorf("Did not panic when trying to open %s", path)
}

func TestMapOpenNotExist(t *testing.T) {
	path := "/tadmsfopdasfmpdsamfpasdmamfsdpamodfsmo/adsfafmdioadfsmoipafdsmpoadfsm/adsfmopdmofadpsmpdosafmopads"

	defer func() { recover() }()

	OpenMap(path)

	//
	t.Errorf("Did not panic when trying to open %s", path)
}

func TestMapOpenNotAMap(t *testing.T) {
	path := "/etc/passwd"

	defer func() { recover() }()

	OpenMap(path)

	//
	t.Errorf("Did not panic when trying to open %s", path)
}

func TestMapOpenWithCreate(t *testing.T) {
	_map, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Queue,
		Name:       "my_queue",
		ValueSize:  4,
		MaxEntries: 2,
	})

	tmp, err := os.MkdirTemp("/sys/fs/bpf", "ebpf-test")
	path := filepath.Join(tmp, "mapa")

	if err != nil {
		t.Fatal("Could not create map:", err)
	}

	defer _map.Close()

	err = _map.Pin(path)

	if err != nil {
		t.Fatal("Could not pin map:", err)
	}

	_map2, err := OpenMap(path)

	if err != nil {
		t.Fatal("Could not open map:", err)
	}

	err = _map2.Unpin()
	if err != nil {
		t.Fatal("Could not unpin map:", err)
	}

	defer _map2.Close()

}
