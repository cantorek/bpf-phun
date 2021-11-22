package main

import "encoding/binary"

func btos32(val uint32) uint32 {
	_bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(_bytes, val)
	return binary.LittleEndian.Uint32(_bytes)
}

func btos16(val uint16) uint16 {
	_bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(_bytes, val)
	return binary.LittleEndian.Uint16(_bytes)
}

// oh go, missing such a basic method
func contains(s []uint16, e uint16) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
