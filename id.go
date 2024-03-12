package nb10

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"time"
)

type ID [16]byte

func NewID() ID {
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
	var id ID
	copy(id[:5], timestamp[len(timestamp)-5:])
	_, err := rand.Read(id[5:])
	if err != nil {
		panic(err)
	}
	return id
}

func (id ID) IsZero() bool {
	return id == ID{}
}

func (id ID) String() string {
	if id.IsZero() {
		return ""
	}
	var b [32 + 4]byte
	hex.Encode(b[:], id[:4])
	b[8] = '-'
	hex.Encode(b[9:13], id[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], id[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], id[8:10])
	b[23] = '-'
	hex.Encode(b[24:], id[10:])
	return string(b[:])
}

func (id ID) MarshalJSON() ([]byte, error) {
	if id.IsZero() {
		return []byte(`""`), nil
	}
	var array [32 + 4 + 2]byte
	array[0], array[len(array)-1] = '"', '"'
	b := array[1 : len(array)-1]
	hex.Encode(b[:], id[:4])
	b[8] = '-'
	hex.Encode(b[9:13], id[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], id[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], id[8:10])
	b[23] = '-'
	hex.Encode(b[24:], id[10:])
	return array[:], nil
}
