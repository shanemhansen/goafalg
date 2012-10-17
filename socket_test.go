package goafalg

import "testing"

func TestIt(t *testing.T) {
    a, err := NewCipher(make([]byte, 16), make([]byte, 16), ALG_OP_ENCRYPT)
    if err != nil {
        t.Fatal(err)
    }
    err = a.Close()
    if err != nil {
        t.Fatal(err)
    }
}
