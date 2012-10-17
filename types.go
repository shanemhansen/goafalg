package goafalg

import "unsafe"

type Operation int

const (
    ALG_SET_KEY Operation = 1
    ALG_SET_IV  Operation = 2
    ALG_SET_OP  Operation = 3
)

type Mode int

const (
    ALG_OP_DECRYPT Mode = 0
    ALG_OP_ENCRYPT Mode = 1
)

var SOL_ALG int = 279

type SockaddrAlg struct {
    Family  uint16
    Type    [14]uint8
    Feature uint32
    Mark    uint32
    Name    [64]uint8
}

type AfAlgIv struct {
    ivlen uint32
    iv    unsafe.Pointer
}
