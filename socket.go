package goafalg

import "syscall"
import "errors"
import "unsafe"

type AfAlg struct {
    fd   int
    conn int
    mode Mode
}

var SocketCreationError = errors.New("Problem creating socket")

func NewCipher(key, iv []byte, mode Mode) (*AfAlg, error) {
    fd, err := syscall.Socket(syscall.AF_ALG, syscall.SOCK_SEQPACKET, 0)
    if err != nil || fd < 0 {
        return nil, SocketCreationError
    }

    sa := SockaddrAlg{Family: syscall.AF_ALG}
    sa.Type = [14]byte{'s', 'k', 'c', 'i', 'p', 'h', 'e', 'r'}
    sa.Name = [64]byte{'c', 'b', 'c', '(', 'a', 'e', 's', ')'}
    err = Bind(&sa, fd, uintptr(unsafe.Pointer(&sa)), uint32(unsafe.Sizeof(sa)))
    if err != nil {
        return nil, err
    }
    err = SetKey(fd, key)
    if err != nil {
        return nil, err
    }
    self := &AfAlg{fd: fd, mode: mode}
    self.conn, err = self.Accept()
    if err != nil {
        return self, err
    }
    return self, nil
}

func Bind(self *SockaddrAlg, s int, addr uintptr, addrlen uint32) (err error) {
    _, _, e1 := syscall.Syscall(syscall.SYS_BIND, uintptr(s),
        uintptr(addr), uintptr(addrlen))
    if e1 != 0 {
        err = e1
    }
    return
}
func (self *AfAlg) Accept() (fd int, err error) {
    r1, _, e1 := syscall.Syscall(syscall.SYS_ACCEPT, uintptr(self.fd),
        0, 0)
    fd = int(r1)
    if e1 != 0 {
        err = e1
    }
    return
}
func SetKey(s int, key []byte) (err error) {
    _, _, e1 := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(s),
        uintptr(SOL_ALG), uintptr(ALG_SET_KEY),
        uintptr(unsafe.Pointer(&key[0])), uintptr(len(key)), 0)
    if e1 != 0 {
        err = e1
    }
    return
}

func (self *AfAlg) Encrypt(byte []byte) ([]byte, error) {
    return nil, nil
}
func (self *AfAlg) Close() (e error) {
    err := syscall.Close(self.fd)
    if err != nil {
        e = err
    }
    syscall.Close(self.conn)
    if err != nil {
        e = err
    }
    return
}
