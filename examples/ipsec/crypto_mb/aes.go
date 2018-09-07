package crypto_mb

//TODO copyright header?

//TODO check cpuid

type aes_x8 struct {
	blockSize int
	enc       []uint32
	dec       []uint32
}

func (this *aes_x8) BlockSize() int {
	return this.blockSize
}

func (this *aes_x8) VecSize() int {
	return 8
}

//TODO accept number of blocks
func NewAESMultiBlock(key []byte) MultiBlock {
	if len(key) != 16 {
		// TODO return error?
		panic("For now only 16-byte keys are supported")
	}
	n := len(key) + 28
	rounds := 10
	c := aes_x8{len(key), make([]uint32, n), make([]uint32, n)}
	expandKeyAsm(rounds, &key[0], &c.enc[0], &c.dec[0])
	return &c
}

func (this *aes_x8) EncryptMany(dst, src [][]byte) {
	//TODO add  more checks?
	//TODO number of rounds
	if len(src) != 8 || len(dst) != 8 {
		panic("aes x8 requires 8 input and 8 output blocks")
	}
	encrypt8BlocksAsm(&this.enc[0], dst, src)
}

// in aes.s
//go:noescape
func encrypt8BlocksAsm(xk *uint32, dst, src [][]byte)

// in aes.s
//go:noescape
func expandKeyAsm(nr int, key *byte, enc, dec *uint32)

func (this *aes_x8) DecryptMany(dst, src [][]byte) {
	panic("Not implemented yet")
}
