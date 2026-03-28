package lsh256

import (
	"encoding/binary"
	"hash"
	"math/bits"

	"go.foxforensics.dev/go-krypto/internal"
)

func newContextGo(size int) hash.Hash {
	ctx := &lsh256ContextGo{
		outlenbytes: size,
	}
	ctx.Reset()

	return ctx
}

func sumGo(size int, data []byte) [Size]byte { //nolint:unused
	ctx := lsh256ContextGo{
		outlenbytes: size,
	}
	ctx.Reset()
	_, _ = ctx.Write(data)

	return ctx.checkSum()
}

const (
	numStep = 26

	alphaEven = 29
	alphaOdd  = 5

	betaEven = 1
	betaOdd  = 17
)

var gamma = [...]int{0, 8, 16, 24, 24, 16, 8, 0}

type lsh256ContextGo struct {
	cv    [16]uint32
	tcv   [16]uint32
	msg   [16 * (numStep + 1)]uint32
	block [BlockSize]byte

	boff        int
	outlenbytes int
}

func (ctx *lsh256ContextGo) Size() int {
	return ctx.outlenbytes
}

func (ctx *lsh256ContextGo) BlockSize() int {
	return BlockSize
}

func (ctx *lsh256ContextGo) Reset() {
	internal.MemclrU32(ctx.tcv[:])
	internal.MemclrU32(ctx.msg[:])
	internal.Memclr(ctx.block[:])

	ctx.boff = 0
	switch ctx.outlenbytes {
	case Size:
		copy(ctx.cv[:], iv256)
	case Size224:
		copy(ctx.cv[:], iv224)
	}
}

func (ctx *lsh256ContextGo) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	plen := len(p)

	gap := BlockSize - ctx.boff
	if ctx.boff > 0 && len(p) >= gap {
		copy(ctx.block[ctx.boff:], p[:gap])
		ctx.compress(ctx.block[:])
		ctx.boff = 0

		p = p[gap:]
	}

	for len(p) >= BlockSize {
		ctx.compress(p)
		ctx.boff = 0
		p = p[BlockSize:]
	}

	if len(p) > 0 {
		copy(ctx.block[ctx.boff:], p)
		ctx.boff += len(p)
	}

	return plen, nil
}

func (ctx *lsh256ContextGo) Sum(p []byte) []byte {
	b0 := *ctx
	hs := b0.checkSum()
	return append(p, hs[:ctx.Size()]...)
}

func (ctx *lsh256ContextGo) checkSum() [Size]byte {
	ctx.block[ctx.boff] = 0x80

	internal.Memclr(ctx.block[ctx.boff+1:])
	ctx.compress(ctx.block[:])

	var temp [8]uint32
	for i := 0; i < 8; i++ {
		temp[i] = ctx.cv[i] ^ ctx.cv[i+8]
	}

	var digest [Size]byte
	for i := 0; i < ctx.outlenbytes; i++ {
		digest[i] = byte(temp[i>>2] >> ((i << 3) & 0x1f))
	}

	return digest
}

func (ctx *lsh256ContextGo) compress(data []byte) {
	ctx.msgExpansion(data)

	for i := 0; i < numStep/2; i++ {
		ctx.step(2*i+0, alphaEven, betaEven)
		ctx.step(2*i+1, alphaOdd, betaOdd)
	}

	// b.msg add
	for i := 0; i < 16; i++ {
		ctx.cv[i] ^= ctx.msg[16*numStep+i]
	}
}

func (ctx *lsh256ContextGo) msgExpansion(in []byte) {
	for i := 0; i < 32; i++ {
		ctx.msg[i] = binary.LittleEndian.Uint32(in[i*4:])
	}

	for i := 2; i <= numStep; i++ {
		idx := 16 * i
		ctx.msg[idx] = ctx.msg[idx-16] + ctx.msg[idx-29]
		ctx.msg[idx+1] = ctx.msg[idx-15] + ctx.msg[idx-30]
		ctx.msg[idx+2] = ctx.msg[idx-14] + ctx.msg[idx-32]
		ctx.msg[idx+3] = ctx.msg[idx-13] + ctx.msg[idx-31]
		ctx.msg[idx+4] = ctx.msg[idx-12] + ctx.msg[idx-25]
		ctx.msg[idx+5] = ctx.msg[idx-11] + ctx.msg[idx-28]
		ctx.msg[idx+6] = ctx.msg[idx-10] + ctx.msg[idx-27]
		ctx.msg[idx+7] = ctx.msg[idx-9] + ctx.msg[idx-26]
		ctx.msg[idx+8] = ctx.msg[idx-8] + ctx.msg[idx-21]
		ctx.msg[idx+9] = ctx.msg[idx-7] + ctx.msg[idx-22]
		ctx.msg[idx+10] = ctx.msg[idx-6] + ctx.msg[idx-24]
		ctx.msg[idx+11] = ctx.msg[idx-5] + ctx.msg[idx-23]
		ctx.msg[idx+12] = ctx.msg[idx-4] + ctx.msg[idx-17]
		ctx.msg[idx+13] = ctx.msg[idx-3] + ctx.msg[idx-20]
		ctx.msg[idx+14] = ctx.msg[idx-2] + ctx.msg[idx-19]
		ctx.msg[idx+15] = ctx.msg[idx-1] + ctx.msg[idx-18]
	}
}

func (ctx *lsh256ContextGo) step(stepidx, alpha, beta int) {
	var vl, vr uint32

	for colidx := 0; colidx < 8; colidx++ {
		vl = ctx.cv[colidx] ^ ctx.msg[16*stepidx+colidx]
		vr = ctx.cv[colidx+8] ^ ctx.msg[16*stepidx+colidx+8]
		vl = bits.RotateLeft32(vl+vr, alpha) ^ step[8*stepidx+colidx]
		vr = bits.RotateLeft32(vl+vr, beta)
		ctx.tcv[colidx] = vr + vl
		ctx.tcv[colidx+8] = bits.RotateLeft32(vr, gamma[colidx])
	}

	// wordPermutation
	ctx.cv[0] = ctx.tcv[6]
	ctx.cv[1] = ctx.tcv[4]
	ctx.cv[2] = ctx.tcv[5]
	ctx.cv[3] = ctx.tcv[7]
	ctx.cv[4] = ctx.tcv[12]
	ctx.cv[5] = ctx.tcv[15]
	ctx.cv[6] = ctx.tcv[14]
	ctx.cv[7] = ctx.tcv[13]
	ctx.cv[8] = ctx.tcv[2]
	ctx.cv[9] = ctx.tcv[0]
	ctx.cv[10] = ctx.tcv[1]
	ctx.cv[11] = ctx.tcv[3]
	ctx.cv[12] = ctx.tcv[8]
	ctx.cv[13] = ctx.tcv[11]
	ctx.cv[14] = ctx.tcv[10]
	ctx.cv[15] = ctx.tcv[9]
}
