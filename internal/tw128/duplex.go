package tw128

import "github.com/codahale/thyrse/internal/keccak"

// duplex is the TW128-owned x1 keyed/body transcript wrapper.
// It currently delegates to the optimized Keccak x1 backend.
type duplex struct {
	s keccak.State1
}

func (d *duplex) initKeyed(key, iv []byte) {
	d.s.InitKeyed(key, iv)
}

func (d *duplex) absorb(data []byte) {
	d.s.Absorb(data)
}

func (d *duplex) absorbCV(src *duplex) {
	d.s.AbsorbCV(&src.s)
}

func (d *duplex) absorbCVs(cvs []byte) {
	d.s.AbsorbCVs(cvs)
}

func (d *duplex) bodyEncrypt(dst, src []byte) {
	d.s.BodyEncrypt(dst, src)
}

func (d *duplex) bodyDecrypt(dst, src []byte) {
	d.s.BodyDecrypt(dst, src)
}

func (d *duplex) bodyEncryptLoop(src, dst []byte) int {
	return d.s.BodyEncryptLoop(src, dst)
}

func (d *duplex) bodyDecryptLoop(src, dst []byte) int {
	return d.s.BodyDecryptLoop(src, dst)
}

func (d *duplex) encryptBytesAt(pos int, src, dst []byte) {
	d.s.EncryptBytesAt(pos, src, dst)
}

func (d *duplex) decryptBytesAt(pos int, src, dst []byte) {
	d.s.DecryptBytesAt(pos, src, dst)
}

func (d *duplex) setPos(pos int) {
	d.s.SetPos(pos)
}

func (d *duplex) padStarPermute() {
	d.s.PadStarPermute()
}

func (d *duplex) bodyPadStarPermute() {
	d.s.BodyPadStarPermute()
}

func (d *duplex) squeeze(dst []byte) {
	d.s.Squeeze(dst)
}
