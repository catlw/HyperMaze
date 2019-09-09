package hibe

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/pbc"
)

type RandomDataBigInt struct {
	Random  *big.Int
	Randoms []*big.Int
}

var IDKey map[string]*SecretShadow

type RandomData struct {
	Random  *pbc.Element
	Randoms []*pbc.Element
}

func (key *RandomData) RandomToBigInt() *RandomDataBigInt {
	bytes := &RandomDataBigInt{}
	bytes.Random = key.Random.BigInt()
	len := len(key.Randoms)
	ints := make([]*big.Int, len)
	for i, element := range key.Randoms {
		ints[i] = element.BigInt()
	}
	bytes.Randoms = ints
	return bytes
}

func (bigint *RandomDataBigInt) BigIntToRandom() *RandomData {
	random := &RandomData{}
	r := pairing.NewZr()
	r.SetBig(bigint.Random)
	random.Random = r

	len := len(bigint.Randoms)
	rs := make([]*pbc.Element, len)
	for i, big := range bigint.Randoms {
		t := pairing.NewZr()
		t.SetBig(big)
		rs[i] = t
	}
	random.Randoms = rs
	return random
}

type SIGBytes struct {
	X, Y, Z []byte
}

func (csig *CompressedSIGBytes) CompressedBytesToSig() *SIG {
	xbytes, ybytes, zbytes := csig.SIG[0:65], csig.SIG[65:130], csig.SIG[130:195]
	x, y, z := pairing.NewG1(), pairing.NewG1(), pairing.NewG1()
	x.SetCompressedBytes(xbytes)
	y.SetCompressedBytes(ybytes)
	z.SetCompressedBytes(zbytes)
	signature := &SIG{X: x, Y: y, Z: z}
	return signature
}

func (sig *SIG) SigToCompressedBytes() *CompressedSIGBytes {
	sigBytes := sig.SIGToBytes()
	CsigBytes := &CompressedSIGBytes{}
	CsigBytes.SIG = append(CsigBytes.SIG, sigBytes.X...)
	CsigBytes.SIG = append(CsigBytes.SIG, sigBytes.Y...)
	CsigBytes.SIG = append(CsigBytes.SIG, sigBytes.Z...)
	return CsigBytes
}

type CompressedSIGBytes struct {
	SIG []byte
}

const HibeSigLength = 65 * 3

func Sign(sks *SecretShadow, mpk *MasterPublicKey, hash []byte, s *pbc.Element) CompressedSIGBytes {
	sig := ShadowSign(sks, mpk, hash, s)
	sigbytes := sig.SIGToBytes()
	compressedsig := CompressedSIGBytes{}
	compressedsig.SIG = append(compressedsig.SIG, sigbytes.X...)
	compressedsig.SIG = append(compressedsig.SIG, sigbytes.Y...)
	compressedsig.SIG = append(compressedsig.SIG, sigbytes.Z...)

	return compressedsig
}

func (key *SIG) SIGToBytes() *SIGBytes {
	sigbytes := &SIGBytes{}
	sigbytes.X, sigbytes.Y, sigbytes.Z = key.X.CompressedBytes(), key.Y.CompressedBytes(), key.Z.CompressedBytes()
	//fmt.Println(len(sigbytes.X), len(sigbytes.Y), len(sigbytes.Z))
	return sigbytes
}

func (key *SIGBytes) BytesToSIG() *SIG {
	sig := &SIG{}
	x, y, z := pairing.NewG1(), pairing.NewG1(), pairing.NewG1()
	x.SetCompressedBytes(key.X)
	y.SetCompressedBytes(key.Y)
	z.SetCompressedBytes(key.Z)
	sig.X, sig.Y, sig.Z = x, y, z
	return sig
}

func (key *SecretShadow) ShadowToBytes() *ShadowBytes {
	bytes := &ShadowBytes{}

	len := len(key.B)
	hbytes := make([][]byte, len)
	for i, element := range key.B {
		hbytes[i] = element.CompressedBytes()
	}

	bytes.Set(key.A0.CompressedBytes(), key.A1.CompressedBytes(), hbytes)

	return bytes
}

func (key *MasterPublicKey) MasterPubkeyToBytes() *MasterPublicKeyBytes {
	bytes := &MasterPublicKeyBytes{}

	len := len(key.H)
	hbytes := make([][]byte, len)
	for i, element := range key.H {
		hbytes[i] = element.CompressedBytes()
	}

	bytes.Set(key.MaxDepth, key.G.CompressedBytes(), key.G1.CompressedBytes(), key.G2.CompressedBytes(), key.G3.CompressedBytes(), hbytes)

	return bytes
}

type MasterPublicKeyBytes struct {
	MaxDepth      uint32
	G, G1, G2, G3 []byte
	H             [][]byte
}

type ShadowBytes struct {
	A0, A1 []byte
	B      [][]byte
}

type KeyAndID struct {
	Key *ShadowBytes
	ID  string
}

func (bytes *MasterPublicKeyBytes) BytesToMasterPubkey() *MasterPublicKey {
	key := &MasterPublicKey{}
	g, g1, g2, g3 := pairing.NewG1(), pairing.NewG1(), pairing.NewG1(), pairing.NewG1()

	g.SetCompressedBytes(bytes.G)
	g1.SetCompressedBytes(bytes.G1)
	g2.SetCompressedBytes(bytes.G2)
	g3.SetCompressedBytes(bytes.G3)

	len := len(bytes.H)
	h := make([]*pbc.Element, len)
	for i, bs := range bytes.H {
		ele := pairing.NewG1()
		ele.SetCompressedBytes(bs)
		h[i] = ele
	}

	key.Set(bytes.MaxDepth, g, g1, g2, g3, h)
	return key
}

func (bytes *ShadowBytes) BytesToShadow() *SecretShadow {
	key := &SecretShadow{}
	a0, a1 := pairing.NewG1(), pairing.NewG1()

	a0.SetCompressedBytes(bytes.A0)
	a1.SetCompressedBytes(bytes.A1)
	len := len(bytes.B)
	b := make([]*pbc.Element, len)
	for i, bs := range bytes.B {
		ele := pairing.NewG1()
		ele.SetCompressedBytes(bs)
		b[i] = ele
	}
	key.Set(a0, a1, b)
	return key
}

func (bytes *MasterPublicKeyBytes) Set(depth uint32, g, g1, g2, g3 []byte, h [][]byte) {
	bytes.MaxDepth = uint32(depth)
	bytes.G, bytes.G1, bytes.G2, bytes.G3 = g, g1, g2, g3
	bytes.H = h
}

func (key *MasterPublicKey) Set(depth uint32, g, g1, g2, g3 *pbc.Element, h []*pbc.Element) {
	key.MaxDepth = depth
	key.G, key.G1, key.G2, key.G3 = g, g1, g2, g3
	key.H = h

}
func (bytes *ShadowBytes) Set(a0, a1 []byte, b [][]byte) {
	bytes.A0, bytes.A1 = a0, a1
	bytes.B = b
}

func (key *SecretShadow) Set(a0, a1 *pbc.Element, b []*pbc.Element) {

	key.A0, key.A1 = a0, a1
	key.B = b

}

const Debug = true

var PrivateKey *SecretShadow
var MasterPubKey *MasterPublicKey

func DHibePrivatekey() *SecretShadow {
	return PrivateKey
}

func DHibePubkey() *MasterPublicKey {
	return MasterPubKey
}

var Random *pbc.Element

var M, N uint32

var Index, Level uint32

// MasterPublicKey stores the master public key used for all levels
type MasterPublicKey struct {
	MaxDepth      uint32
	G, G1, G2, G3 *pbc.Element
	H             []*pbc.Element
}

// SecretShadow stores private key shares
type SecretShadow struct {
	A0, A1 *pbc.Element
	B      []*pbc.Element
}

// SIG stores the signature of a message
type SIG struct {
	X, Y, Z *pbc.Element
}

// parameters of the curve
const str = `type a
	q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
	h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
	r 730750818665451621361119245571504901405976559617
	exp2 159
	exp1 107
	sign1 1
	sign0 1`

var pairing, _ = pbc.NewPairingFromString(str)

var StaticZr = pairing.NewZr().SetBytes([]byte(string("0x4aa990")))
var StaticG = []byte{48, 157, 94, 118, 198, 28, 66, 139, 61, 41, 240, 150, 225, 195, 202, 153, 238, 172, 139, 131, 157, 199, 62, 150, 165, 113, 115, 229, 20, 235, 118, 73, 87, 16, 152, 177, 55, 1, 5, 103, 235, 108, 93, 28, 42, 106, 89, 57, 22, 100, 148, 143, 175, 94, 73, 83, 37, 80, 78, 254, 133, 47, 151, 178}
var StaticG1 = pairing.NewG1().SetXBytes(StaticG)

//
func GenerateRandom() *pbc.Element {
	r := pairing.NewZr().Rand()
	return r
}

// Setup generates public parameters and private key shares for n0 authorities at the root for a given threshold t0 and a given maximum depth l

// mpk starts from index 1
func Setup(maxDepth, numOfLevel0, thresholdOfLevel0 int) (*MasterPublicKey, []*SecretShadow, error) {
	if thresholdOfLevel0 > numOfLevel0 {
		return nil, nil, errors.New("secret key would be irrecoverable")
	}
	g, g2, g3 := pairing.NewG1().Rand(), pairing.NewG1().Rand(), pairing.NewG1().Rand()
	alpha := pairing.NewZr().Rand()
	g1 := pairing.NewG1().PowZn(g, alpha)
	h := make([]*pbc.Element, maxDepth)
	for i := 0; i < maxDepth; i++ {
		h[i] = pairing.NewG1().Rand()
	}
	var mpk MasterPublicKey
	mpk.G, mpk.G1, mpk.G2, mpk.G3, mpk.H, mpk.MaxDepth = g, g1, g2, g3, h, uint32(maxDepth)
	poly := GenCoef(thresholdOfLevel0)
	s := make([]*pbc.Element, numOfLevel0+1)
	for index := 1; index <= numOfLevel0; index++ {
		s[index-1] = pairing.NewZr().Add(C(poly, index), alpha)
	}

	mss := make([]*SecretShadow, numOfLevel0)
	for i := 0; i < numOfLevel0; i++ {
		var tmpSs SecretShadow
		tmpSs.A0 = pairing.NewG1().PowZn(g2, s[i])
		tmpSs.A1 = pairing.NewG1().Set1()
		b := make([]*pbc.Element, maxDepth)
		for j := 0; j < maxDepth; j++ {
			b[j] = pairing.NewG1().Set1()
		}
		tmpSs.B = b
		mss[i] = &tmpSs
	}
	return &mpk, mss, nil
}

// ShadowGen generate a partial shadows for a low-level authority
func ShadowGen(ss *SecretShadow, mpk *MasterPublicKey, Cs []*pbc.Element, r *pbc.Element, ID string, index int, level int) *SecretShadow { // index of a node
	I := hashID(ID)
	// I := make([]*pbc.Element, level)
	// for i := 0; i < level; i++ {
	// 	I[i] = pairing.NewZr().Set0()
	// }
	//fmt.Println("I:", I)
	Ck := C(Cs, index)
	a0 := pairing.NewG1().Mul(ss.A0, pairing.NewG1().PowZn(mpk.G2, Ck))
	prod1 := pairing.NewG1().Set1()
	tmp := pairing.NewG1().Set1()
	for i := 0; i < level-1; i++ {
		tmp.PowZn(mpk.H[i], I[i])
		prod1.Mul(prod1, tmp)
	}
	prod1.Mul(prod1, mpk.G3)
	prod1.PowZn(prod1, Ck)
	a0.Mul(a0, prod1)
	prod2 := pairing.NewG1().Set1()
	for i := 0; i < level; i++ {
		tmp.PowZn(mpk.H[i], I[i])
		prod2.Mul(prod2, tmp)
	}
	prod2.Mul(prod2, mpk.G3) // TO be simplified
	prod2.PowZn(prod2, r)
	a0.Mul(a0, prod2)
	tmp.PowZn(ss.B[0], I[level-1])
	a0.Mul(a0, tmp)
	tmp.PowZn(mpk.H[level-1], I[level-1])
	tmp.PowZn(tmp, Ck)
	a0.Mul(a0, tmp)

	expon := pairing.NewZr().Add(Ck, r)
	tmp.PowZn(mpk.G, expon)
	a1 := pairing.NewG1().Mul(ss.A1, tmp)

	bNum := int(mpk.MaxDepth) - level
	b := make([]*pbc.Element, bNum)
	for i := 0; i < bNum; i++ {
		ind := 1 + i
		tmpB := pairing.NewG1().PowZn(mpk.H[level+i], expon)
		tmpB.Mul(ss.B[ind], tmpB)
		b[i] = tmpB
	}
	var newSs SecretShadow
	newSs.A0 = a0
	newSs.A1 = a1
	newSs.B = b
	return &newSs
}

// KeyRecon enables  an authority that obtains all partial shares from the set of upper-level authorities to reconstruct its complete shadow
func KeyRecon(Ss []*SecretShadow, SelectedNodes []int) *SecretShadow { // SelectedNodes represents for indexes
	t := len(SelectedNodes)
	Xl := make([]*pbc.Element, t)
	for i := 0; i < t; i++ {
		Xl[i] = pairing.NewZr().SetInt32(int32(SelectedNodes[i]))
	}
	A0s := make([]*pbc.Element, t)
	A1s := make([]*pbc.Element, t)
	bNum := len(Ss[0].B)
	Bs := make([][]*pbc.Element, bNum)
	for i := range Bs {
		Bs[i] = make([]*pbc.Element, t)
	}
	for i := 0; i < t; i++ {
		l := L(Xl, i)
		A0s[i] = pairing.NewG1().PowZn(Ss[i].A0, l)
		A1s[i] = pairing.NewG1().PowZn(Ss[i].A1, l)
		for j := 0; j < bNum; j++ {
			Bs[j][i] = pairing.NewG1().PowZn(Ss[i].B[j], l) // To be checked
		}
	}
	b := make([]*pbc.Element, bNum)
	for i := 0; i < bNum; i++ {
		b[i] = PIg(Bs[i])
	}
	var sks SecretShadow
	sks.A0 = PIg(A0s)
	sks.A1 = PIg(A1s)
	sks.B = b
	return &sks
}

// ShadowSign enables an authority holding a secret shadow to generate a partial signature on message M
func ShadowSign(sks *SecretShadow, mpk *MasterPublicKey, M []byte, s *pbc.Element) *SIG {
	h := h3(M, mpk)
	xi := pairing.NewG1().Mul(sks.A0, pairing.NewG1().PowZn(h, s))
	yi := sks.A1
	zi := pairing.NewG1().PowZn(mpk.G, s)
	Psig := new(SIG)
	Psig.X, Psig.Y, Psig.Z = xi, yi, zi
	return Psig
}

// ShadowSign enables an authority holding a secret shadow to generate a partial signature on message M
// func ShadowSign(sks *SecretShadow, mpk *MasterPublicKey, s *pbc.Element, M string) *SIG {
// 	x := pairing.NewG1().PowZn(mpk.G2, s)
// 	h := h3(M, x)
// 	yi := pairing.NewG1().PowZn(sks.A0, pairing.NewZr().Add(s, h))
// 	zi := pairing.NewG1().PowZn(sks.A1, pairing.NewZr().Add(s, h))
// 	Psig := new(SIG)
// 	Psig.X, Psig.Y, Psig.Z = x, yi, zi
// 	return Psig
// }

// SignRecon reconstructs a complete signature from multiple parital signatures
// the order of PartialSIG should correspond to the order of SelectedNodes!!
func SignRecon(PartialSIG []*SIG, SelectedNodes []int) *SIG {
	thresh := len(SelectedNodes)
	Xl := make([]*pbc.Element, thresh)
	for i := 0; i < thresh; i++ {
		Xl[i] = pairing.NewZr().SetInt32(int32(SelectedNodes[i]))
	}
	Sx := make([]*pbc.Element, thresh)
	Sy := make([]*pbc.Element, thresh)
	Sz := make([]*pbc.Element, thresh)
	for i := 0; i < thresh; i++ {
		l := L(Xl, i)
		Sx[i] = pairing.NewG1().PowZn(PartialSIG[i].X, l)
		Sy[i] = pairing.NewG1().PowZn(PartialSIG[i].Y, l)
		Sz[i] = pairing.NewG1().PowZn(PartialSIG[i].Z, l)
	}
	sig := new(SIG)
	sig.X, sig.Y, sig.Z = PIg(Sx), PIg(Sy), PIg(Sz)
	return sig
}

// Verify verifies a complete signature reconstructed from partial signatures
func Verify(mpk *MasterPublicKey, ID string, M []byte, level int, sig *SIG) bool {
	LHS := pairing.NewGT().Pair(mpk.G, sig.X)
	h := h3(M, mpk)
	tmp := pairing.NewGT().Pair(mpk.G1, mpk.G2)
	tmp1 := pairing.NewG1().Set1()
	tmp2 := pairing.NewG1().Set1()
	I := hashID(ID)
	for i := 0; i < level; i++ {
		tmp1.PowZn(mpk.H[i], I[i])
		tmp2.Mul(tmp2, tmp1)
	}
	tmp2.Mul(tmp2, mpk.G3)
	tmpGT := pairing.NewGT().Pair(sig.Y, tmp2)
	RHS := pairing.NewGT().Mul(tmp, tmpGT)
	tmp = pairing.NewGT().Pair(sig.Z, h)
	RHS.Mul(RHS, tmp)
	return LHS.Equals(RHS)
}

// Verify verifies a complete signature reconstructed from partial signatures
// func Verify(mpk *MasterPublicKey, ID, M string, level int, sig *SIG) bool {
// 	LHS := pairing.NewGT().Pair(mpk.G, sig.Y)
// 	h := h3(M, sig.X)
// 	tmp := pairing.NewGT().Pair(mpk.G1, pairing.NewG1().Mul(pairing.NewG1().PowZn(mpk.G2, h), sig.X))
// 	tmp1 := pairing.NewG1().Set1()
// 	tmp2 := pairing.NewG1().Set1()
// 	I := hashID(ID)
// 	for i := 0; i < level; i++ {
// 		tmp1.PowZn(mpk.H[i], I[i])
// 		tmp2.Mul(tmp2, tmp1)
// 	}
// 	tmp2.Mul(tmp2, mpk.G3)
// 	tmpGT := pairing.NewGT().Pair(sig.Z, tmp2)
// 	RHS := pairing.NewGT().Mul(tmp, tmpGT)
// 	return LHS.Equals(RHS)
// }

// C returns the result of f(x) = C1*x+C2*x^2+...+Ctk-1*x^(tk-1)
func C(Cs []*pbc.Element, index int) *pbc.Element {
	x := pairing.NewZr().SetInt32(int32(index))
	ret := pairing.NewZr().Set0()
	for _, coef := range Cs {
		ret.Add(ret, coef)
		ret.MulZn(ret, x)
	}
	return ret
}

// GenCoef generates the coefficients used by func C
func GenCoef(t int) []*pbc.Element {
	Cs := make([]*pbc.Element, t-1)
	for i := 0; i < t-1; i++ {
		Cs[i] = pairing.NewZr().Rand()
	}
	return Cs
}

// L generates the Lagrange coefficient of an index
func L(SelectedNodes []*pbc.Element, indexOfArray int) *pbc.Element { // indexOfArray represents index of SelectedNodes
	t := len(SelectedNodes)
	others := make([]*pbc.Element, t)
	copy(others, SelectedNodes)
	cur := others[indexOfArray]
	if indexOfArray == t-1 {
		others = others[:indexOfArray]
	} else {
		others = append(others[:indexOfArray], others[indexOfArray+1:]...)
	}
	tmpN := make([]*pbc.Element, t-1)
	tmpD := make([]*pbc.Element, t-1)
	for i, o := range others {
		tmpN[i] = o
		tmpD[i] = pairing.NewZr().Sub(o, cur)
	}
	accumN := PIz(tmpN)
	accumD := PIz(tmpD)
	ret := pairing.NewZr().Div(accumN, accumD)
	return ret
}

// h3 returns H3(M, x)
// func h3(M string, x *pbc.Element) *pbc.Element {
// 	bx := x.XBytes()
// 	Ms := sha256.Sum256([]byte(M))
// 	bxs := sha256.Sum256(bx)
// 	s1 := Ms[0:4]
// 	s2 := bxs[0:4]
// 	si1 := binary.BigEndian.Uint32(s1)
// 	si2 := binary.BigEndian.Uint32(s2)
// 	h := pairing.NewZr().SetBig(big.NewInt(int64(si1) + int64(si2)))
// 	return h
// }

// h3 returns H3(M, x)
func h3(M []byte, mpk *MasterPublicKey) *pbc.Element {
	sl := M[0:4]
	si := binary.BigEndian.Uint32(sl)
	sr := pairing.NewZr().SetBig(big.NewInt(int64(si)))
	h := pairing.NewG1().PowZn(mpk.G, sr)
	return h
}

// VSS returns f(x) used in VSS scheme
func VSS(thresholdOfLowLevel int) func(index int) *pbc.Element { // index of a low level node
	Ck := GenCoef(thresholdOfLowLevel)
	r := pairing.NewZr().Rand()
	return func(index int) *pbc.Element {
		return pairing.NewZr().Add(C(Ck, index), r)
	}
}

// GenVSS generates VSS functions used by up-level nodes
func GenVSS(numberOfUpLevelNodes, thresholdOfLowLevelNodes int) []func(int) *pbc.Element {
	F := make([]func(int) *pbc.Element, numberOfUpLevelNodes)
	for i := 0; i < numberOfUpLevelNodes; i++ {
		F[i] = VSS(thresholdOfLowLevelNodes)
	}
	return F
}

// Vsum returns a VSS shadow value
func Vsum(indexOfUpNode int, F []func(int) *pbc.Element) *pbc.Element {
	ret := pairing.NewZr().Set0()
	for _, fn := range F {
		ret.Add(ret, fn(indexOfUpNode))
	}
	return ret
}

// VSSValueSum returns the sum of a slice of Zr numbers
func VSSValueSum(Values []*pbc.Element) *pbc.Element {
	ret := pairing.NewZr().Set0()
	for _, val := range Values {
		ret.Add(ret, val)
	}
	return ret
}

// hashID returns the hash of IDs in an ID string
func hashID(ID string) []*pbc.Element {
	level := len(ID) / 2
	I := make([]*pbc.Element, level)
	for index := 0; index < level; index++ {
		s := sha256.Sum256([]byte(string(ID[index*2 : (index+1)*2])))
		sl := s[0:4]
		si := binary.BigEndian.Uint32(sl)
		sr := pairing.NewZr().SetBig(big.NewInt(int64(si)))
		I[index] = sr
	}
	return I
}

// PIz returns the product of Zr inputs
func PIz(vals []*pbc.Element) *pbc.Element {
	accum := pairing.NewZr().Set1()
	for _, v := range vals {
		if v != nil {
			accum.MulZn(accum, v)
		}
	}
	return accum
}

// PIg returns the product of G1 inputs
func PIg(vals []*pbc.Element) *pbc.Element {
	accum := pairing.NewG1().Set1()
	for _, v := range vals {
		if v != nil {
			accum.Mul(accum, v)
		}
	}
	return accum
}
