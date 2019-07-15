package rc4

type arrayByte [256]byte

// Cypher : Holder for the rc4 cypher
type Cypher struct {
	key  arrayByte
	i, j uint8
}

func (ab *arrayByte) swap(i, j uint8) {
	tmp := ab[i]
	ab[i] = ab[j]
	ab[j] = tmp
}

// SetKey : Set cypher key
func (c *Cypher) SetKey(key string) {
	var keyLength = len(key)
	var j uint8

	for i := range c.key {
		c.key[i] = uint8(i)
	}
	for i := range c.key {
		j = (j + c.key[i] + key[i%keyLength])
		c.key.swap(uint8(i), j)
	}
	c.i, c.j = 0, 0
}

// Crypt given array of byte with the cypher key
func (c *Cypher) Crypt(src []byte) []byte {
	dst := make([]byte, len(src))

	for i := range src {
		c.i++
		c.j = (c.j + c.key[c.i])
		c.key.swap(c.i, c.j)
		dst[i] = (c.key[c.key[c.i]+c.key[c.j]]) ^ src[i]
	}
	return dst
}
