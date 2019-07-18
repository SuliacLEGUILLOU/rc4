package rc4_test

import (
	"testing"

	localRC4 "github.com/suliacLEGUILLOU/rc4"
)

/**
 *	Test case: "Plaintext" encrypted with "key" should output "BBF316E8D940AF0AD3"
 */

func TestCrypt(t *testing.T) {
	c := localRC4.Cypher{}
	src := []byte("Plaintext")

	c.SetKey("Key")
	result := c.Crypt(src)
	if result[0] != 0xBB || result[3] != 0xE8 {
		t.Error("Crypt error")
	}
}

func TestDecrypt(t *testing.T) {
	c := localRC4.Cypher{}
	src := []byte{0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3}

	c.SetKey("Key")
	result := c.Crypt(src)
	if result[0] != 'P' || result[5] != 't' {
		t.Error("Decrypt error")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	c := localRC4.Cypher{}
	src := []byte("Plaintext")

	c.SetKey("Key")
	message := c.Crypt(src)

	c.SetKey("Key")
	clear := c.Crypt(message)
	if clear[0] != 'P' || clear[5] != 't' {
		t.Error("Decrypt error")
	}
}

func TestStreamByte(t *testing.T) {
	c := localRC4.Cypher{}
	src := []byte("Plaintext")

	c.SetKey("Key")
	c.InitStream(1)
	c.StreamByte(src[0])

	var result = <-c.Stream
	if result != 0xBB {
		t.Error("Stream error")
	}
}

func TestStreamArray(t *testing.T) {
	c := localRC4.Cypher{}
	src := []byte("Plaintext")

	c.SetKey("Key")
	c.InitStream(20)
	c.StreamArray(src)

	var result = <-c.Stream
	if result != 0xBB {
		t.Error("Stream error")
	}
}
