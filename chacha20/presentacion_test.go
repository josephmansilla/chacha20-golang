package chacha20

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustCipher(t *testing.T, keyHex, nonceHex string) *Cipher {
	t.Helper()
	c, err := NewUnauthenticatedCipher(hexDecode(keyHex), hexDecode(nonceHex))
	if err != nil {
		t.Fatalf("no se pudo crear el cipher: %v", err)
	}
	return c
}

func TestTextoVacio(t *testing.T) {
	const (
		keyHex   = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		nonceHex = "000000000000000000000000"
	)
	c := mustCipher(t, keyHex, nonceHex)

	plaintext := make([]byte, 0)
	ciphertext := make([]byte, 0)
	c.XORKeyStream(ciphertext, plaintext)

	if len(ciphertext) != 0 {
		t.Fatalf("esperaba un mensaje cifrado vacio, obtuve %d bytes", len(ciphertext))
	}

	control := mustCipher(t, keyHex, nonceHex)
	message := []byte("ChaCha20 sigue listo aunque el mensaje inicial sea vacio.")
	got := make([]byte, len(message))
	expected := make([]byte, len(message))
	c.XORKeyStream(got, message)
	control.XORKeyStream(expected, message)
	if !bytes.Equal(got, expected) {
		t.Fatalf("el primer mensaje real no coincidio luego de cifrar el vacio")
	}

	t.Log("ChaCha20 ignora entradas vacias sin modificar el estado y el siguiente mensaje se cifra correctamente.")
}

func TextTextoReconocible(t *testing.T) {
	const (
		keyHex      = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
		nonceHex    = "404142434445464748494a4b4c4d4e4f5051525354555658"
		inputHex    = "5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e"
		expectedHex = "4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e98d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0daece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e7443056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b748142407c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486ccb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a66393b93111c1a55dd7421a10184974c7c5"
	)

	message := hexDecode(inputHex)
	t.Logf("Fragmento del texto original: %q...", string(message[:64]))

	c := mustCipher(t, keyHex, nonceHex)
	ciphertext := make([]byte, len(message))
	c.XORKeyStream(ciphertext, message)

	gotHex := hex.EncodeToString(ciphertext)
	if gotHex != expectedHex {
		t.Fatalf("cifrado inesperado, obtuve %s, esperaba %s", gotHex, expectedHex)
	}

	t.Logf("Primeros 32 bytes cifrados: %s", gotHex[:64])
	t.Log("Este vector reproduce el ejemplo narrativo de XChaCha20 y es ideal para una demostracion.")
}

func TestPasoAPaso(t *testing.T) {
	const (
		keyHex   = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		nonceHex = "000000000000000000000002"
	)
	message := []byte("Miren como ChaCha20 opera bloque por bloque y mezcla cada parte.")

	control := mustCipher(t, keyHex, nonceHex)
	expected := make([]byte, len(message))
	control.XORKeyStream(expected, message)

	c := mustCipher(t, keyHex, nonceHex)
	ciphertext := make([]byte, len(message))

	const chunk = 16
	for offset := 0; offset < len(message); offset += chunk {
		end := offset + chunk
		if end > len(message) {
			end = len(message)
		}
		c.XORKeyStream(ciphertext[offset:end], message[offset:end])

		keystream := make([]byte, end-offset)
		copy(keystream, ciphertext[offset:end])
		for i := range keystream {
			keystream[i] ^= message[offset+i]
		}

		t.Logf("Bloque %02d | texto=%q | keystream=%s | cifrado=%s",
			offset/chunk,
			string(message[offset:end]),
			hex.EncodeToString(keystream),
			hex.EncodeToString(ciphertext[offset:end]))
	}

	if !bytes.Equal(ciphertext, expected) {
		t.Fatalf("el recorrido paso a paso produjo un cifrado distinto al esperado")
	}

	t.Log("Los bloques se encadenan sin perder consistencia con el resultado obtenido en una sola pasada.")
}
