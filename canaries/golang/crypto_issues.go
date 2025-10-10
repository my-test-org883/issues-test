package main

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"fmt"
	"math/rand"
	"time"
)

// Crypto vulnerability #1: Weak hashing - MD5
func weakPasswordHash(password string) string {
	// Vulnerable: MD5 is cryptographically broken
	hash := md5.Sum([]byte(password))
	return fmt.Sprintf("%x", hash)
}

// Crypto vulnerability #2: Weak hashing - SHA1
func sha1Hash(data string) string {
	// Vulnerable: SHA1 is weak for cryptographic purposes
	hash := sha1.Sum([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// Crypto vulnerability #3: Weak random number generation
func generateWeakToken() string {
	// Vulnerable: math/rand is not cryptographically secure
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%d", rand.Int63())
}

// Crypto vulnerability #4: DES encryption (broken cipher)
func encryptWithDES(plaintext, key []byte) []byte {
	// Vulnerable: DES is cryptographically broken
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Also vulnerable: ECB mode (no IV)
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += des.BlockSize {
		end := i + des.BlockSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		block.Encrypt(ciphertext[i:end], plaintext[i:end])
	}

	return ciphertext
}

// Crypto vulnerability #5: RC4 encryption (insecure)
func encryptWithRC4(plaintext, key []byte) []byte {
	// Vulnerable: RC4 is insecure
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)

	return ciphertext
}

// Crypto vulnerability #6: Weak key generation
func generateWeakKey() []byte {
	// Vulnerable: Using time as seed for key generation
	rand.Seed(time.Now().Unix())
	key := make([]byte, 8)
	for i := range key {
		key[i] = byte(rand.Intn(256))
	}
	return key
}

// Crypto vulnerability #7: Predictable IV/nonce
func generatePredictableIV() []byte {
	// Vulnerable: Using current time as IV
	now := time.Now().Unix()
	iv := make([]byte, 16)
	for i := 0; i < 8; i++ {
		iv[i] = byte(now >> (8 * i))
	}
	return iv
}

// Crypto vulnerability #8: Insufficient entropy
func generateWeakRandomBytes(n int) []byte {
	// Vulnerable: Limited entropy source
	source := []byte("0123456789abcdef")
	result := make([]byte, n)

	rand.Seed(time.Now().UnixNano())
	for i := 0; i < n; i++ {
		result[i] = source[rand.Intn(len(source))]
	}

	return result
}

// Better example with proper crypto/rand
func generateSecureRandomBytes(n int) []byte {
	bytes := make([]byte, n)
	rand.Read(bytes)
	return bytes
}

func main() {
	// Demonstrate vulnerabilities
	password := "userpassword123"
	weakHash := weakPasswordHash(password)
	fmt.Printf("Weak MD5 hash: %s\n", weakHash)

	weakToken := generateWeakToken()
	fmt.Printf("Weak token: %s\n", weakToken)

	weakKey := generateWeakKey()
	fmt.Printf("Weak key: %x\n", weakKey)

	// Show the difference
	strongKey := generateSecureRandomBytes(32)
	fmt.Printf("Strong key: %x\n", strongKey)
}