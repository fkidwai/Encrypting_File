package filecrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

// Encrypt encrypts the content of the file at the given path using the provided password
func Encrypt(source string, password []byte) {

	// Check if the file exists
	if _, err := os.Stat(source); os.IsNotExist(err) {
		panic(err.Error())
	}

	// Open the source file for reading
	srcFile, err := os.Open(source)
	if err != nil {
		panic(err.Error())
	}
	defer srcFile.Close()

	// Read the entire content of the file
	plaintext, err := io.ReadAll(srcFile)
	if err != nil {
		panic(err.Error())
	}

	// Use the provided password as the encryption key
	key := password

	// Generate a nonce (number used once) for encryption
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	// Derive a key using PBKDF2 with the password and nonce
	dk := pbkdf2.Key(key, nonce, 4096, 32, sha1.New)

	// Create a new AES cipher block using the derived key
	block, err := aes.NewCipher(dk)
	if err != nil {
		panic(err.Error())
	}

	// Create a new Galois/Counter Mode (GCM) block cipher
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	// Encrypt the plaintext using the AES-GCM cipher
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	// Append the nonce to the ciphertext
	ciphertext = append(ciphertext, nonce...)

	// Create (or overwrite) the source file for writing the encrypted data
	f, err := os.Create(source)
	if err != nil {
		panic(err.Error())
	}

	// Write the ciphertext to the file
	_, err = io.Copy(f, bytes.NewReader(ciphertext))
	if err != nil {
		panic(err.Error())
	}
}

// Decrypt decrypts the content of the file at the given path using the provided password
func Decrypt(source string, password []byte) {

	// Check if the file exists
	if _, err := os.Stat(source); os.IsNotExist(err) {
		panic(err.Error())
	}

	// Open the source file for reading
	srcFile, err := os.Open(source)
	if err != nil {
		panic(err.Error())
	}
	defer srcFile.Close()

	// Read the entire content of the file
	ciphertext, err := io.ReadAll(srcFile)
	if err != nil {
		panic(err.Error())
	}

	// Use the provided password as the decryption key
	key := password

	// Extract the nonce from the end of the ciphertext
	salt := ciphertext[len(ciphertext)-12:]

	// Encode the nonce to a hexadecimal string
	str := hex.EncodeToString(salt)

	// Decode the nonce from the hexadecimal string
	nonce, err := hex.DecodeString(str)
	if err != nil {
		panic(err.Error())
	}

	// Derive a key using PBKDF2 with the password and nonce
	dk := pbkdf2.Key(key, nonce, 4096, 32, sha1.New)

	// Create a new AES cipher block using the derived key
	block, err := aes.NewCipher(dk)
	if err != nil {
		panic(err.Error())
	}

	// Create a new Galois/Counter Mode (GCM) block cipher
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	// Decrypt the ciphertext using the AES-GCM cipher
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext[:len(ciphertext)-12], nil)
	if err != nil {
		panic(err.Error())
	}

	// Create (or overwrite) the source file for writing the decrypted data
	f, err := os.Create(source)
	if err != nil {
		panic(err.Error())
	}

	// Write the plaintext to the file
	_, err = io.Copy(f, bytes.NewReader(plaintext))
	if err != nil {
		panic(err.Error())
	}
}
