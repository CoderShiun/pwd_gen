package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"strconv"
)

func main() {
	a, _ := hash("A2B3c6d8E9", 16, 100000)
	fmt.Println(a)
}

func hash(password string, saltSize int, iterations int) (string, error) {
	// Generate a random salt value, 128 bits.
	salt := make([]byte, saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	return hashWithSalt(password, salt, iterations), nil
}

func hashWithSalt(password string, salt []byte, iterations int) string {
	// Generate the hash.  This should be a little painful, adjust ITERATIONS
	// if it needs performance tweeking.  Greatly depends on the hardware.
	// NOTE: We store these details with the returned hash, so changes will not
	// affect our ability to do password compares.
	hash := pbkdf2.Key([]byte(password), salt, iterations, sha512.Size, sha512.New)

	// Build up the parameters and hash into a single string so we can compare
	// other string to the same hash.  Note that the hash algorithm is hard-
	// coded here, as it is above.  Introducing alternate encodings must support
	// old encodings as well, and build this string appropriately.
	var buffer bytes.Buffer

	buffer.WriteString("PBKDF2$")
	buffer.WriteString("sha512$")
	buffer.WriteString(strconv.Itoa(iterations))
	buffer.WriteString("$")
	buffer.WriteString(base64.StdEncoding.EncodeToString(salt))
	buffer.WriteString("$")
	buffer.WriteString(base64.StdEncoding.EncodeToString(hash))

	return buffer.String()
}