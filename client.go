package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
)

type jMessage struct {
	Msg string `json:"message"`
}

func main() {

	// connect to this socket
	conn, err := net.Dial("tcp", "127.0.0.1:3000")
	if err != nil {
		fmt.Println("Couldn't connect!")
		return
	}
	for {
		// read in input from stdin
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Text to send: ")
		text, _ := reader.ReadString('\x00')
		// send to socket
		outgoingMessage := &jMessage{
			Msg: text[:len(text)-1], // remove \x00 from message
		}
		outBytes, err := json.Marshal(outgoingMessage)
		if err != nil {
			continue
		}
		sendText := string(encrypt([]byte(outBytes), "password"))
		fmt.Fprintf(conn, sendText+"\x00")
		// listen for reply
		message, _ := bufio.NewReader(conn).ReadString('\x00')

		byt := decrypt([]byte(message[:len(message)-1]), "password")
		var dat map[string]interface{}
		json.Unmarshal(byt, &dat)

		fmt.Println("Message from server:", dat["message"].(string))
	}
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}
