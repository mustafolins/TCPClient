package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
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
		text, _ := reader.ReadString('\n')
		// text := "dude\n"
		// send to socket
		outgoingMessage := &jMessage{
			Msg: text[:len(text)-1], // remove \x00 from message
		}
		outBytes, err := json.Marshal(outgoingMessage)
		if err != nil {
			continue
		}
		sendText := string(encrypt("password", []byte(outBytes)))
		_, sendErr := fmt.Fprintf(conn, sendText+"\x00")
		// listen for reply
		if sendErr == nil {
			message, recErr := bufio.NewReader(conn).ReadString('\x00')
			if recErr != nil {
				continue
			}

			if len(message) > aes.BlockSize {
				byt := decrypt("password", []byte(message[:len(message)-1]))
				var dat map[string]interface{}
				json.Unmarshal(byt, &dat)

				if dat != nil {
					fmt.Println("Message from server:", dat["message"].(string))
				}
			}
		}
	}
}

func encodeBase64(b []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(b))
}

func decodeBase64(b []byte) []byte {
	data, _ := base64.StdEncoding.DecodeString(string(b))
	return data
}

func encrypt(key string, text []byte) []byte {
	paddedKey := fmt.Sprintf("%032s", key)
	block, _ := aes.NewCipher([]byte(paddedKey))

	b := encodeBase64(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], b)
	return ciphertext
}

func decrypt(key string, text []byte) []byte {
	paddedKey := fmt.Sprintf("%032s", key)
	block, _ := aes.NewCipher([]byte(paddedKey))

	if len(text) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	return decodeBase64(text)
}
