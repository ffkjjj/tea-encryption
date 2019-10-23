package main

import (
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/tea"
	"strconv"
)

func EncryptByTea(content []byte, key []byte, rounds int) []byte {
	block, err := tea.NewCipherWithRounds(key, rounds)
	if err != nil {
		return []byte{}
	}
	// crypto/tea 源码里面加密轮数除以了 2
	rounds = rounds << 1

	n := 8 - len(content)%8
	encryptBytes := make([]byte, len(content)+n)
	copyArray(&content, 0, &encryptBytes, 0, len(content))
	fillChar(&encryptBytes, byte(n), len(content), n)
	result := make([]byte, len(encryptBytes))
	for offset := 0; offset < len(result); offset += 8 {
		temp := make([]byte, 8)
		block.Encrypt(temp, encryptBytes[offset:offset+8])
		copyArray(&temp, 0, &result, offset, 8)
	}
	return result
}

func DecryptByTea(content []byte, key []byte, rounds int) []byte {
	block, err := tea.NewCipherWithRounds(key, rounds)
	if err != nil {
		return []byte{}
	}

	result := make([]byte, len(content))
	for offset := 0; offset < len(content); offset += 8 {
		temp := make([]byte, 8)
		block.Decrypt(temp, content[offset:offset+8])
		copyArray(&temp, 0, &result, offset, 8)
	}
	lastIndex := len(result) - int(result[len(result)-1])
	return result[:lastIndex]
}

func fillChar(content *[]byte, char byte, startIndex int, time int) {
	for j := 0; j < time; j++ {
		(*content)[startIndex] = char
		startIndex++
	}
}

func copyArray(src *[]byte, srcPos int, dest *[]byte, destPos int, length int) {
	for i := 0; i < length; i++ {
		(*dest)[destPos] = (*src)[srcPos]
		srcPos++
		destPos++
	}
}

func HexToByteArray(str string) *[]byte {
	sLen := len(str)
	bHex := make([]byte, len(str)/2)
	ii := 0
	for i := 0; i < len(str); i = i + 2 {
		if sLen != 1 {
			ss := string(str[i]) + string(str[i+1])
			bt, _ := strconv.ParseInt(ss, 16, 32)
			bHex[ii] = byte(bt)
			ii = ii + 1
			sLen = sLen - 2
		}
	}
	return &bHex
}

func main() {
	key := HexToByteArray("8287BB000DA8422B497C72B21D7B3CB0")
	text := HexToByteArray("1f0400160064000469ee0b3f0001000200000019000401010101c0")

	result := EncryptByTea(*text, *key, 16)
	fmt.Println(hex.EncodeToString(result))

	result1 := DecryptByTea(result, *key, 16)
	fmt.Println(hex.EncodeToString(result1))

}
