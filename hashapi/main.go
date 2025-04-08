package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"runtime"
	"strings"

	"github.com/For-ACGN/hash-api/rorwk"
)

var (
	format   string
	modName  string
	funcName string
	hexKey   string
	concise  bool
)

func init() {
	var defaultFormat string
	switch runtime.GOARCH {
	case "386":
		defaultFormat = "32"
	case "amd64":
		defaultFormat = "64"
	}
	flag.StringVar(&format, "fmt", defaultFormat, "binary format: 32 or 64")
	flag.StringVar(&modName, "mod", "kernel32.dll", "module name")
	flag.StringVar(&funcName, "func", "WinExec", "function name")
	flag.StringVar(&hexKey, "key", "", "specific key, it must be hex format")
	flag.BoolVar(&concise, "conc", false, "print concise result for development")
	flag.Parse()
}

func main() {
	var (
		numZero string
		apiHash []byte
		hashKey []byte
		err     error
	)
	if hexKey != "" {
		hashKey, err = hex.DecodeString(hexKey)
		if err != nil {
			log.Fatalln("invalid hash key:", err)
		}
	}
	switch format {
	case "64":
		if hashKey != nil {
			apiHash, err = rorwk.HashAPI64WithKey(modName, funcName, hashKey)
		} else {
			apiHash, hashKey, err = rorwk.HashAPI64(modName, funcName)
		}
		numZero = "16"
	case "32":
		if hashKey != nil {
			apiHash, err = rorwk.HashAPI32WithKey(modName, funcName, hashKey)
		} else {
			apiHash, hashKey, err = rorwk.HashAPI32(modName, funcName)
		}
		numZero = "8"
	default:
		log.Fatalln("invalid format:", format)
	}
	if err != nil {
		log.Fatalln("failed to calculate hash:", err)
	}
	if concise {
		h := rorwk.BytesToUint64(apiHash)
		k := rorwk.BytesToUint64(hashKey)
		fmt.Printf("0x%0"+numZero+"X, "+"0x%0"+numZero+"X // %s\n", h, k, funcName)
		return
	}
	fmt.Println("module:  ", modName)
	fmt.Println("function:", funcName)
	fmt.Printf("format:   %s bit\n", format)
	fmt.Println()
	fmt.Printf("Hash: 0x%0"+numZero+"X\n", rorwk.BytesToUint64(apiHash))
	fmt.Printf("Key:  0x%0"+numZero+"X\n", rorwk.BytesToUint64(hashKey))
	fmt.Printf("Hash: %s\n", dumpBytesHex(apiHash))
	fmt.Printf("Key:  %s\n", dumpBytesHex(hashKey))
}

func dumpBytesHex(b []byte) string {
	n := len(b)
	builder := strings.Builder{}
	builder.Grow(len("0xFF, ")*n - len(", "))
	for i := 0; i < n; i++ {
		builder.WriteString("0x")
		v := hex.EncodeToString([]byte{b[i]})
		v = strings.ToUpper(v)
		builder.WriteString(v)
		if i == n-1 {
			break
		}
		builder.WriteString(", ")
	}
	return builder.String()
}
