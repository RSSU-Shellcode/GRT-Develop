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
	procName string
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
	flag.StringVar(&procName, "proc", "WinExec", "procedure name")
	flag.StringVar(&hexKey, "key", "", "specific key, it must be hex format")
	flag.BoolVar(&concise, "conc", false, "print concise result for development")
	flag.Parse()
}

func main() {
	var (
		nZero string
		mHash []byte
		pHash []byte
		hKey  []byte
		err   error
	)
	if hexKey != "" {
		hKey, err = hex.DecodeString(hexKey)
		if err != nil {
			log.Fatalln("invalid hash key:", err)
		}
	}
	switch format {
	case "64":
		if hKey == nil {
			mHash, pHash, hKey, err = rorwk.HashAPI64(modName, procName)
		} else {
			mHash, pHash, err = rorwk.HashAPI64WithKey(modName, procName, hKey)
		}
		nZero = "16"
	case "32":
		if hKey == nil {
			mHash, pHash, hKey, err = rorwk.HashAPI32(modName, procName)
		} else {
			mHash, pHash, err = rorwk.HashAPI32WithKey(modName, procName, hKey)
		}
		nZero = "8"
	default:
		log.Fatalln("invalid format:", format)
	}
	if err != nil {
		log.Fatalln("failed to calculate hash:", err)
	}
	if concise {
		f := "0x%0" + nZero + "X"
		m := rorwk.BytesToUint64(mHash)
		p := rorwk.BytesToUint64(pHash)
		k := rorwk.BytesToUint64(hKey)
		fmt.Printf("{ "+f+", "+f+", "+f+" }, // %s\n", m, p, k, procName)
		return
	}
	fmt.Println("module:   ", modName)
	fmt.Println("procedure:", procName)
	fmt.Printf("format:    %s bit\n", format)
	fmt.Println()
	fmt.Printf("Module Hash:    0x%0"+nZero+"X\n", rorwk.BytesToUint64(mHash))
	fmt.Printf("Procedure Hash: 0x%0"+nZero+"X\n", rorwk.BytesToUint64(pHash))
	fmt.Printf("Hash Key:       0x%0"+nZero+"X\n", rorwk.BytesToUint64(hKey))
	fmt.Println()
	fmt.Printf("Module Hash:    %s\n", dumpBytesHex(mHash))
	fmt.Printf("Procedure Hash: %s\n", dumpBytesHex(pHash))
	fmt.Printf("Hash Key:       %s\n", dumpBytesHex(hKey))
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
