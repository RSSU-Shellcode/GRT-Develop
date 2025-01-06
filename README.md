# GRT-Config
A package for configure Gleam-RT options and Encode/Decode argument stub. 

## Usage
```go
package main

import (
    "fmt"
    "os"

    "github.com/RSSU-Shellcode/GRT-Config/argument"
    "github.com/RSSU-Shellcode/GRT-Config/option"
)

func main() {
    tpl, err := os.ReadFile("Gleam-RT.bin")
    checkError(err)

    opts := option.Options{
        NotEraseInstruction: false,
        NotAdjustProtect:    false,
        TrackCurrentThread:  false,
    }
    tpl, err = option.Set(tpl, &opts)
    checkError(err)

    args := [][]byte{
        []byte("arg1"), []byte("arg2"),
    }
    stub, err := argument.Encode(args...)
    checkError(err)

    output := append(tpl, stub...)
    err = os.WriteFile("output.bin", output, 0600)
    checkError(err)
}

func checkError(err error) {
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}
```
