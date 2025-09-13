# GRT-Develop
A package for deep customization of Gleam-RT. 

## option and argument
```go
package main

import (
    "fmt"
    "os"

    "github.com/RSSU-Shellcode/GRT-Develop/argument"
    "github.com/RSSU-Shellcode/GRT-Develop/option"
)

func main() {
    template, err := os.ReadFile("Gleam-RT.bin")
    checkError(err)

    opts := option.Options{
        DisableSysmon:       false,
        DisableWatchdog:     false,
        NotEraseInstruction: false,
        NotAdjustProtect:    false,
        TrackCurrentThread:  false,
    }
    template, err = option.Set(template, &opts)
    checkError(err)

    arg1 := &argument.Arg{
        ID:   0,
        Data: []byte("arg1"),
    }
    arg2 := &argument.Arg{
        ID:   1,
        Data: []byte("arg2"),
    }
    stub, err := argument.Encode(arg1, arg2)
    checkError(err)

    output := append(template, stub...)
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
