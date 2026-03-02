.code64

// the CriticalSize must be aligned with 8 bytes

// struct:
//   CriticalAddress
//   CriticalSize
//   VirtualProtect
//   WaitForSingleObject
//   Timer
//   Key

// steps:
//   encrypt return address
//   encrypt the critical instructions
//   adjust the memory page protect
//   encrypt stack about structure
//   call WaitForSingleObject
//   decrypt stack about structure
//   restore the memory page protect
//   decrypt the critical instructions
//   decrypt return address

entry:
  // save context
  push {{.RegN.rbp}}
  push {{.RegN.rbx}}

  // save structure pointer to non-volatile register
  // save crypto key to non-volatile register
  mov {{.RegN.rbp}}, rcx
  mov {{.RegN.rbx}}, [{{.RegN.rbp}} + 5*8]

  // encrypt return address
  mov {{.RegV.rcx}}, [rsp + 2*8]
  xor {{.RegV.rcx}}, {{.RegN.rbx}}
  mov [rsp + 2*8], {{.RegV.rcx}}

  // encrypt the runtime instructions
  mov {{.RegV.rcx}}, [{{.RegN.rbp}}]
  mov {{.RegV.rdx}}, [{{.RegN.rbp}} + 1*8]
  call encrypt



  // decrypt return address
  mov {{.RegV.rcx}}, [rsp + 2*8]
  xor {{.RegV.rcx}}, {{.RegN.rbx}}
  mov [rsp + 2*8], {{.RegV.rcx}}

  // restore context
  pop {{.RegN.rbx}}
  pop {{.RegN.rbp}}
  ret

encrypt:
  shr {{.RegV.rdx}}, 3                  // calculate the loop count
 loop_xor:
  xor [{{.RegV.rcx}}], {{.RegN.rbx}}    // encrypt 8 bytes with xor
  add {{.RegV.rcx}}, 8                  // add data address
  dec {{.RegV.rdx}}                     // update loop count
  jnz loop_xor                          // check need decrypt again
  ret
