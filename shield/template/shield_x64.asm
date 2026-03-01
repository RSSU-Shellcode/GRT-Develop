.code64

// struct:
//   CriticalAddress
//   CriticalSize
//   VirtualProtect
//   WaitForSingleObject
//   Timer
//   Key

// steps:
//   encrypt return address
//   encrypt the runtime instructions
//   encrypt stack about structure
//   adjust the memory page protect
//   call WaitForSingleObject
//   restore the memory page protect
//   decrypt stack about structure
//   decrypt the runtime instructions
//   decrypt return address

entry:
  // save context
  push {{.RegN.rbp}}
  push {{.RegN.rbx}}

  // save structure pointer to non-volatile register
  // save crypto key to non-volatile register
  mov {{.RegN.rbp}}, rcx
  mov {{.RegN.rbx}}, [{{.RegN.rbp}} + (3+5)*8]

  // encrypt return address
  pop  {{.RegV.rcx}}
  xor  {{.RegV.rcx}}, {{.RegN.rbx}}
  push {{.RegV.rcx}}




  // decrypt return address
  pop  {{.RegV.rcx}}
  xor  {{.RegV.rcx}}, {{.RegN.rbx}}
  push {{.RegV.rcx}}

  mov rax, {{.RegN.rbx}}

  // restore context
  pop {{.RegN.rbx}}
  pop {{.RegN.rbp}}


  ret
