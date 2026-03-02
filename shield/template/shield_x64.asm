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
  // ensure stack is 16 bytes aligned
  push rbp
  mov rbp, rsp
  and rsp, 0xFFFFFFFFFFFFFFF0
  push rbp

  // save context
  push {{.RegN.rbp}}                           // for save structure pointer
  push {{.RegN.rbx}}                           // for save crypto key
  push {{.RegN.rsi}}                           // for save the memory page old protect

  // save fields to non-volatile registers
  mov {{.RegN.rbp}}, rcx                       // save structure pointer
  mov {{.RegN.rbx}}, [{{.RegN.rbp}} + 5*8]     // save crypto key

  // encrypt return address
  mov {{.RegV.rcx}}, [rsp + 2*8]
  xor {{.RegV.rcx}}, {{.RegN.rbx}}
  mov [rsp + 2*8], {{.RegV.rcx}}

  // encrypt the critical memory
  mov {{.RegV.rcx}}, [{{.RegN.rbp}}]
  mov {{.RegV.rdx}}, [{{.RegN.rbp}} + 1*8]
  call encrypt

  // adjust the protect to PAGE_READWRITE
  mov r8, 0x04
  call protect







  // recover the protect to old protect
  mov r8, {{.RegN.rsi}}
  call protect

  // decrypt return address
  mov {{.RegV.rcx}}, [rsp + 2*8]
  xor {{.RegV.rcx}}, {{.RegN.rbx}}
  mov [rsp + 2*8], {{.RegV.rcx}}

  // restore context
  pop {{.RegN.rsi}}
  pop {{.RegN.rbx}}
  pop {{.RegN.rbp}}

  // restore stack and rbp
  pop rbp
  mov rsp, rbp
  pop rbp
  ret

encrypt:
  shr {{.RegV.rdx}}, 3                         // calculate the loop count
 loop_xor:
  xor [{{.RegV.rcx}}], {{.RegN.rbx}}           // encrypt 8 bytes with xor
  add {{.RegV.rcx}}, 8                         // add data address
  dec {{.RegV.rdx}}                            // update loop count
  jnz loop_xor                                 // check need decrypt again
  ret

protect:
  sub rsp, 0x08                                // for save old protect
  mov rax, [{{.RegN.rbp}} + 2*8]               // get address of VirtualProtect
  mov rcx, [{{.RegN.rbp}}]                     // set address of critical
  mov rdx, [{{.RegN.rbp}} + 1*8]               // set size of critical
  mov r9,  rsp                                 // lpflOldProtect
  sub rsp, 0x20                                // reserve stack for call convention
  call rax                                     // call VirtualProtect
  add rsp, 0x20                                // restore stack for call convention
  mov {{.RegN.rsi}}, [rsp]                     // save old protect
  add rsp, 0x08                                // restore stack for old protect
  ret
