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
  mov {{.RegV.rcx}}, [{{.RegN.rbp}}]           // get critical address
  mov {{.RegV.rdx}}, [{{.RegN.rbp}} + 1*8]     // set the critical size
  call xor_buf

  // adjust the page protect to PAGE_READWRITE
  mov r8, 0x04
  call protect

  // prepare argument before encrypt stack
  mov {{.RegV.rax}}, 0xFFFFFFFF
  mov rdx, {{.RegV.rax}}                       // set INFINITE
  mov rcx, [{{.RegN.rbp}} + 4*8]               // set handle of hTimer
  mov rax, [{{.RegN.rbp}} + 3*8]               // get address of WaitForSingleObject

  // save argument about WaitForSingleObject
  push rax
  push rcx
  push rdx

  // encrypt  argument structure
  mov {{.RegV.rcx}}, {{.RegN.rbp}}             // get structure pointer
  mov {{.RegV.rdx}}, 6*8                       // set the buffer size
  call xor_buf

  // restore argument about WaitForSingleObject
  pop rdx
  pop rcx
  pop rax

  // Sleep with WaitForSingleObject
  sub rsp, 0x20                                // reserve stack for call convention
  call rax                                     // call WaitForSingleObject
  add rsp, 0x20                                // restore stack for call convention

  // decrypt argument structure
  mov {{.RegV.rcx}}, {{.RegN.rbp}}             // get structure pointer
  mov {{.RegV.rdx}}, 6*8                       // set the buffer size
  call xor_buf

  // recover the page protect to old protect
  mov r8, {{.RegN.rsi}}
  call protect

  // decrypt the critical memory
  mov {{.RegV.rcx}}, [{{.RegN.rbp}}]           // get critical address
  mov {{.RegV.rdx}}, [{{.RegN.rbp}} + 1*8]     // set the critical size
  call xor_buf

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

xor_buf:
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
