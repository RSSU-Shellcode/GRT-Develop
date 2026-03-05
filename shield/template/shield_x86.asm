.code32

// the CriticalSize must be aligned with 4 bytes

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
  // check argument is valid
  mov {{.RegV.ecx}}, [esp+4]
  test {{.RegV.ecx}}, {{.RegV.ecx}}
  jnz next
  ret 4
 next:

  // store argument before stack alignment
  mov eax, [esp+4]

  // ensure stack is 16 bytes aligned
  push ebp
  mov ebp, esp
  and esp, 0xFFFFFFF0
  push ebp

  // save context
  push {{.RegN.ebp}}                           // for save structure pointer
  push {{.RegN.ebx}}                           // for save crypto key
  push {{.RegN.esi}}                           // for save the memory page old protect

  // save fields to non-volatile registers
  mov {{.RegN.ebp}}, eax                       // save structure pointer
  mov {{.RegN.ebx}}, [{{.RegN.ebp}} + 5*4]     // save crypto key

  // encrypt return address
  mov {{.RegV.ecx}}, [esp + 2*4]
  xor {{.RegV.ecx}}, {{.RegN.ebx}}
  mov [esp + 2*4], {{.RegV.ecx}}

  // encrypt the critical memory
  mov {{.RegV.ecx}}, [{{.RegN.ebp}}]           // get critical address
  mov {{.RegV.edx}}, [{{.RegN.ebp}} + 1*4]     // set the critical size
  call xor_buf

  // adjust the page protect to PAGE_READWRITE
  push 0x04
  call protect

  // prepare argument before encrypt stack
  xor {{.RegV.eax}}, {{.RegV.eax}}             // clear register
  dec {{.RegV.eax}}                            // calcualte 0xFFFFFFFF
  mov edx, {{.RegV.eax}}                       // set INFINITE
  mov ecx, [{{.RegN.ebp}} + 4*4]               // set handle of hTimer
  mov eax, [{{.RegN.ebp}} + 3*4]               // get address of WaitForSingleObject

  // save argument about WaitForSingleObject
  push edx
  push ecx
  push eax

  // encrypt argument structure
  mov {{.RegV.ecx}}, {{.RegN.ebp}}             // get structure pointer
  mov {{.RegV.edx}}, 6*4                       // set the buffer size
  call xor_buf

  // Sleep with WaitForSingleObject
  pop eax                                      // get WaitForSingleObject address
  call eax                                     // call WaitForSingleObject

  // decrypt argument structure
  mov {{.RegV.ecx}}, {{.RegN.ebp}}             // get structure pointer
  mov {{.RegV.edx}}, 6*4                       // set the buffer size
  call xor_buf

  // recover the page protect to old protect
  push {{.RegN.esi}}
  call protect

  // decrypt the critical memory
  mov {{.RegV.ecx}}, [{{.RegN.ebp}}]           // get critical address
  mov {{.RegV.edx}}, [{{.RegN.ebp}} + 1*4]     // set the critical size
  call xor_buf

  // decrypt return address
  mov {{.RegV.ecx}}, [esp + 2*4]
  xor {{.RegV.ecx}}, {{.RegN.ebx}}
  mov [esp + 2*4], {{.RegV.ecx}}

  // restore context
  pop {{.RegN.esi}}
  pop {{.RegN.ebx}}
  pop {{.RegN.ebp}}

  // restore stack and ebp
  pop ebp
  mov esp, ebp
  pop ebp
  ret 4

xor_buf:
  shr {{.RegV.edx}}, 2                         // calculate the loop count
 loop_xor:
  xor [{{.RegV.ecx}}], {{.RegN.ebx}}           // encrypt 8 bytes with xor
  add {{.RegV.ecx}}, 4                         // add data address
  dec {{.RegV.edx}}                            // update loop count
  jnz loop_xor                                 // check need decrypt again
  ret

protect:
  mov {{.RegV.eax}}, [esp+4]                   // read argument about new protect
  sub esp, 0x04                                // for save old protect
  push esp                                     // lpflOldProtect
  push {{.RegV.eax}}                           // new protect
  mov {{.RegV.ecx}}, [{{.RegN.ebp}} + 1*4]     // set size of critical
  push {{.RegV.ecx}}                           // push size
  mov {{.RegV.ecx}}, [{{.RegN.ebp}}]           // set address of critical
  push {{.RegV.ecx}}                           // push address
  mov {{.RegV.eax}}, [{{.RegN.ebp}} + 2*4]     // get address of VirtualProtect
  call {{.RegV.eax}}                           // call VirtualProtect
  mov {{.RegN.esi}}, [esp]                     // save old protect
  add esp, 0x04                                // restore stack for old protect
  ret 4                                        // return and release stack
