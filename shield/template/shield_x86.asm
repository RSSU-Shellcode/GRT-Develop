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

  // ensure stack is 16 bytes aligned
  push ebp
  mov ebp, esp
  and esp, 0xFFFFFFF0
  push ebp






  // restore stack and ebp
  pop ebp
  mov esp, ebp
  pop ebp
  ret 4
