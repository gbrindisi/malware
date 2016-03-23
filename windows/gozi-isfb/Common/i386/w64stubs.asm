;//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
;// ActiveDll project. Version 1.5
;//	
;// module: w64stubs.asm
;// $Revision: 261 $
;// $Date: 2014-07-05 15:11:09 +0400 (Сб, 05 июл 2014) $
;// description: 
;//	 X86 and WOW64 context stubs.

.686p

_TEXT segment

;// REX prefixes used
REXW	MACRO
	db 48h
ENDM

REXB	MACRO
	db 41h
ENDM

REXR	MACRO
	db 4Ch
ENDM

;// LONG _cdecl Wow64NativeCall(ULONGLONG NativeFunctionAddress, ULONGLONG NumberOfArgs, ...)
;// All arguments are ULONG64 values.
;// Switches processor into the Long mode and calls the specified native function with the specified argument list.
 _Wow64NativeCall	proc
  push ebp
  push ebx
  push esi
  mov ebp, esp
  lea eax, [esp-8]
  and eax, 0fffffff8h
  mov esp, eax
  lea ecx, [ebp+10h]
  push 33h
  call @@1

;// ---- x64 code starts here --------------------------------------------------------------------------------------------
  push ebp
  push esi

  sub esp,20h
  mov ebp,esp
  and esp,0fffffff0h

  REXW
  mov esi, [ecx]			;// mov rsi, [rcx]

  lea edx, [ecx+8]
  mov ecx, [edx]

  add ecx, 1
  and ecx, 0feh
 @@:
  push dword ptr [edx+ecx*8]
  loop @B

  REXW
  mov ecx, [esp]			;// mov rcx, [rsp]
  REXW	
  mov edx, [esp+8]			;// mov rdx, [rsp+8]
  REXR
  mov eax, [esp+10h]		;// mov r8, [rsp+10h]
  REXR
  mov ecx, [esp+18h]		;// mov r9, [rsp+18h]

  call esi

  mov esp,ebp
  add esp,20h
  pop esi
  pop ebp
  retf
;// ---- End of x64 code ------------------------------------------------------------------------------------------------
@@1:
  call fword ptr[esp]

  mov esi, eax				;//	 A serializing instruction is required here, to avoid access violation later 
  xor eax,eax				;//	  when working with the stack.
  cpuid						;//
  mov eax, esi				;//

  mov esp, ebp
  pop esi
  pop ebx
  pop ebp
  ret
_Wow64NativeCall	endp



;// WOW64 inject context stub.
;// Receives pointer to INJECT_CONTEXT structure in RAX
_Wow64InjectStub	proc
	push [eax]		;// retpoint

	push ecx
	push edx
	REXB
	push eax		;// push r8
	REXB
	push ecx		;// push r9
	push ebp
	REXW
	mov ebp, esp
	REXW
;// Since we get here by the context switch from the patched application entry point we always have the stack misaligned.
;// Here we have to align it on 16-bytes boundary to avoid application crash while saving SSE-state.
	sub esp, 38h

	REXW
	mov edx, [eax+8]
	REXW
	mov ecx, [eax+10h]

	call edx

	REXW
	mov esp, ebp

	pop ebp
	REXB
	pop ecx
	REXB
	pop eax
	pop edx
	pop ecx
	ret
_Wow64InjectStub	endp

_Win32InjectStub	proc
	push [eax]
	mov ecx, [eax+10h]
	mov edx, [eax+8]
	push ecx
	call edx
	ret
_Win32InjectStub	endp

_TEXT ends

public	_Wow64NativeCall
public	_Wow64InjectStub

end