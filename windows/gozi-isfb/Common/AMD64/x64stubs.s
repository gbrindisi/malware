;//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
;// ActiveDll project. Version 1.5
;//	
;// module: x64stubs.asm
;// $Revision: 178 $
;// $Date: 2012-07-20 18:23:46 +0400 (Ïò, 20 èþë 2012) $
;// description: 
;//	 AMD64 context stubs.

_TEXT segment


;// WOW64 inject context stub.
;// Receives pointer to INJECT_CONTEXT structure in RAX
Win64InjectStub	proc
	push [rax]		;// retpoint

	push rcx
	push rdx
	push r8
	push r9		;// push r9

	push rbp
	mov rbp, rsp
	sub rsp, 30h
	and rsp, 0fffffffffffffff0h

	mov rdx, [rax+8]
	mov rcx, [rax+10h]

	call rdx

	mov rsp, rbp

	pop rbp
	
	pop r9
	pop r8
	pop rdx
	pop rcx
	ret
Win64InjectStub	endp


Wow64InjectStub	proc
	push [rax]
	mov edx, [rax+8]
	mov ecx, [rax+10h]

	push rcx
	call rdx
	ret
Wow64InjectStub endp

_TEXT ends


public	Win64InjectStub

end
