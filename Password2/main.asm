.386

.model flat,stdcall
option casemap:none

include windows.inc
include kernel32.inc
include user32.inc
includelib kernel32.lib
includelib user32.lib

DlgProc proto :DWORD,:DWORD,:DWORD,:DWORD
GenerateKey proto
TransformResult proto :DWORD
IncrementCombination proto
SaveCombination proto
ResetValues proto
GetCodeAsChar proto :BYTE

.data
DlgName db "#100",0
format db "%lu",0
buffer db 512 dup(0)
bufferIndex dd 0

num1 dd 0DEADh
num2 dd 0DEADh
num3 dd 42424242h
result1 dd 0DEADh
result2 dd 0DEADh
result3 dd 42424242h

;Initializing the first combination for the shameless brute forcing. Be patient.
;combination db 1,1,1,1,1,1,1,1,1,1

;Correct password
combination db 7,9,0Dh,0Eh,6,2,4,0Ch,4,0Bh

.data?
hInstance HINSTANCE ?

.const
ID_EDIT_PASSWORD equ 40001

.code
start:
	invoke GetModuleHandle, NULL
	mov hInstance, eax
	invoke DialogBoxParam, hInstance, ADDR DlgName, NULL, addr DlgProc, NULL
	invoke ExitProcess, eax
	
DlgProc proc hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
	.if uMsg==WM_INITDIALOG
		invoke GenerateKey
		invoke SetDlgItemText, hWnd, ID_EDIT_PASSWORD, addr buffer
	.elseif uMsg==WM_CLOSE
		invoke PostQuitMessage, NULL
	.else
		mov eax, FALSE
		ret
	.endif
	
	mov eax,TRUE
	Ret
DlgProc endp

GenerateKey proc
	local index:DWORD
	
	@@:
	mov index,0
	.while index < 0Ah
		mov ebx,offset combination
		mov edx,index
		movzx eax,byte ptr [ebx + edx]
		invoke TransformResult,eax
		add index,1
	.endw
	
	.if dword ptr [result1] == 9CC5B4B9h && dword ptr [result2] == 0D1EB13FBh && dword ptr [result3] == 837D424Eh
		invoke SaveCombination
		ret
	.endif
	
	invoke IncrementCombination
	
	.if eax == 0
		ret
	.endif
	
	invoke ResetValues
	jmp @b
	
	Ret
GenerateKey endp

SaveCombination proc
	mov edx,0
	mov ebx, offset buffer
	mov ecx, offset combination
	push edi
	
	@@:
	invoke GetCodeAsChar, byte ptr [ecx + edx]
	mov edi,bufferIndex
	mov byte ptr [ebx + edi],al
	add edx,1
	add bufferIndex,1
	
	.if edx < 0Ah
		jmp @b
	.endif
	
	mov edi,bufferIndex
	mov byte ptr [ebx + edi],0
	add bufferIndex,1
	
	pop edi
	Ret
SaveCombination endp

IncrementCombination proc
	mov ebx, 9
	mov ecx, offset combination
	
	@@:
	add byte ptr [ecx + ebx],1
	
	.if byte ptr [ecx + ebx] == 10h
		.if ebx == 0
			xor eax,eax
			ret
		.endif
	
		mov byte ptr [ecx + ebx], 1
		sub ebx,1
		jmp @b
	.endif
	
	mov eax,1
	Ret
IncrementCombination endp

ResetValues proc
	mov eax,num1
	mov ebx,num2
	mov ecx,num3
	mov result1,eax
	mov result2,ebx
	mov result3,ecx
	
	Ret
ResetValues endp

GetCodeAsChar proc code:BYTE
	mov al, code
	
	.if code > 0 && code < 0Ah
		add al,30h
	.else
		add al,37h
	.endif

	Ret
GetCodeAsChar endp

TransformResult proc code:DWORD
	PUSHAD
	
	MOV ECX,result3
	MOV EBX,result2
	MOV EAX,result1
	
	.if code == 1
		ADD ECX,54Bh
		IMUL EBX,EAX
		XOR EAX,ECX
	.elseif code == 2
		SUB ECX,233h
		IMUL EBX,EBX,14h
		ADD ECX,EAX
		AND EBX,EAX
	.elseif code == 3
		ADD EAX,582h
		IMUL ECX,ECX,16h
		XOR EBX,EAX
	.elseif code == 4
		AND EAX,EBX
		SUB EBX,111222h
		XOR ECX,EAX
	.elseif code == 5
		.if eax == 80000000h
			xor eax,eax
		.endif
	
		CDQ
		
		.if ecx > 0
			IDIV ECX
		.endif
		
		SUB EBX,EDX
		ADD EAX,ECX
	.elseif code == 6
		XOR EAX,ECX
		AND EBX,EAX
		ADD ECX,546879h
	.elseif code == 7
		SUB ECX,25FF5h
		XOR EBX,ECX
		ADD EAX,401000h
	.elseif code == 8
		XOR EAX,ECX
		IMUL EBX,EBX,14h
		ADD ECX,12589h
	.elseif code == 9
		SUB EAX,542187h
		SUB EBX,EAX
		XOR ECX,EAX
	.elseif code == 0Ah
		.if eax == 80000000h
			xor eax,eax
		.endif
	
		CDQ
		
		.if ebx > 0
			IDIV EBX
		.endif
		
		ADD EBX,EDX
		IMUL EAX,EDX
		XOR ECX,EDX
	.elseif code == 0Bh
		ADD EBX,1234FEh
		ADD ECX,2345DEh
		ADD EAX,9CA4439Bh
	.elseif code == 0Ch
		XOR EAX,EBX
		SUB EBX,ECX
		IMUL ECX,ECX,12h
	.elseif code == 0Dh
		AND EAX,12345678h
		SUB ECX,65875h
		IMUL EBX,ECX
	.elseif code == 0Eh
		XOR EAX,55555h
		SUB EBX,587351h
	.else
		ADD EAX,EBX
		ADD EBX,ECX
		ADD ECX,EAX
	.endif
	
	mov result1,eax
	mov result2,ebx
	mov result3,ecx
	
	Ret
TransformResult endp
end start