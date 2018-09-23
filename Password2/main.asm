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
	pushad
	
	mov ecx,result3
	mov ebx,result2
	mov eax,result1
	
	.if code == 1
		add ecx,54Bh
		imul ebx,eax
		xor eax,ecx
	.elseif code == 2
		sub ecx,233h
		imul ebx,ebx,14h
		add ecx,eax
		and ebx,eax
	.elseif code == 3
		add eax,582h
		imul ecx,ecx,16h
		xor ebx,eax
	.elseif code == 4
		and eax,ebx
		sub ebx,111222h
		xor ecx,eax
	.elseif code == 5
		.if eax == 80000000h
			xor eax,eax
		.endif
	
		cdq
		
		.if ecx > 0
			idiv ecx
		.endif
		
		sub ebx,edx
		add eax,ecx
	.elseif code == 6
		xor eax,ecx
		and ebx,eax
		add ecx,546879h
	.elseif code == 7
		sub ecx,25FF5h
		xor ebx,ecx
		add eax,401000h
	.elseif code == 8
		xor eax,ecx
		imul ebx,ebx,14h
		add ecx,12589h
	.elseif code == 9
		sub eax,542187h
		sub ebx,eax
		xor ecx,eax
	.elseif code == 0Ah
		.if eax == 80000000h
			xor eax,eax
		.endif
	
		cdq
		
		.if ebx > 0
			idiv ebx
		.endif
		
		add ebx,edx
		imul eax,edx
		xor ecx,edx
	.elseif code == 0Bh
		add ebx,1234FEh
		add ecx,2345DEh
		add eax,9CA4439Bh
	.elseif code == 0Ch
		xor eax,ebx
		sub ebx,ecx
		imul ecx,ecx,12h
	.elseif code == 0Dh
		and eax,12345678h
		sub ecx,65875h
		imul ebx,ecx
	.elseif code == 0Eh
		xor eax,55555h
		sub ebx,587351h
	.else
		add eax,ebx
		add ebx,ecx
		add ecx,eax
	.endif
	
	mov result1,eax
	mov result2,ebx
	mov result3,ecx
	
	Ret
TransformResult endp
end start