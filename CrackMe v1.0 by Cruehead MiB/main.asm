.386

.model flat,stdcall
option casemap:none

DlgProc proto :DWORD,:DWORD,:DWORD,:DWORD
GenerateKey proto
InvertString proto :DWORD

include windows.inc
include kernel32.inc
include user32.inc
includelib kernel32.lib
includelib user32.lib

.data
DlgName db "#100",0
format db "%lu",0
buffer db 512 dup(0)

.data?
hInstance HINSTANCE ?
CommandLine LPSTR ?
editInputHandle dd ?
editOutputHandle dd ?

.const
IDGENERATE equ 40000
IDEDITINPUT equ 40001
IDEDITOUTPUT equ 40002 

.code
start:
	invoke GetModuleHandle, NULL
	mov hInstance, eax
	invoke DialogBoxParam, hInstance, ADDR DlgName, NULL, addr DlgProc, NULL
	invoke ExitProcess, eax
	
DlgProc proc hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
	.IF uMsg==WM_INITDIALOG
		invoke GetDlgItem, hWnd, IDEDITOUTPUT
		mov editOutputHandle,eax
		
		invoke GetDlgItem, hWnd, IDEDITINPUT
		mov editInputHandle, eax
		invoke SetFocus, eax
	.ELSEIF uMsg==WM_CLOSE
		invoke PostQuitMessage, NULL
	.ELSEIF uMsg==WM_COMMAND
		mov eax, wParam
		.IF lParam==0
		.ELSE
			mov edx, wParam
			shr edx,16
			.if dx==BN_CLICKED
				.if ax==IDGENERATE
					invoke GenerateKey
					invoke SetDlgItemText, hWnd, IDEDITOUTPUT, addr buffer
				.endif
			.endif
		.ENDIF
	.else
		mov eax, FALSE
		ret
	.ENDIF
	mov eax,TRUE
	Ret
DlgProc endp

GenerateKey proc
	local serial:DWORD, divisor:DWORD
	mov divisor,0Ah
	
	invoke GetWindowText, editInputHandle, addr buffer, 512

	mov esi,offset buffer
	
	invoke CharUpper, addr buffer
	
	xor edi,edi
	xor ebx,ebx
	
	@@:
	mov bl, byte ptr ds:[ESI]
	test bl,bl
	je @f
	add edi,ebx
	inc esi
	jmp @b
	@@:
	
	xor edi,5678h
	mov serial,edi
	
	invoke InvertString, addr buffer
	
	mov eax,serial
	mov esi,offset buffer
	xor ebx,ebx
	xor edx,edx
	xor eax,1234h
	
	@@:
	mov bl,byte ptr [esi]
	test bl,bl
	je @f
	sub bl,30h
	sub eax, ebx
	idiv divisor
	xor edx,edx
	inc esi
	jmp @b
	@@:
	
	invoke wsprintf, addr buffer, addr format, eax
	
	Ret
GenerateKey endp

InvertString proc StringPtr:DWORD
	invoke lstrlen, StringPtr
	push edi
	xor ebx,ebx
	xor ecx,ecx
	xor edx,edx
	xor edi,edi
	mov edi, dword ptr [StringPtr]
	
	@@:
	.if ebx < eax
		mov dl, byte ptr [edi + ebx]
		mov cl, byte ptr [edi + eax]
		mov byte ptr [edi + ebx], cl
		mov byte ptr [edi + eax], dl
		
		inc ebx
		dec eax
		jmp @b
	.endif
	
	pop edi
	Ret
InvertString endp
end start
