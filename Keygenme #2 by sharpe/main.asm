.386

.model flat,stdcall
option casemap:none

include windows.inc
include kernel32.inc
include user32.inc
include ../Misc/misc.inc
includelib kernel32.lib
includelib user32.lib
includelib ../Misc/misc.lib

DlgProc proto :DWORD,:DWORD,:DWORD,:DWORD
GenerateKey proto

.data
dlgName db "#100",0
format db "%lu",0
resultBuffer db 512 dup(0)

.data?
hInstance HINSTANCE ?
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
	
	invoke DialogBoxParam, hInstance, addr dlgName, NULL, addr DlgProc, NULL
	invoke ExitProcess, eax
	
DlgProc proc hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
	.if uMsg==WM_INITDIALOG
		invoke GetDlgItem, hWnd, IDEDITOUTPUT
		mov editOutputHandle, eax
		
		invoke GetDlgItem, hWnd, IDEDITINPUT
		mov editInputHandle, eax
		invoke SetFocus, eax
	.elseif uMsg==WM_CLOSE
		invoke PostQuitMessage, NULL
	.elseif uMsg==WM_COMMAND
		mov eax, wParam
		
		.if lParam==0
		.else
			mov edx, wParam
			shr edx,16
			
			.if dx==BN_CLICKED
				.if ax==IDGENERATE
					invoke GenerateKey
					
					mov ebx, offset resultBuffer
					add ebx, 10h
					invoke SetDlgItemText, hWnd, IDEDITOUTPUT, ebx
				.endif
			.endif
		.endif
	.else
		mov eax, FALSE
		ret
	.endif
	
	mov eax, TRUE
	
	ret
DlgProc endp

GenerateKey proc
	local flag:BYTE
	
	push esi
	push edi
	
	invoke GetWindowText, editInputHandle, offset resultBuffer, 128
	
	.if eax > 10h
		mov eax, 0
		ret
	.endif
	
	mov edx, eax
	
	mov flag, 0
	mov ecx, 10h
	mov esi, offset resultBuffer
	mov edi, offset resultBuffer
	add edi, 10h
	
	.while ecx > 0
		mov al, byte ptr [esi]
		
		.if al <= 0
			mov al, 3Fh
		.endif
		
		mul cl
		
		push edx
		.while edx > 0
			mov bl, byte ptr [esi + edx - 1]
			xor al, bl
			dec edx
		.endw
		pop edx
		
		.if flag < 1
			and al, 0Fh
		.else
			and al, 0F0h
			shr al, 4
		.endif
		
		neg flag
		
		.if al > 9
			add al, 7
		.endif
		
		add al, 30h
		
		mov byte ptr[edi], al
		
		inc edi
		inc esi
		dec ecx
	.endw
	
	pop edi
	pop esi
	
	ret
GenerateKey endp

end start