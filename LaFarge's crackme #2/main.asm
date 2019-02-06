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
ResetEncryptionSequence proto
Encryption1 proto :DWORD
Encryption2 proto :DWORD
Encryption3 proto :DWORD
Encryption4 proto :DWORD
Encryption5 proto :DWORD
GenerateFinalCode proto :DWORD, :DWORD

.data
dlgName db "#100",0
format db "%lu",0
username db 512 dup(0)
resultCode DWORD 0
resultBuffer db 512 dup(0)
originalEncryptionSequence db 0AAh, 89h, 0C4h, 0FEh, 46h, 78h, 0F0h, 0D0h, 3h, 0E7h, 0F7h, 0FDh, 0F4h, 0E7h, 0B9h, 0B5h, 1Bh, 0C9h, 50h, 73h, 0
encryptionSequence db 0AAh, 89h, 0C4h, 0FEh, 46h, 78h, 0F0h, 0D0h, 3h, 0E7h, 0F7h, 0FDh, 0F4h, 0E7h, 0B9h, 0B5h, 1Bh, 0C9h, 50h, 73h, 0

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
					invoke SetDlgItemText, hWnd, IDEDITOUTPUT, addr resultBuffer
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
	invoke ResetEncryptionSequence
	
	mov resultCode, 0

	invoke GetWindowText, editInputHandle, offset username, 128
	
	.if eax < 4
		ret
	.endif
	
	invoke Encryption1, offset username
	invoke Encryption2, offset username
	invoke Encryption3, offset username
	invoke Encryption4, offset username
	invoke Encryption5, offset username
	invoke GenerateFinalCode, offset resultCode, offset resultBuffer
	
	invoke ReverseString, offset resultBuffer
	
	ret
GenerateKey endp

ResetEncryptionSequence proc
	mov eax, offset originalEncryptionSequence
	mov ebx, offset encryptionSequence
	
	.while byte ptr [eax] != 0
		mov cl, byte ptr [eax]
		mov byte ptr [ebx], cl
		inc eax
		inc ebx
	.endw
	
	Ret
ResetEncryptionSequence endp

Encryption1 proc string:DWORD
	local usernameIndex:DWORD
	local encryptionIndex:DWORD
	local usernameLength:DWORD
	
	push esi
	push edi
	
	invoke lstrlen, string
	mov usernameLength, eax
	mov eax, 0
	mov usernameIndex, 1
	mov encryptionIndex, 0
	
	mov ebx, usernameIndex
	mov edi, string
	mov esi, offset encryptionSequence
	
	mov cl, byte ptr [edi + ebx]
	
	.while eax < usernameLength
		mov ebx, encryptionIndex
		mov dl, byte ptr [esi + ebx]
		mov byte ptr [esi + ebx], cl
		
		xor cl, dl
		mov ebx, usernameIndex
		mov byte ptr [edi + ebx], cl
		
		inc encryptionIndex
		
		.if encryptionIndex > 4
			mov encryptionIndex, 0
		.endif
		
		inc usernameIndex
		inc ebx
		mov cl, byte ptr [edi + ebx]
		
		inc eax
	.endw
	
	pop edi
	pop esi
	
	Ret
Encryption1 endp

Encryption2 proc string:DWORD
	local encryptionIndex:DWORD
	
	push esi
	push edi
	
	invoke lstrlen, string
	dec eax
	
	mov encryptionIndex, 5
	mov edi, string
	inc edi
	mov esi, offset encryptionSequence
	
	mov cl, byte ptr [edi + eax - 1]
	
	.while eax > 0
		mov ebx, encryptionIndex
		mov dl, byte ptr [esi + ebx]
		dec ebx
		mov byte ptr [esi + ebx], cl
		
		xor cl, dl
		mov byte ptr [edi + eax - 1], cl
		
		inc encryptionIndex
		
		.if encryptionIndex > 9
			mov encryptionIndex, 5
		.endif
		
		dec eax
		
		mov cl, byte ptr [edi + eax - 1]
	.endw
	
	pop edi
	pop esi
	
	Ret
Encryption2 endp

Encryption3 proc string:DWORD
	local usernameMaxIndex:DWORD
	local encryptionIndex:DWORD
	
	push esi
	push edi
	
	invoke lstrlen, string
	mov usernameMaxIndex, eax
	mov eax, 1
	
	mov encryptionIndex, 10
	mov edi, string
	mov esi, offset encryptionSequence
	
	mov cl, byte ptr [edi + eax]
	
	.while eax < usernameMaxIndex
		mov ebx, encryptionIndex
		mov dl, byte ptr [esi + ebx]
		dec ebx
		mov byte ptr [esi + ebx], cl
		
		xor cl, dl
		mov byte ptr [edi + eax], cl
		
		inc encryptionIndex
		
		.if encryptionIndex > 14
			mov encryptionIndex, 10
		.endif
		
		inc eax
		
		mov cl, byte ptr [edi + eax]
	.endw
	
	pop edi
	pop esi
	
	Ret
Encryption3 endp

Encryption4 proc string:DWORD
	local encryptionIndex:DWORD
	
	push esi
	push edi
	
	invoke lstrlen, string
	dec eax
	
	mov ebx, 15
	mov encryptionIndex, ebx
	mov edi, string
	inc edi
	mov esi, offset encryptionSequence
	
	mov cl, byte ptr [edi + eax - 1]
	
	.while eax > 0
		mov ebx, encryptionIndex
		mov dl, byte ptr [esi + ebx]
		dec ebx
		mov byte ptr [esi + ebx], cl
		
		xor cl, dl
		mov byte ptr [edi + eax - 1], cl
		
		inc encryptionIndex
		
		mov ebx, 19
		
		.if encryptionIndex > ebx
			mov ebx, 15
			mov encryptionIndex, ebx
		.endif
		
		dec eax
		
		mov cl, byte ptr [edi + eax - 1]
	.endw
	
	pop edi
	pop esi
	
	Ret
Encryption4 endp

Encryption5 proc string:DWORD
	local usernameIndex:DWORD
	
	push esi
	push edi
	
	mov usernameIndex, 1
	mov esi, string
	
	invoke lstrlen, string
	mov edx, eax
	
	mov edi, offset resultCode
	
	.while usernameIndex < edx
		mov eax, usernameIndex
		dec eax
		and eax, 3
		mov bl, byte ptr [edi + eax]
		
		push eax
		
		mov eax, usernameIndex
		mov cl, byte ptr [esi + eax]
		add bl, cl
		
		pop eax
		mov byte ptr [edi + eax], bl
		
		inc usernameIndex
	.endw
	
	pop edi
	pop esi
	
	Ret
Encryption5 endp

GenerateFinalCode proc baseCode:DWORD, buffer:DWORD
	mov ebx, dword ptr [baseCode]
	mov eax, dword ptr [ebx]
	mov ecx, 0Ah
	mov ebx, buffer
	
	.while eax > 0
		xor edx, edx
		div ecx
		add dl, 30h
		mov byte ptr [ebx], dl
		inc ebx
	.endw
	
	mov byte ptr[ebx], 0
	
	Ret
GenerateFinalCode endp

end start