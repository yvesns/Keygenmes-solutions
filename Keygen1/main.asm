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
GenerateKeyPart1 proto :DWORD, :DWORD
GenerateKeyPart2 proto :DWORD, :DWORD, :DWORD
GenerateKeyPart3 proto :DWORD, :DWORD
GenerateNameCode proto :DWORD, :DWORD
GenerateNameCode2 proto :DWORD, :DWORD

.data
dlgName db "#100",0
format db "%lu",0
resultBuffer db 512 dup(0)
fixedKeyPart1 db "???000000",0
fixedKeyPart2 db "00000?",0
dwFlags DWORD HEAP_ZERO_MEMORY

.data?
hInstance HINSTANCE ?
editInputHandle dd ?
editOutputHandle dd ?
hHeap DWORD ?

.const
IDGENERATE equ 40000
IDEDITINPUT equ 40001
IDEDITOUTPUT equ 40002

.code
start:
	invoke GetModuleHandle, NULL
	mov hInstance, eax
	
	invoke GetProcessHeap
	mov hHeap, eax
	
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
	local username:DWORD
	local nameCode:DWORD
	local nameCode2:DWORD
	local keyPart1:DWORD
	local keyPart2:DWORD
	local keyPart3:DWORD
	
	invoke HeapAlloc, hHeap, dwFlags, 128
	mov username, eax
	
	invoke HeapAlloc, hHeap, dwFlags, 512
	mov nameCode, eax
	
	invoke HeapAlloc, hHeap, dwFlags, 512
	mov nameCode2, eax
	
	invoke HeapAlloc, hHeap, dwFlags, 512
	mov keyPart1, eax
	
	invoke HeapAlloc, hHeap, dwFlags, 512
	mov keyPart2, eax
	
	invoke HeapAlloc, hHeap, dwFlags, 512
	mov keyPart3, eax
	
	invoke GetWindowText, editInputHandle, username, 128
	
	invoke lstrlen, username
	
	.if eax == 0
		ret
	.endif
	
	invoke GenerateNameCode, username, nameCode
	invoke GenerateNameCode2, nameCode, nameCode2
	invoke GenerateKeyPart1, nameCode2, keyPart1
	invoke GenerateKeyPart3, nameCode2, keyPart3
	invoke GenerateKeyPart2, keyPart3, keyPart1, keyPart2
	
	mov eax, offset resultBuffer
	mov byte ptr[eax], 0
	
	invoke ConcatStrings, offset resultBuffer, offset fixedKeyPart1
	invoke ConcatStrings, offset resultBuffer, keyPart1
	invoke ConcatStrings, offset resultBuffer, keyPart2
	invoke ConcatStrings, offset resultBuffer, offset fixedKeyPart2
	invoke ConcatStrings, offset resultBuffer, keyPart3
	
	Ret
GenerateKey endp

GenerateKeyPart1 proc nameCode:DWORD, outputString:DWORD
	local result:DWORD
	push esi
	push edi
	
	mov result, 0
	mov esi, nameCode
	mov edi, 0
	
	.while byte ptr[esi + edi] != 0
		mov eax, edi
		inc eax
		mov ecx, 0Ah
	
		.if eax > 9
			cdq
			div ecx
			mov eax, edx
		.endif
		
		movzx ecx, byte ptr [esi + edi]
		mul ecx
		
		add result, eax
		
		inc edi
	.endw
	
	invoke HexToAsciiDecimal, result, outputString
	
	pop edi
	pop esi
	
	ret
GenerateKeyPart1 endp

GenerateKeyPart2 proc keyPart1:DWORD, keyPart2:DWORD, outputString:DWORD
	xor eax, eax
	
	mov ecx, offset fixedKeyPart1
	
	.while byte ptr [ecx] != 0
		movzx ebx, byte ptr [ecx]
		add eax, ebx
		inc ecx
	.endw
	
	mov ecx, keyPart1
	
	.while byte ptr [ecx] != 0
		movzx ebx, byte ptr [ecx]
		add eax, ebx
		inc ecx
	.endw
	
	mov ecx, offset fixedKeyPart2
	
	.while byte ptr [ecx] != 0
		movzx ebx, byte ptr [ecx]
		add eax, ebx
		inc ecx
	.endw
	
	mov ecx, keyPart2
	
	.while byte ptr [ecx] != 0
		movzx ebx, byte ptr [ecx]
		add eax, ebx
		inc ecx
	.endw
	
	invoke HexToAsciiDecimal, eax, outputString
	invoke ReverseString, outputString
	
	ret
GenerateKeyPart2 endp

GenerateKeyPart3 proc nameCode:DWORD, outputString:DWORD
	mov ecx, 0
	mov ebx, nameCode
	mov edx, outputString
	
	.while ecx <= 2
		movzx eax, byte ptr [ebx + ecx]
		mov byte ptr [edx], al
		inc ecx
		inc edx
	.endw
	
	push ebx
	push edx
	
	invoke lstrlen, nameCode
	mov ecx, eax
	sub ecx, 2
	
	pop edx
	pop ebx
	
	.while byte ptr [ebx + ecx] != 0
		movzx eax, byte ptr [ebx + ecx]
		mov byte ptr [edx], al
		inc ecx
		inc edx
	.endw
	
	ret
GenerateKeyPart3 endp

GenerateNameCode proc username:DWORD, outputString:DWORD
	local charCodeAsString:DWORD
	push esi
	
	invoke HeapAlloc, hHeap, dwFlags, 4
	mov charCodeAsString, eax
	
	mov ebx, outputString
	mov esi, username
	mov edi, 0
	
	.while byte ptr [esi] != 0
		movzx eax, byte ptr [esi]
		push ebx
		invoke HexToAsciiDecimal, eax, charCodeAsString
		invoke lstrlen, charCodeAsString
		mov ecx, 3
		sub ecx, eax
		mov eax, 31h
		pop ebx
		
		.while ecx > 0
			mov byte ptr[ebx], al
			inc ebx
			dec ecx
		.endw
		
		mov ecx, charCodeAsString
		
		.while byte ptr [ecx] != 0
			movzx eax, byte ptr [ecx]
			
			.if eax == 39h
				mov eax, 30h
			.else
				inc eax
			.endif
			
			mov byte ptr [ebx], al
			inc ebx
			inc ecx
		.endw
		
		inc esi
	.endw
	
	invoke ReverseString, outputString
	
	pop esi
	
	ret
GenerateNameCode endp

GenerateNameCode2 proc nameCode:DWORD, outputString:DWORD
	local subString:DWORD
	local subStringAsHex:DWORD
	local resultIndex:DWORD
	push esi
	push edi
	
	mov resultIndex, 0
	
	invoke HeapAlloc, hHeap, dwFlags, 256
	mov subString, eax
	
	mov esi, nameCode
	mov edi, 0
	
	.while byte ptr [esi + edi] != 0
		invoke ClipString, esi, edi, 3, subString
		invoke AsciiDecimalToHex, subString
		mov subStringAsHex, eax
		
		mov eax, edi
		inc eax
		mov ecx, 0Ah

		.if eax > 9
			cdq
			div ecx
			mov eax, edx
		.endif
		
		cdq
		mov ecx, subStringAsHex
		mul ecx
		
		invoke HexToAsciiDecimal, eax, subString
		mov eax, subString
		mov byte ptr [eax + 3], 0
		invoke AsciiDecimalToHex, subString
		
		mov ecx, 27h
		cdq
		div ecx
		
		add eax, 41h
		
		mov ebx, outputString
		mov edx, resultIndex
		mov byte ptr [ebx + edx], al
		inc resultIndex
		
		add edi, 3
	.endw
	
	pop edi
	pop esi
	
	ret
GenerateNameCode2 endp

ClipString proc string:DWORD, index:DWORD, charCount:DWORD, outputString:DWORD
	mov ecx, index
	
	.while charCount > 0
		dec charCount
		mov edx, charCount
		add edx, ecx
		
		mov ebx, string
		mov al, byte ptr [ebx + edx]
		
		sub edx, ecx
		mov ebx, outputString
		mov byte ptr [ebx + edx], al
	.endw
	
	ret
ClipString endp

HexToAsciiDecimal proc number:DWORD, outputString:DWORD
	mov eax, number
	mov ecx, 0Ah
	push esi
	
	mov esi, outputString
	
	.if eax == 0
		mov byte ptr [esi], 30h
		inc esi
	.endif
	
	.while eax > 0
		cdq
		div ecx
		add edx, 30h
		mov byte ptr [esi], dl
		inc esi
	.endw
	
	mov byte ptr [esi], 0
	
	invoke ReverseString, outputString
	
	pop esi
	
	ret
HexToAsciiDecimal endp

AsciiDecimalToHex proc string:DWORD
	local stringLength:DWORD
	local index:DWORD
	local result:DWORD
	mov stringLength, 0
	mov index, 0
	mov result, 0
	push esi
	
	mov ebx, string
	mov ecx, 0
	
	.while byte ptr [ebx + ecx] != 0
		inc stringLength
		inc ecx
	.endw
	
	mov esi, 0
	
	.while stringLength > 0
		dec stringLength
		
		invoke Pow, 0Ah, stringLength
		
		movzx ecx, byte ptr [ebx + esi]
		sub ecx, 30h
		mul ecx
		add result, eax
		
		inc esi
	.endw
	
	pop esi
	mov eax, result
	
	ret
AsciiDecimalToHex endp

Pow proc number:DWORD, exponent:DWORD
	mov eax, 1
	mov ecx, number
	
	.while exponent > 0
		dec exponent
		mul ecx
	.endw
	
	ret
Pow endp

ConcatStrings proc string1:DWORD, string2:DWORD
	mov ecx, string1
	invoke lstrlen, string1
	add ecx, eax
	
	mov ebx, string2
	
	.while byte ptr [ebx] != 0
		mov dl, byte ptr [ebx]
		mov byte ptr[ecx], dl
		inc ecx
		inc ebx
	.endw
	
	mov byte ptr[ecx], 0
	
	ret
ConcatStrings endp

GetStringLength proc string:DWORD
	mov ebx, string
	mov eax, 0
	
	.while byte ptr [ebx] != 0
		inc ebx
		inc eax
	.endw
	
	ret
GetStringLength endp

ReverseString proc string:DWORD
	invoke lstrlen, string
	dec eax
	push edi
	xor ebx, ebx
	xor ecx, ecx
	xor edx, edx
	xor edi, edi
	mov edi, dword ptr [string]
	
	.while ebx < eax
		mov dl, byte ptr [edi + ebx]
		mov cl, byte ptr [edi + eax]
		mov byte ptr [edi + ebx], cl
		mov byte ptr [edi + eax], dl
		
		inc ebx
		dec eax
	.endw
	
	pop edi
	
	ret
ReverseString endp
end start