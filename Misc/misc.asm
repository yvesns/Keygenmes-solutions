.386

.model flat,stdcall
option casemap:none

include windows.inc
include kernel32.inc
include user32.inc
includelib kernel32.lib
includelib user32.lib

ClipString proto :DWORD, :DWORD, :DWORD, :DWORD
AsciiDecimalToHex proto :DWORD
HexToAsciiDecimal proto :DWORD, :DWORD
Pow proto :DWORD, :DWORD
ConcatStrings proto :DWORD, :DWORD
ReverseString proto :DWORD

.data

.data?

.code
DLLEntry proc hInstDLL:HINSTANCE, reason:DWORD, reserved1:DWORD
	mov eax, TRUE
	Ret
DLLEntry endp

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
	
	invoke lstrlen, string
	mov stringLength, eax
	
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
	invoke lstrlen, string1
	mov ecx, string1
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

ReverseString proc string:DWORD
	invoke lstrlen, string
	
	.if eax < 2
		ret
	.endif
	
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

end DLLEntry