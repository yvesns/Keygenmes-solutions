.386

.model flat,stdcall
option casemap:none

DlgProc proto :DWORD,:DWORD,:DWORD,:DWORD

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

.const
ID_EDIT_PASSWORD equ 40001

.code
start:
	invoke GetModuleHandle, NULL
	mov hInstance, eax
	
	mov dword ptr [buffer],73384901h
	mov dword ptr [buffer + 4],3134460Bh
	mov word ptr [buffer + 8],0F432h
	
	invoke DialogBoxParam, hInstance, ADDR DlgName, NULL, addr DlgProc, NULL
	invoke ExitProcess, eax
	
DlgProc proc hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
	.if uMsg==WM_INITDIALOG
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
end start
