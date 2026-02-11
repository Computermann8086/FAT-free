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
;* 

cpu 586
bits 32
org 400000h

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