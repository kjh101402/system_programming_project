.text
_start:
bl print
ldr r0, [r1]
str r1, [r1]
ldr r0, [r1, #12]!
str r1, [r2], r3

print:
mov r0, #1
adr r1, msg
mov r2, #14
mov r7, #4
swi 0
bx lr

msg:
    .asciz "Hello, World!\n"