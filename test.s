.text
test:
mov r1, r2
mov r2, #2
bx lr

_start:
mov r2, #100
bl test
mov r1, #1
mov r7, #7
swi 0