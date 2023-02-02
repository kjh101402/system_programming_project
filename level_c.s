.text
_start: .global _start
adr r0, msg0
ldr r1, =msg1
ldr r2, msg2
@ ldr r3, msg3
ldr r4, =msg3
ldr r3, [r4]
ldr r5, =100
ldr r5, =123456
ldmia r1, {r2-r4, pc}
stmib r1, {r3-r7} 
push {r2-r4, pc}
pop {r2-r4, pc}

msg0:
    .word 1234
msg1:
    .word 5678
msg2:
    .word 7890

.data
msg3:
    .word 3456