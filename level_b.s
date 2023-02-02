movlts r1, #10
adds r1, #3
subne r2, r3, #2
addgt r1, r2, r3, LSL #2
add r1, r2, r3, ASR r4
swi 0
mulle r1, r2, r3
umull r1, r2, r3, r4