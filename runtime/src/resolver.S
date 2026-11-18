.section .tbss,"awT",@nobits
.balign 4
.global artitux_resolver_depth
.hidden artitux_resolver_depth
.type artitux_resolver_depth,@tls_object
.size artitux_resolver_depth,4
artitux_resolver_depth:
    .zero 4
.text
.hidden ARTITUX_RESOLVER_GATEWAY
.hidden ARTITUX_RESOLVER_HOOK_POINTER
.if ARTITUX_RESOLVER_STATS_ENABLED
.hidden ARTITUX_RESOLVER_STATS
.endif
.global artitux_resolver_clear_depth
.hidden artitux_resolver_clear_depth
.type artitux_resolver_clear_depth,@function
artitux_resolver_clear_depth:
    mov rax,qword ptr [rip+artitux_resolver_depth@gottpoff]
    mov dword ptr fs:[rax],0
    ret
.global artitux_resolver_entry
.hidden artitux_resolver_entry
.global artitux_resolver_entry_end
.hidden artitux_resolver_entry_end
.type artitux_resolver_entry,@function
artitux_resolver_entry:
    .cfi_startproc
    push rbp
    .cfi_def_cfa_offset 16
    .cfi_offset rbp,-16
    lea rsp,[rsp-160]
    .cfi_def_cfa_offset 176
    lea rbp,[rsp+160]
    .cfi_def_cfa rbp,16
    mov dword ptr [rsp+96],0
.Lresolver_prologue_end:
    .if (.Lresolver_prologue_end-artitux_resolver_entry) != 25
    .error "resolver Windows unwind prologue changed"
    .endif
    movaps [rsp+32],xmm0
    movaps [rsp+48],xmm1
    movaps [rsp+64],xmm2
    movaps [rsp+80],xmm3
    mov [rsp+104],r10
    mov [rsp+112],r11
    mov [rsp+120],rax
    pushfq
    pop r11
    mov [rsp+128],r11
    # Offsets 0..31 belong to the callee's Windows shadow space.
    mov r10,qword ptr [rip+artitux_resolver_depth@gottpoff]
    cmp dword ptr fs:[r10],0
    jne .Lresolver_nested
    mov dword ptr [rsp+96],1
    mov dword ptr fs:[r10],1
    mov r11,[rip+ARTITUX_RESOLVER_HOOK_POINTER]
    mov r11,[r11]
    mov [rsp+144],r11
.if ARTITUX_RESOLVER_STATS_ENABLED
    lea r10,[rip+ARTITUX_RESOLVER_STATS]
    lock inc qword ptr [r10+8]
.endif
    jmp .Lresolver_invoke
.Lresolver_nested:
    mov r11,[rip+ARTITUX_RESOLVER_GATEWAY]
    mov [rsp+144],r11
.if ARTITUX_RESOLVER_STATS_ENABLED
    lea r10,[rip+ARTITUX_RESOLVER_STATS]
    lock inc qword ptr [r10+16]
.endif
.Lresolver_invoke:
    mov rax,[rsp+120]
    mov r10,[rsp+104]
    mov r11,[rsp+112]
    push qword ptr [rsp+128]
    popfq
    call qword ptr [rsp+144]
    mov [rsp+104],r10
    pushfq
    pop r10
    mov [rsp+136],r10
    cmp dword ptr [rsp+96],0
    je .Lresolver_restore
    mov r10,qword ptr [rip+artitux_resolver_depth@gottpoff]
    sub dword ptr fs:[r10],1
.Lresolver_restore:
    mov r10,[rsp+104]
    push qword ptr [rsp+136]
    popfq
    movaps xmm0,[rsp+32]
    movaps xmm1,[rsp+48]
    movaps xmm2,[rsp+64]
    movaps xmm3,[rsp+80]
    lea rsp,[rbp]
    .cfi_def_cfa rsp,16
    pop rbp
    .cfi_restore rbp
    .cfi_def_cfa rsp,8
    ret
artitux_resolver_entry_end:
    .cfi_endproc
.size artitux_resolver_entry,.-artitux_resolver_entry
.section .note.GNU-stack,"",@progbits
