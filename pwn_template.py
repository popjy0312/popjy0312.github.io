from pwn import *


binary = 'prob'
image = 'ultrac'
container = 'ultrac'

e = ELF(binary)
# libc = './libc.so.6'
# l = ELF(libc)

context.binary = e
context.log_level = 'debug'
# context.log_level = 'info'
context.terminal = ['tmux', 'splitw', '-h']
context.aslr = False

HOST, PORT = '127.0.0.1 12999'.split()
GDBSCRIPT = '\n'.join([
    # f'b *$_base("{binary}")+0x1030' # pie breakpoint sample
])

if args.REMOTE:
    p = remote('host3.dreamhack.games', 8267)
elif args.SET:
    LPORT=8080
    run_cmd = ("docker run "
               "--cap-add=SYS_PTRACE " 
               "--security-opt "
               "seccomp=unconfined "
               "--privileged "
               "-d "
               f"-p {PORT}:{LPORT} --name {container} {image}")
    info(run_cmd)
    subprocess.run(run_cmd.split(), shell=False)
    exit(0)
elif args.GDB:
    p = remote(HOST, PORT)
    pid = int(subprocess.check_output(
            f"docker top {container} -eo pid,comm | tail -n 1 | awk '{{print $1}}'", 
            shell=True
        ).decode().strip().split()[-1])
    rootfs = f"/proc/{pid}/root"
    GDBSCRIPT += f'''
        set sysroot {rootfs}
        set solib-search-path {rootfs}/lib:{rootfs}/usr/lib
    '''
    gdb.attach(pid, gdbscript=GDBSCRIPT, exe=binary)
    pause()
else:
    p = remote(HOST, PORT)

pause()

p.interactive()