import paramiko
import time

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.46.131', username='osboxes', password='osboxes.org')

c_code = """#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

int main() {
    printf("[clean_jit] Starting Clean JIT Workload PID: %d\\n", getpid());
    fflush(stdout);
    size_t size = 1024 * 1024; // 1 MB anonymous RWX memory
    void *jit_mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (jit_mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    // x86_64 machine code: NOP sled + RET (0xc3)
    unsigned char code[] = { 0x90, 0x90, 0x90, 0x90, 0xc3 };
    memcpy(jit_mem, code, sizeof(code));
    void (*jit_func)() = (void (*)())jit_mem;
    jit_func();
    printf("[clean_jit] Anonymous executable memory mapped at %p (%zu bytes)\\n", jit_mem, size);
    fflush(stdout);
    while (1) {
        jit_func();
        sleep(1);
    }
    return 0;
}
"""

sftp = ssh.open_sftp()
with sftp.file('/home/osboxes/clean_jit.c', 'w') as f:
    f.write(c_code)
sftp.close()

print("1. clean_jit.c written to VM.")

# Compile clean_jit.c
stdin, stdout, stderr = ssh.exec_command('gcc -O2 -o /home/osboxes/clean_jit /home/osboxes/clean_jit.c')
rc = stdout.channel.recv_exit_status()
print("2. Compilation exit code:", rc)
if rc != 0:
    print("Compilation error:", stderr.read().decode())
    exit(1)

# Kill any existing clean_jit
ssh.exec_command('killall clean_jit 2>/dev/null || true')
time.sleep(0.5)

# Launch clean_jit
stdin, stdout, stderr = ssh.exec_command('nohup /home/osboxes/clean_jit > /home/osboxes/clean_jit.log 2>&1 & echo $!')
jit_pid = stdout.read().decode().strip().splitlines()[-1]
print("3. Launched clean_jit with PID:", jit_pid)
time.sleep(1)

# Check log and maps
stdin, stdout, stderr = ssh.exec_command(f'cat /home/osboxes/clean_jit.log; ps aux | grep clean_jit | grep -v grep; grep -E "rwxp|r-xp" /proc/{jit_pid}/maps')
print("4. Process info & memory maps:\n", stdout.read().decode())

# Check /mnt/hgfs/KaliShared
stdin, stdout, stderr = ssh.exec_command('ls -la /mnt/hgfs/KaliShared 2>&1')
print("5. Shared folder status:\n", stdout.read().decode())

ssh.close()
