import paramiko
import time
import os
import shutil

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.46.131', username='osboxes', password='osboxes.org')

print("1. Creating dumps directory on VM if not exists...")
ssh.exec_command('mkdir -p /home/osboxes/dumps')

print("2. Removing old dump if present...")
ssh.exec_command('rm -f /home/osboxes/dumps/clean_jit.lime')
ssh.exec_command('echo osboxes.org | sudo -S rmmod lime 2>/dev/null || true')
time.sleep(1)

print("3. Capturing physical memory snapshot via LiME...")
start_time = time.time()
cmd = 'echo osboxes.org | sudo -S insmod /home/osboxes/tools/LiME/src/lime-6.12.25-amd64.ko path=/home/osboxes/dumps/clean_jit.lime format=lime dio=0'
stdin, stdout, stderr = ssh.exec_command(cmd)
rc = stdout.channel.recv_exit_status()
elapsed = time.time() - start_time
print(f"   insmod LiME completed in {elapsed:.2f}s with rc={rc}")

print("4. Unloading LiME module...")
stdin, stdout, stderr = ssh.exec_command('echo osboxes.org | sudo -S rmmod lime')
stdout.channel.recv_exit_status()

print("5. Verifying dump size on VM...")
stdin, stdout, stderr = ssh.exec_command('ls -lh /home/osboxes/dumps/clean_jit.lime; ls -l /home/osboxes/dumps/clean_jit.lime')
dump_info = stdout.read().decode().strip()
print("   Dump info:\n", dump_info)

print("6. Copying dump to VMware Shared Folder /mnt/hgfs/KaliShared/clean_jit.lime...")
start_cp = time.time()
stdin, stdout, stderr = ssh.exec_command('cp /home/osboxes/dumps/clean_jit.lime /mnt/hgfs/KaliShared/clean_jit.lime')
rc_cp = stdout.channel.recv_exit_status()
elapsed_cp = time.time() - start_cp
print(f"   Copy to shared folder completed in {elapsed_cp:.2f}s with rc={rc_cp}")

ssh.close()

# Verify on host at C:\SIT\KaliShared\clean_jit.lime
shared_path = r'C:\SIT\KaliShared\clean_jit.lime'
target_path = r'baseline\images\clean_jit.lime'

if os.path.exists(shared_path):
    size = os.path.getsize(shared_path)
    print(f"7. Host shared file found: {shared_path} ({size} bytes)")
    os.makedirs('baseline/images', exist_ok=True)
    print(f"   Copying to {target_path}...")
    shutil.copyfile(shared_path, target_path)
    final_size = os.path.getsize(target_path)
    print(f"   Copied successfully to {target_path} ({final_size} bytes)")
else:
    print(f"ERROR: Shared path {shared_path} not found!")

print("LiME acquisition and transfer complete!")
