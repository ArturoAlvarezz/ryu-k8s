import paramiko
import sys

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('192.168.122.100', username='ubuntu', password='ubuntu')
cmd = " ".join(sys.argv[1:])
stdin, stdout, stderr = client.exec_command(f"sudo -S {cmd}")
stdin.write('ubuntu\n')
stdin.flush()
print(stdout.read().decode())
print(stderr.read().decode())
client.close()
