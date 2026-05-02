import paramiko
import sys

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('192.168.122.100', username='ubuntu', password='ubuntu')
stdin, stdout, stderr = client.exec_command(sys.argv[1])
print(stdout.read().decode())
print(stderr.read().decode())
client.close()
