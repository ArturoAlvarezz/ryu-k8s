import paramiko
import sys

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('192.168.122.100', username='ubuntu', password='ubuntu')

cmd = " ".join(sys.argv[1:])
# Escapar comillas simples para pasarlo a bash -c
cmd_escaped = cmd.replace("'", "'\\''")

stdin, stdout, stderr = client.exec_command(f"sudo -S bash -c '{cmd_escaped}'")
stdin.write('ubuntu\n')
stdin.flush()

print(stdout.read().decode(errors='replace'))
err = stderr.read().decode(errors='replace')
if err and 'sudo' not in err.lower() and 'password' not in err.lower():
    print(err)

# Cerrar explicitamente los canales para evitar Exception ignored in __del__
stdin.close()
stdout.close()
stderr.close()
client.close()
