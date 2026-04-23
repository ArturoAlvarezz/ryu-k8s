import paramiko

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('192.168.122.100', username='ubuntu', password='ubuntu', timeout=15)

commands = [
    "echo ubuntu | sudo -S mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d",
    "echo ubuntu | sudo -S bash -c \"printf '[Service]\\nExecStart=\\nExecStart=/lib/systemd/systemd-networkd-wait-online --any --timeout=30\\n' > /etc/systemd/system/systemd-networkd-wait-online.service.d/override.conf\"",
    "echo ubuntu | sudo -S systemctl daemon-reload",
    "echo ubuntu | sudo -S systemctl reset-failed systemd-networkd-wait-online.service",
    "echo ubuntu | sudo -S systemctl restart k3s.service",
    "sleep 4",
    "echo ubuntu | sudo -S systemctl is-active k3s.service",
    "echo ubuntu | sudo -S kubectl get nodes",
]

for cmd in commands:
    stdin, stdout, stderr = client.exec_command(cmd, timeout=20)
    out = stdout.read().decode(errors='replace').strip()
    err = stderr.read().decode(errors='replace').strip()
    if out:
        print(f">> {out}")
    if err and 'sudo' not in err and 'password' not in err.lower():
        print(f"   ERR: {err}")

client.close()
print("Done")
