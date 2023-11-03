import paramiko

def check_ssh(ip, port):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, port=port, timeout=2)
        ssh.close()
        return True
    except:
        return False