import socket

def check_ssh(ip, port):
    try:
        s = socket.create_connection((ip, port), timeout=2)
        response = s.recv(1024)
        s.close()

        if response.startswith(b"SSH-"):
            return True
    except:
        pass

    return False
