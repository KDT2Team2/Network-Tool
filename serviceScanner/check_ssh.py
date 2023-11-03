import socket

def check_ssh(ip, port):
    try:
        s = socket.create_connection((ip, port), timeout=2)
        response = s.recv(1024)
        s.close()

        # SSH는 초기 응답으로 "SSH-"로 시작하는 문자열을 전송합니다.
        if response.startswith(b"SSH-"):
            return True
    except:
        pass

    return False
