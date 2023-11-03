import socket

def check_smtp(ip, port):
    try:
        s = socket.create_connection((ip, port), timeout=2)
        initial_response = s.recv(1024)
        if not b"220" in initial_response:
            s.close()
            return False
        
        s.send(b"EHLO test.com\r\n")
        response = s.recv(1024)
        s.close()

        if b"250" in response:
            return True
    except:
        pass

    return False
