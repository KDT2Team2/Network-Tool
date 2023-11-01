import socket
from scapy.all import *

try:
    host = input("Enter a host address: ") 
    p = list(input("Enter range of the ports to scan: ").split("-"))
    
    ports = range(int(p[0]),int(p[1]))
    
    print("Scanning...\n")
    print("host: ",host)
    print("Ports: ",ports)

    #port scan
    pkt = IP(dst=host)/TCP(dport=ports,flags="S")
    ans, unans = sr(pkt,verbose=0,timeout=2)
    alive_ports = []
    for (s,r) in ans:
       if(r[TCP].flags == "SA"):
          print("[+] {} Open".format(s[TCP].dport))
          alive_ports.append(s[TCP].dport)
    
    #service scan
    http_request = b'GET / HTTP/1.1\r\nHost: ' + bytes(host,'utf-8') +b'\r\n\r\n' #
    for port in alive_ports:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((host,port))
        sock.sendall(http_request)
        print("========================================")
        try:
            res = sock.recv(1024)
            print(f"port:{port}, {res}")
        except socket.timeout:
            print(f"{port} [-] time out")
        except socket.error as e:
            print(f"port:{port}, {e}")
        finally:
            sock.close()
except:
    print("port scan error")

