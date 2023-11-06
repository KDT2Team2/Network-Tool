import socket
from scapy.all import *
from pyfiglet import Figlet
from datetime import datetime
from ftplib import FTP
import telnetlib
import dns.message
import dns.query
import dns.flags
import dns.rdatatype
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import as_completed
from mysql.connector import errorcode
import os
import mysql.connector

# show ascii art
def load_start_ascii():
    print("-" * 50)
    f = Figlet(font = 'doom')
    print(f.renderText('SERVICE PORT SCANNER'))
    print("-" * 50)

def port_scan(host,ports):
    pkt = IP(dst=host)/TCP(dport=ports,flags="S")                       
    ans, unans = sr(pkt,verbose=0,timeout=10)
    alive_ports = []
    for (s,r) in ans:
        if(r[TCP].flags == "SA"):
           print(f"[+] {s[TCP].dport} Open")
           alive_ports.append(s[TCP].dport)
    return alive_ports
    
# port scan
def port_check():
    host = input("Scanner Target IP : ")
    p = list(input("Scanner  Target Port(ex. 1 - 65535): ").split("-"))
    worker_num = os.cpu_count()

    ports = range(int(p[0]), int(p[1]))
    n = int(len(ports) / 40)
    ports = [ports[i:i+n] for i in range(0,len(ports),n)]

    start_time = datetime.now()
    # alive_ports = port_scan(host,ports)
    print(f"Scanner start time : {str(datetime.now())}")
    print("-" * 50)
    alive_ports = []
    with ProcessPoolExecutor(max_workers=worker_num) as executer:
        futures = [executer.submit(port_scan,host,ports[i]) for i in range(40)]
        for future in as_completed(futures):
            alive_ports+=future.result()
    end_time = datetime.now()
    print(f"Took {end_time-start_time} seconds")
    return host, alive_ports

# smtp scan
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

# ssh scan
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
    
# ftp scan
def check_ftp(ip, port):
    try:
        with FTP() as ftp:
            ftp.connect(host=ip, port=port, timeout=10)
            welcome_message = ftp.getwelcome()
            print(welcome_message)
                
            #정상적인 접속이 될 경우 welcom messaage에 220 ProFTP  ~ 버전 출력됨 
            if '220' in welcome_message:
                ftp_flag = True
    except Exception as e:
        print(f"[-] FTP 서비스 연결 중 에러 발생: {e}")
        ftp_flag = False
    return ftp_flag

# http scan
def check_http(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect((ip, port))

    http_request = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(ip)
    s.sendall(http_request.encode())

    response = s.recv(4096).decode('utf-8')

    if "HTTP/1." in response:
        return True
    else:
        return False

# dhcp scan
def check_dhcp(ip, port, iface="eth0"):
    dhcp_discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst=ip) /
        UDP(sport=68, dport=port) /
        BOOTP(chaddr=b"\x00\x01\x02\x03\x04\x05") /
        DHCP(options=[("message-type", "discover"), "end"])
    )

    response = srp1(dhcp_discover, timeout=2, verbose=0, iface=iface)

    if response and DHCP in response and response[DHCP].options[0][1] == 2:
        return True
    return False

# telnet scan
def check_telnet(ip,port):
    try:
        tn = telnetlib.Telnet(host=ip,port=port,timeout=2)
        tn.close()
        return True
    except:
        return False       

# dns scan
def check_dns(ip,port):
    query = dns.message.make_query("google.com",dns.rdatatype.A)
    query.flags += dns.flags.RD
    try:
        res = dns.query.tcp(q=query,where=ip,port=port,timeout=1)
        if res:
            return True
        else:
            return False
    except:
        return False

# sql scan
def check_sql(ip, port):
    try:
        connection = mysql.connector.connect(
            host=ip,
            port=port,
            connection_timeout=10
        )
        if connection.is_connected():
            connection.close()
            return True
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print(f"[-] My SQL 접근권한이 없음")
            return True
        
        # 
    except Error as e:
        print(f"[-] My SQL 서비스 연결 중 에러 발생: {e}")
        return False

def service_scan(ip,port):
    scanner_function_map ={
        'http':check_http,
        'ftp':check_ftp,
        'dns':check_dns,
        'sql':check_sql,
        'ssh':check_ssh,
        'smtp':check_smtp,
        'dhcp':check_dhcp,
        'telnet':check_telnet
    }
    priority_protocol = 'http' # -> 교체예정
    if scanner_function_map[priority_protocol](ip,port):
        print(f"[+] {port}:{priority_protocol}")
        return
    for k,v in scanner_function_map.items():
        if k == priority_protocol:
            continue
        if v(ip,port):
            print(f"[+] {port}:{k}")
            return
    print(f"[-] {port}:unknown")

if __name__ == "__main__":
    load_start_ascii()
    host, alive_ports = port_check()

    for port in alive_ports:
       service_scan(host,port)
