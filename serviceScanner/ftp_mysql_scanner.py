from pyfiglet import Figlet
from datetime import datetime
from scapy.all import *
from ftplib import FTP
import mysql.connector
import socket

conf.use_pcap = True


def load_start_ascii():
    print("-" * 50)
    f = Figlet(font = 'doom')
    print(f.renderText('PORT SCANNER'))
    print("-" * 50)
    
def port_check():
    host = input("Scanner Target IP : ")
    p = list(input("Scanner  Target Port(ex. 1 - 65535): ").split("-"))
    
    ports = range(int(p[0]), int(p[1]))
    
    print(f"Scanner start time : {str(datetime.now())}")
    print("-" * 50)
    
    pkt = IP(dst=host)/TCP(dport=ports,flags="S")                       
    ans, unans = sr(pkt,verbose=0,timeout=2)
    alive_ports = []
    for (s,r) in ans:
        if(r[TCP].flags == "SA"):
           print(f"[+] {s[TCP].dport} Open")
           alive_ports.append(s[TCP].dport)
    return host, alive_ports

def ftp_check(ip, port):
    if port == 21:
        try:
            with FTP() as ftp:
                ftp.connect(host=ip, port=port, timeout=10)
                welcome_message = ftp.getwelcome()
                print(welcome_message)
                
                #정상적인 접속이 될 경우 welcom messaage에 220 ProFTP  ~ 버전 출력됨 
                if '220' in welcome_message:
                    return  True
        except Exception as e:
            print(f"[-] FTP 서비스 연결 중 에러 발생: {e}")
            return False
    else:
        print("[+] Port is not FTP Port")
        return False

def mysql_check(ip, port):
    connection = None
    if port == 3306:
        try:
            connection = mysql.connector.connect(
                host=ip,
                port=port,
                connection_timeout=1000
            )
            if connection.is_connected():
                return True
        except Exception as e:
            print(f"[-] MySQL 서비스 연결 중 에러 발생: {e}")
            return False
        finally:
            if connection is not None and connection.is_connected():
                connection.close()
    else:
        print("[+] Port is not MySQL Port")
        return False



def main_start():
    load_start_ascii()
    host, port_list = port_check()
    for i in port_list:
        if i == 21:
            ftp_flag = ftp_check(host, i)
        elif i == 3306:
            mysql_flag = mysql_check(host, i)
    
if __name__ == "__main__":
    # load_start_ascii()
    # host, port_list = port_check()
    print(mysql_check("210.246.245.200", 3306))
