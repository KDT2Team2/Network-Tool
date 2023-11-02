import telnetlib

# pip install dnspython
import dns.message
import dns.query
import dns.flags
import dns.rdatatype

# telnet scan : telnetlib.Telnet에서 예외 발생할 경우 telnet 서비스가 없는 것을 판단
def check_telnet(ip,port):
    try:
        tn = telnetlib.Telnet(host=ip,port=port,timeout=2)
        tn.close()
        print("running telnet")
        return True
    except:
        print("error")
        return False
        
# dns scan : dns query를 보냈을 때 시간안에 응답이 돌아오는지로 판단
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
# test code
#check_telnet("189.114.92.121",23) 
#check_dns("8.8.8.8",53)