from scapy.all import *
import time


print("1 send SYN req\n")
SYN = IP(ttl=128, proto="tcp", src = "172.168.40.175",  dst = "41.110.21.252")/TCP(dport=25,seq =100, ack=0, flags = "S")#, options   = [('MSS', 1460), ('NOP', None), ('WScale', 2), ('NOP', None), ('NOP', None), ('SAckOK', b'')])


#1. start syn tcp connection with server and retraive synack response
AckSyn = sr1(SYN)
#time.sleep(0.3)
print("2 receive ACKSYN req",AckSyn)
#2. send ack response and retreive Welcome server response
ACK = IP(ttl=128, proto="tcp", src = "172.168.40.175",  dst = "41.110.21.252")/TCP(dport=25,seq =AckSyn[TCP].ack , ack=AckSyn[TCP].seq +1 , flags = "A")
Welcome = sr1(ACK)
#time.sleep(0.3)
print("3 send ACK and Receive Welcome from Server",Welcome)
#3. send ACK to server

ACKWelcome = IP(ttl=128, proto="tcp", src = "172.168.40.175",  dst = "41.110.21.252")/TCP(dport=25,seq =Welcome[TCP].ack , ack=Welcome[TCP].seq +1 , flags = "A")
send(ACKWelcome)
#time.sleep(0.3)
print("4 send ACK to Welcome\n")

#4 . send EHLO to server
data = "EHLO server\r\n"
sendEhlo = IP(ttl=128, proto="tcp", src = "172.168.40.175",  dst = "41.110.21.252")/TCP(dport=25,seq =Welcome[TCP].ack , ack=Welcome[TCP].seq + len(data), flags = "PA")/Raw(load=data)

Ehlo = sr1(sendEhlo)
time.sleep(0.3)

print("\n5 send Ehlo req", Ehlo)
#5 . ACK Server of EHLO


#6 . Server Response of EHLO
#7 . ACK Client of EHLO response
ACKEhlo = IP(ttl=128, proto="tcp", src = "172.168.40.175",  dst = "41.110.21.252")/TCP(dport=25,seq =Ehlo[TCP].ack , ack=Ehlo[TCP].seq +1 , flags = "A")
AckRespEhlo = send(ACKEhlo)
time.sleep(0.3)
print("\n 6 ACK EHLO")

#8 . send new reqest to server
data = "STARTTLS\r\n"
sendSTARTTLS  = IP(ttl=128, proto="tcp", src = "172.168.40.175",  dst = "41.110.21.252")/TCP(dport=25,seq =Ehlo[TCP].ack , ack=Ehlo[TCP].seq + len(data) , flags = "PA")/Raw(load=data)
print("\n  7 send starttls")

 