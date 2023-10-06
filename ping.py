from scapy.all import sr1, send, RandIP
from scapy.layers.inet import Ether, IP, TCP, ICMP
import sys
from scapy.packet import Raw
from random import randbytes, randint

if len(sys.argv) != 3:
    print("Incorrect number of arguments. Please only specify target IP and target port.")
    exit(0)
src_ip = RandIP()
rand_padding = randint(0, 200)
payload = "secret message SSH " + str(rand_padding)

# Random Source IP
# send(
#     IP(dst=sys.argv[1], src=src_ip) / TCP(dport=int(sys.argv[2]), flags="S") / Raw(load=payload)
# )

# Non-Random Source IP
send(
    IP(dst=sys.argv[1]) / TCP(dport=int(sys.argv[2]), flags="S") / Raw(load=payload)
)
print(src_ip)

print(sys.argv)
