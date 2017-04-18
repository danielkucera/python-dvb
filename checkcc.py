#!/usr/bin/env python

import socket
import binascii
import sys
import time
import datetime

counter = {}

def main():
#  MCAST_GRP = '239.114.221.33' 
#  MCAST_PORT = 1234
  oldpacket = ""

  MCAST_GRP = sys.argv[1]
  MCAST_PORT = int(sys.argv[2])

  if MCAST_PORT > 0:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  else:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
  try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  except AttributeError:
     pass
  sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32) 
  sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

  if MCAST_PORT > 0:
    sock.bind((MCAST_GRP, MCAST_PORT))
  host = socket.gethostbyname('0.0.0.0')
  sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(host))
  sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, 
                  socket.inet_aton(MCAST_GRP) + socket.inet_aton(host))

  sock.setblocking(0)
  sock.settimeout(0.01)

  pktCnt = 0
  scrambledCnt = 0
  CCerrors = 0
  haveStream = False
  lastTime = 0
  addr = ""

  while 1:
    try:
      data, rcvAddr = sock.recvfrom(1316)
      if MCAST_PORT == 0:
        sport = 256 * ord(data[20]) + ord(data[21])
        dport = 256 * ord(data[22]) + ord(data[23])
        data = data[28:]
#      print data.encode("hex")
      if addr == "":
	addr = rcvAddr
      if addr != rcvAddr:
	continue
      if lastTime + 1 < time.time():
	if pktCnt > 0:
		if not haveStream:
			haveStream = True
			print "\nHAVE STREAM!"
	else:
		if haveStream:
			haveStream = False
			print "\nLOST STREAM!"
		
	print datetime.datetime.now(),
  	print int((round(float(scrambledCnt)/(pktCnt + 1)*100))), "%crypt",
  	print (pktCnt*188*8)/1024, "Kbps",
  	scrambledCnt = 0
  	pktCnt = 0
  	print CCerrors, "CCerr",
  	print addr,
	if MCAST_PORT == 0:
  	  print "SP:", sport,
  	  print "DP:", dport,
#  	print "PIDs:",counter.keys(),
  	sys.stdout.flush()
  	print "\r",
  	lastTime = time.time()
  
    except socket.error, e:
      pass
      continue

    while len(data) > 0:
    	pktCnt += 1
	packet = data[:188]
	data = data[188:]
	PID = ord(packet[2]) + (ord(packet[1]) % 32) * 256
	CC = ord(packet[3]) % 16
	hasPayload = (ord(packet[3]) & 16) != 0
	scrambled = (ord(packet[3]) & 0xc0) !=0

	if scrambled:
		scrambledCnt += 1

	#print MCAST_GRP, CC

	if packet == oldpacket:
		#sys.stdout.write('D')
#		print "DUP!"
		a=0

	if (PID in counter) and (counter[PID] + 1 != CC) and (CC != 0) and hasPayload:
	    print datetime.datetime.now(),"ccerror", MCAST_GRP, PID, "expected", counter[PID] + 1, "got", CC
	    CCerrors += 1

	counter[PID] = CC
	oldpacket = packet



if __name__ == '__main__':
  main()
